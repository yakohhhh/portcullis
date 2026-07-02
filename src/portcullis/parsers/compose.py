"""docker-compose file parsing.

Compose files are treated as untrusted input: they are read with a
``yaml.SafeLoader`` variant only, and any structural surprise degrades
gracefully instead of crashing the scan (a homelab repository contains many
hand-written files) - unparseable files are skipped with a warning unless the
user pointed at a single file. The parser intentionally supports the subset
of the compose specification that matters for a security audit: services,
images, published ports, networks, volumes, environment, labels,
capabilities, profiles, secrets and a few security-relevant flags.

It also resolves the constructs that change what a service actually is, so
exposure is not under-reported: ``include:`` (with cycle protection),
``extends:`` (same file and cross file, with cycle protection), and
project-level ``.env`` interpolation of ``$VAR`` / ``${VAR}`` /
``${VAR:-default}`` in image references and ports.

Override files are merged with simplified compose semantics: mappings are
deep-merged, lists are concatenated (duplicates removed, order preserved) and
scalars from the override win.
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import Any

import yaml

from portcullis.discovery import ComposeGroup
from portcullis.model import (
    ImageRef,
    Network,
    PortMapping,
    Service,
    Stack,
    VolumeMount,
)


class ComposeParseError(Exception):
    """A compose file could not be read or is not a mapping."""


class _ComposeSafeLoader(yaml.SafeLoader):
    """SafeLoader minus YAML 1.1 sexagesimal integers.

    PyYAML resolves unquoted ``22:22`` to the integer 1342 (base 60). The
    compose specification is YAML 1.2 and Docker's own parser keeps such
    values as strings, so the int resolver is re-registered without the
    sexagesimal form - otherwise port mappings like ``- 53:53`` would parse
    into bogus port numbers.
    """


_ComposeSafeLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:int"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_ComposeSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(
        r"""^(?:
            [-+]?0b[0-1_]+
            | [-+]?0o?[0-7_]+
            | [-+]?(?:0|[1-9][0-9_]*)
            | [-+]?0x[0-9a-fA-F_]+
        )$""",
        re.X,
    ),
    list("-+0123456789"),
)


def parse_compose_groups(groups: list[ComposeGroup], root: Path) -> Stack:
    """Parse every compose group into a single :class:`Stack`.

    Unparseable files are skipped with a warning on ``stack.warnings`` -
    except when the user pointed at a single group, where failing loudly is
    more useful. Services and networks are namespaced with the relative
    directory of their compose file when needed, so unrelated projects in
    the same tree can reuse names like ``backend`` without their
    definitions (e.g. ``internal: true``) leaking into each other.
    """
    stack = Stack(root=root)
    for group in groups:
        try:
            merged: dict[str, Any] = {}
            for file in group.files:
                merged = _merge(merged, _load_model(file, set()))
        except ComposeParseError as exc:
            if len(groups) == 1:
                raise
            stack.warnings.append(f"skipped: {exc}")
            continue
        stack.files.extend(group.files)

        base_dir = group.base.parent
        prefix = _relative_label(base_dir, root)
        env_vars = _read_env_file(base_dir / ".env")  # project-level interpolation

        services_cfg = merged.get("services")
        if not isinstance(services_cfg, dict):
            if services_cfg is not None:
                stack.warnings.append(f"{group.base}: 'services' is not a mapping - file skipped")
            services_cfg = {}
        networks_cfg = merged.get("networks")
        if not isinstance(networks_cfg, dict):
            if networks_cfg is not None:
                stack.warnings.append(f"{group.base}: 'networks' is not a mapping - ignored")
            networks_cfg = {}

        services_cfg = _resolve_all_extends(services_cfg, group.base, base_dir, stack.warnings)

        for section in ("secrets", "configs"):
            for secret_name in _section_keys(merged.get(section)):
                if section == "secrets":
                    stack.secret_names.add(secret_name)

        for net_name, net_cfg in networks_cfg.items():
            network = _parse_network(str(net_name), net_cfg if isinstance(net_cfg, dict) else {})
            stack.networks.setdefault(_scoped(prefix, network.name), network)

        for raw_name, cfg in services_cfg.items():
            service = _parse_service(str(raw_name), cfg or {}, group.base, base_dir, env_vars)
            service.networks = [_scoped(prefix, net) for net in service.networks]
            key = service.name
            if key in stack.services:
                key = _scoped(prefix, key) if prefix else f"{group.base.name}:{key}"
                service.name = key
            stack.services[key] = service
    return stack


def _section_keys(value: Any) -> list[str]:
    return [str(key) for key in value] if isinstance(value, dict) else []


# ---------------------------------------------------------------------------
# include: resolution (with cycle protection)


def _load_model(file: Path, seen: set[Path]) -> dict[str, Any]:
    """Load a compose file, resolving its top-level ``include:`` recursively.

    Included models are merged first; the including file's own definitions win
    on conflict. A cycle (a file that includes itself, directly or not) stops
    at the repeated file instead of recursing forever.
    """
    resolved = _resolve(file)
    if resolved in seen:
        return {}
    seen = seen | {resolved}
    data = _load_yaml(file)
    includes = data.get("include")
    if not includes:
        return data

    base_dir = file.parent
    model: dict[str, Any] = {}
    entries = includes if isinstance(includes, list) else [includes]
    for entry in entries:
        for inc_path in _include_paths(entry):
            # A broken include degrades the analysis, it never crashes it.
            with contextlib.suppress(ComposeParseError):
                model = _merge(model, _load_model(base_dir / inc_path, seen))
    local = {key: value for key, value in data.items() if key != "include"}
    return _merge(model, local)


def _include_paths(entry: Any) -> list[str]:
    if isinstance(entry, dict):
        path = entry.get("path")
        return [str(p) for p in path] if isinstance(path, list) else ([str(path)] if path else [])
    return [str(entry)] if entry else []


# ---------------------------------------------------------------------------
# extends: resolution (same file and cross file, with cycle protection)


def _resolve_all_extends(
    services_cfg: dict[str, Any], base_file: Path, base_dir: Path, warnings: list[str]
) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for name, cfg in services_cfg.items():
        resolved[name] = _resolve_service_extends(
            cfg if isinstance(cfg, dict) else {}, services_cfg, base_file, base_dir, set(), warnings
        )
    return resolved


def _resolve_service_extends(
    cfg: dict[str, Any],
    local_services: dict[str, Any],
    current_file: Path,
    base_dir: Path,
    seen: set[tuple[Path, str]],
    warnings: list[str],
) -> dict[str, Any]:
    extends = cfg.get("extends")
    if not extends:
        return cfg
    own = {key: value for key, value in cfg.items() if key != "extends"}
    target_name, target_file = _extends_target(extends, current_file, base_dir)
    if target_name is None:
        return own

    ref = (_resolve(target_file), target_name)
    if ref in seen:
        warnings.append(f"{current_file}: circular extends on '{target_name}'")
        return own
    seen = seen | {ref}

    if _resolve(target_file) == _resolve(current_file):
        base_services = local_services
        base_file = current_file
    else:
        try:
            base_services = _load_yaml(target_file).get("services") or {}
        except ComposeParseError:
            warnings.append(f"{current_file}: cannot extend from {target_file}")
            return own
        base_file = target_file

    base_cfg = base_services.get(target_name)
    if not isinstance(base_cfg, dict):
        warnings.append(f"{current_file}: extends target '{target_name}' not found")
        return own
    resolved_base = _resolve_service_extends(
        base_cfg, base_services, base_file, base_file.parent, seen, warnings
    )
    return _merge(resolved_base, own)


def _extends_target(extends: Any, current_file: Path, base_dir: Path) -> tuple[str | None, Path]:
    if isinstance(extends, str):
        return extends, current_file
    if isinstance(extends, dict):
        service = extends.get("service")
        file_ref = extends.get("file")
        target_file = (base_dir / str(file_ref)) if file_ref else current_file
        return (str(service) if service else None), target_file
    return None, current_file


def _scoped(prefix: str, name: str) -> str:
    return f"{prefix}/{name}" if prefix else name


def _load_yaml(file: Path) -> dict[str, Any]:
    try:
        data = yaml.load(file.read_text(encoding="utf-8"), Loader=_ComposeSafeLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ComposeParseError(f"Cannot read {file}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ComposeParseError(f"{file} is not a compose file (top level is not a mapping)")
    return data


def _merge(base: Any, override: Any) -> Any:
    """Simplified compose override merge (documented in the module docstring)."""
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = _merge(base.get(key), value) if key in base else value
        return merged
    if isinstance(base, list) and isinstance(override, list):
        merged_list = list(base)
        for item in override:
            if item not in merged_list:
                merged_list.append(item)
        return merged_list
    return override if override is not None else base


def _relative_label(directory: Path, root: Path) -> str:
    try:
        rel = directory.resolve().relative_to(root.resolve())
    except ValueError:
        return ""
    return str(rel).replace("\\", "/") if str(rel) != "." else ""


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:  # pragma: no cover - resolve rarely raises for plain paths
        return path


# ---------------------------------------------------------------------------
# Service parsing


def _parse_service(
    name: str, cfg: dict[str, Any], file: Path, base_dir: Path,
    env_vars: dict[str, str] | None = None,
) -> Service:
    if not isinstance(cfg, dict):
        cfg = {}
    env_vars = env_vars or {}
    image_raw = cfg.get("image")
    image = _interpolate(str(image_raw), env_vars) if image_raw else None
    return Service(
        name=name,
        image=ImageRef.parse(image) if image else None,
        build="build" in cfg,
        command=_parse_command(cfg.get("command")),
        ports=_parse_ports(cfg.get("ports"), env_vars),
        networks=_parse_service_networks(cfg.get("networks")),
        network_mode=_as_str(cfg.get("network_mode")),
        volumes=_parse_volumes(cfg.get("volumes")),
        environment=_parse_environment(cfg, base_dir, env_vars),
        env_files=_env_file_paths(cfg.get("env_file"), base_dir),
        labels=_parse_string_mapping(cfg.get("labels")),
        privileged=bool(cfg.get("privileged", False)),
        cap_add=_parse_string_list(cfg.get("cap_add")),
        cap_drop=_parse_string_list(cfg.get("cap_drop")),
        user=_as_str(cfg.get("user")),
        pid=_as_str(cfg.get("pid")),
        restart=_as_str(cfg.get("restart")),
        read_only=bool(cfg.get("read_only", False)),
        security_opt=_parse_string_list(cfg.get("security_opt")),
        depends_on=_parse_depends_on(cfg.get("depends_on")),
        profiles=_parse_string_list(cfg.get("profiles")),
        secrets=_parse_service_secrets(cfg.get("secrets")),
        source_file=file,
    )


def _parse_service_secrets(value: Any) -> list[str]:
    """Service ``secrets:`` entries (short string form or long ``{source: ...}``)."""
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for entry in value:
        if isinstance(entry, dict):
            source = entry.get("source")
            if source:
                names.append(str(source))
        elif entry is not None:
            names.append(str(entry))
    return names


def _as_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _parse_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _parse_string_mapping(value: Any) -> dict[str, str]:
    """Parse a compose mapping-or-list section (labels and similar)."""
    result: dict[str, str] = {}
    if isinstance(value, dict):
        for key, val in value.items():
            result[str(key)] = "" if val is None else str(val)
    elif isinstance(value, list):
        for item in value:
            if item is None:
                continue
            key, sep, val = str(item).partition("=")
            result[key.strip()] = val.strip() if sep else ""
    return result


def _parse_depends_on(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(key) for key in value]
    return _parse_string_list(value)


def _parse_command(value: Any) -> list[str]:
    """Parse a service ``command:`` (list form, or a shell string split naively).

    Reverse-proxy configuration is often passed here (Traefik provider flags,
    entrypoint addresses), so it is worth capturing. A string command is split
    on whitespace: good enough to recover ``--flag=value`` tokens without
    pulling in a full shell tokenizer.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return str(value).split()


def _parse_service_networks(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(key) for key in value]
    return _parse_string_list(value)


def _parse_network(name: str, cfg: dict[str, Any]) -> Network:
    if not isinstance(cfg, dict):
        cfg = {}
    return Network(
        name=name,
        internal=bool(cfg.get("internal", False)),
        external=bool(cfg.get("external", False)),
        driver=_as_str(cfg.get("driver")),
    )


# ---------------------------------------------------------------------------
# Ports

_PORT_RANGE = re.compile(r"^(\d+)(?:-(\d+))?$")


def _parse_ports(value: Any, env_vars: dict[str, str] | None = None) -> list[PortMapping]:
    mappings: list[PortMapping] = []
    if not isinstance(value, list):
        return mappings
    for entry in value:
        mappings.extend(_parse_port_entry(entry, env_vars or {}))
    return mappings


def _parse_port_entry(entry: Any, env_vars: dict[str, str]) -> list[PortMapping]:
    if entry is None:
        return []
    if isinstance(entry, dict):  # long syntax
        target = _as_int(_interpolate(str(entry.get("target")), env_vars))
        if target is None:
            return []
        return [
            PortMapping(
                container_port=target,
                host_port=_as_int(_interpolate(str(entry.get("published", "")), env_vars)),
                host_ip=str(entry.get("host_ip", "")),
                protocol=str(entry.get("protocol", "tcp")),
                raw=str(entry),
            )
        ]
    return _parse_port_string(_interpolate(str(entry), env_vars))


def _parse_port_string(raw: str) -> list[PortMapping]:
    """Parse short syntax: ``[HOST_IP:][HOST[-RANGE]:]CONTAINER[-RANGE][/proto]``.

    An empty host-port segment (``127.0.0.1::8080``) is valid Docker syntax:
    publish on an ephemeral host port bound to that address.
    """
    text = raw.strip()
    protocol = "tcp"
    if "/" in text:
        text, _, protocol = text.rpartition("/")

    host_ip = ""
    # Bracketed IPv6 host address, e.g. "[::1]:8080:80".
    if text.startswith("["):
        bracket_end = text.find("]")
        if bracket_end != -1:
            host_ip = text[1:bracket_end]
            text = text[bracket_end + 1 :].lstrip(":")

    parts = text.split(":")
    if not host_ip and len(parts) > 2:
        # Unbracketed leading IP (IPv4 like 127.0.0.1, or IPv6 tail-anchored):
        # the last two segments are always ports, the rest is the address.
        host_ip = ":".join(parts[:-2])
        parts = parts[-2:]

    try:
        if len(parts) == 1:
            container_ports = _expand_range(parts[0])
            return [
                PortMapping(container_port=port, host_port=None, host_ip=host_ip,
                            protocol=protocol, raw=raw)
                for port in container_ports
            ]
        host_ports: list[int | None]
        host_ports = [None] if parts[0] == "" else list(_expand_range(parts[0]))
        container_ports = _expand_range(parts[1])
    except ValueError:
        return []  # unparseable entry (e.g. unresolved ${VAR}); skip rather than crash

    if len(host_ports) != len(container_ports):
        # "8000-8010:80" style: Docker picks within the host range; keep one entry.
        host_ports = host_ports[:1] * len(container_ports)
    return [
        PortMapping(container_port=container, host_port=host, host_ip=host_ip,
                    protocol=protocol, raw=raw)
        for host, container in zip(host_ports, container_ports, strict=True)
    ]


def _expand_range(text: str) -> list[int]:
    match = _PORT_RANGE.match(text.strip())
    if not match:
        raise ValueError(f"not a port or range: {text!r}")
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else start
    if end < start or end - start > 128:  # keep pathological ranges bounded
        end = start
    return list(range(start, end + 1))


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Volumes


def _parse_volumes(value: Any) -> list[VolumeMount]:
    mounts: list[VolumeMount] = []
    if not isinstance(value, list):
        return mounts
    for entry in value:
        if entry is None:
            continue
        if isinstance(entry, dict):  # long syntax
            mounts.append(
                VolumeMount(
                    source=str(entry.get("source", "")),
                    target=str(entry.get("target", "")),
                    read_only=bool(entry.get("read_only", False)),
                    kind=str(entry.get("type", "volume")),
                    raw=str(entry),
                )
            )
            continue
        mounts.append(_parse_volume_string(str(entry)))
    return mounts


def _parse_volume_string(raw: str) -> VolumeMount:
    parts = raw.strip().split(":")
    read_only = False
    if len(parts) >= 3 or (len(parts) == 2 and parts[1] in ("ro", "rw")):
        # Possible trailing mode segment ("ro", "rw", "ro,z", ...).
        mode = parts[-1]
        if all(flag in ("ro", "rw", "z", "Z", "cached", "delegated") for flag in mode.split(",")):
            read_only = "ro" in mode.split(",")
            parts = parts[:-1]
    if len(parts) == 1:
        source, target = "", parts[0]
    else:
        source, target = parts[0], ":".join(parts[1:])
    kind = "bind" if source.startswith((".", "/", "~")) else "volume"
    return VolumeMount(source=source, target=target, read_only=read_only, kind=kind, raw=raw)


# ---------------------------------------------------------------------------
# Environment

_INTERPOLATION = re.compile(
    r"\$\$"
    r"|\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<sep>:?-)(?P<default>[^}]*))?\}"
    r"|\$(?P<simple>[A-Za-z_][A-Za-z0-9_]*)"
)


def _parse_environment(
    cfg: dict[str, Any], base_dir: Path, env_vars: dict[str, str] | None = None
) -> dict[str, str]:
    env_vars = env_vars or {}
    env: dict[str, str] = {}
    for path in _env_file_paths(cfg.get("env_file"), base_dir):
        env.update(_read_env_file(path))
    env.update(_parse_environment_section(cfg.get("environment")))
    return {key: _interpolate(value, env_vars) for key, value in env.items()}


def _env_file_paths(value: Any, base_dir: Path) -> list[Path]:
    """Resolve ``env_file:`` entries (string, list, or list of ``{path: ...}``)."""
    entries = value if isinstance(value, list) else ([value] if value is not None else [])
    paths: list[Path] = []
    for entry in entries:
        raw = entry.get("path") if isinstance(entry, dict) else entry
        if raw:
            paths.append(base_dir / str(raw))
    return paths


def _parse_environment_section(value: Any) -> dict[str, str]:
    """Like :func:`_parse_string_mapping`, but pass-through entries are dropped.

    A null mapping value (``FOO:``) or a list item without ``=`` (``- FOO``)
    means "resolve from the host environment at deploy time": the value is
    unknown to a static audit and must not be mistaken for an explicit empty
    string (which the weak-secret rule rightly flags).
    """
    result: dict[str, str] = {}
    if isinstance(value, dict):
        for key, val in value.items():
            if val is not None:
                result[str(key)] = str(val)
    elif isinstance(value, list):
        for item in value:
            if item is None:
                continue
            key, sep, val = str(item).partition("=")
            if sep:
                result[key.strip()] = val.strip()
    return result


def _read_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return env  # referenced env file missing: not fatal for a static audit
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip("'\"")
    return env


def _interpolate(value: str, env_vars: dict[str, str]) -> str:
    """Resolve ``$VAR`` / ``${VAR}`` / ``${VAR:-default}`` interpolations.

    A variable is substituted from ``env_vars`` (the project ``.env``) when
    present; otherwise ``${VAR:-default}`` falls back to its default, and a
    bare ``$VAR`` / ``${VAR}`` with no known value is kept verbatim so rules
    treat it as externally provided (and do not raise false positives).
    ``$$`` is an escaped literal dollar.
    """

    def _sub(match: re.Match[str]) -> str:
        if match.group(0) == "$$":
            return "$"
        name = match.group("braced") or match.group("simple")
        if name is not None and name in env_vars:
            return env_vars[name]
        if match.group("simple") is not None:
            return match.group(0)  # unknown $VAR: keep literal
        if match.group("default") is not None:
            return match.group("default")  # ${VAR:-default}: use the default
        return match.group(0)  # unknown ${VAR}: keep literal

    return _INTERPOLATION.sub(_sub, value)
