"""docker-compose file parsing.

Compose files are treated as untrusted input: they are read with a
``yaml.SafeLoader`` variant only, and any structural surprise degrades
gracefully instead of crashing the scan (a homelab repository contains many
hand-written files) - unparseable files are skipped with a warning unless the
user pointed at a single file. The parser intentionally supports the subset
of the compose specification that matters for a security audit: services,
images, published ports, networks, volumes, environment, labels,
capabilities and a few security-relevant flags.

Override files are merged with simplified compose semantics: mappings are
deep-merged, lists are concatenated (duplicates removed, order preserved) and
scalars from the override win.
"""

from __future__ import annotations

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
                merged = _merge(merged, _load_yaml(file))
        except ComposeParseError as exc:
            if len(groups) == 1:
                raise
            stack.warnings.append(f"skipped: {exc}")
            continue
        stack.files.extend(group.files)

        base_dir = group.base.parent
        prefix = _relative_label(base_dir, root)

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

        for net_name, net_cfg in networks_cfg.items():
            network = _parse_network(str(net_name), net_cfg if isinstance(net_cfg, dict) else {})
            stack.networks.setdefault(_scoped(prefix, network.name), network)

        for raw_name, cfg in services_cfg.items():
            service = _parse_service(str(raw_name), cfg or {}, group.base, base_dir)
            service.networks = [_scoped(prefix, net) for net in service.networks]
            key = service.name
            if key in stack.services:
                key = _scoped(prefix, key) if prefix else f"{group.base.name}:{key}"
                service.name = key
            stack.services[key] = service
    return stack


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


# ---------------------------------------------------------------------------
# Service parsing


def _parse_service(name: str, cfg: dict[str, Any], file: Path, base_dir: Path) -> Service:
    if not isinstance(cfg, dict):
        cfg = {}
    image_raw = cfg.get("image")
    return Service(
        name=name,
        image=ImageRef.parse(str(image_raw)) if image_raw else None,
        build="build" in cfg,
        ports=_parse_ports(cfg.get("ports")),
        networks=_parse_service_networks(cfg.get("networks")),
        network_mode=_as_str(cfg.get("network_mode")),
        volumes=_parse_volumes(cfg.get("volumes")),
        environment=_parse_environment(cfg, base_dir),
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
        source_file=file,
    )


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


def _parse_ports(value: Any) -> list[PortMapping]:
    mappings: list[PortMapping] = []
    if not isinstance(value, list):
        return mappings
    for entry in value:
        mappings.extend(_parse_port_entry(entry))
    return mappings


def _parse_port_entry(entry: Any) -> list[PortMapping]:
    if entry is None:
        return []
    if isinstance(entry, dict):  # long syntax
        target = _as_int(entry.get("target"))
        if target is None:
            return []
        return [
            PortMapping(
                container_port=target,
                host_port=_as_int(entry.get("published")),
                host_ip=str(entry.get("host_ip", "")),
                protocol=str(entry.get("protocol", "tcp")),
                raw=str(entry),
            )
        ]
    return _parse_port_string(str(entry))


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
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<sep>:?-)(?P<default>[^}]*))?\}"
)


def _parse_environment(cfg: dict[str, Any], base_dir: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for env_file in _parse_string_list(cfg.get("env_file")):
        env.update(_read_env_file(base_dir / env_file))
    env.update(_parse_environment_section(cfg.get("environment")))
    return {key: _resolve_defaults(value) for key, value in env.items()}


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


def _resolve_defaults(value: str) -> str:
    """Resolve ``${VAR:-default}`` interpolations to their default value.

    Variables without a default are kept verbatim (``${VAR}``) so that rules
    can recognise them as externally provided and avoid false positives.
    """

    def _sub(match: re.Match[str]) -> str:
        if match.group("default") is not None:
            return match.group("default")
        return match.group(0)

    return _INTERPOLATION.sub(_sub, value)
