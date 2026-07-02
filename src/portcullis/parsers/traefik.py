"""Traefik configuration parsing (milestone 2).

Portcullis already understands Traefik routing declared as compose labels
(``traefik.enable``, ``traefik.http.routers.*``) - that logic lives in
:mod:`portcullis.exposure`. This module adds the other two ways a homelab
configures Traefik:

* the **static** configuration (``traefik.yml`` / ``.toml`` or the service's
  ``command:`` flags): entrypoints and their bind addresses, the docker
  provider and its ``exposedByDefault``, and the file-provider paths;
* the **dynamic** file provider: routers (rule, entrypoints, target service)
  and services (load-balancer server URLs), which name the compose services
  that Traefik routes to the outside.

The output is a :class:`~portcullis.model.RoutingTable` that the exposure
engine folds into its classification. Everything here is defensive: Traefik
configuration is untrusted, hand-written input, and a malformed file must
degrade the analysis, never crash the scan.

Entrypoint awareness: a router reachable only through a loopback-bound
entrypoint (``--entrypoints.internal.address=127.0.0.1:8081``) routes its
target to the host, not to the Internet, so it is reported as HOST rather
than INTERNET.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from portcullis.model import RoutingTable, Service, Stack

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.10 only
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

#: Image repository last component identifying the reverse proxy service.
TRAEFIK_IMAGE_NAME = "traefik"
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_DYNAMIC_SUFFIXES = (".yml", ".yaml", ".toml")


# ---------------------------------------------------------------------------
# Parsed configuration


@dataclass
class _Entrypoint:
    name: str
    address: str

    @property
    def loopback_only(self) -> bool:
        return _address_host(self.address) in _LOOPBACK_HOSTS


@dataclass
class _Router:
    name: str
    service: str | None
    entrypoints: list[str] = field(default_factory=list)


@dataclass
class _TraefikConfig:
    """Everything relevant accumulated from static + dynamic configuration."""

    entrypoints: dict[str, _Entrypoint] = field(default_factory=dict)
    routers: list[_Router] = field(default_factory=list)
    #: load-balancer service name -> upstream hosts extracted from its servers
    services: dict[str, list[str]] = field(default_factory=dict)
    docker_provider: bool = False
    exposed_by_default: bool | None = None
    file_directories: list[str] = field(default_factory=list)
    file_filenames: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API


def analyze(stack: Stack, config_files: list[Path]) -> RoutingTable:
    """Build a routing table from Traefik configuration for ``stack``.

    ``config_files`` are the static files discovered on disk (see
    :func:`portcullis.discovery.find_traefik_configs`). Dynamic file-provider
    configuration is located from the Traefik service's bind mounts.
    """
    routing = RoutingTable()
    proxies = _find_traefik_services(stack)
    config = _TraefikConfig()

    for path in config_files:
        data = _load_document(path)
        if data is not None:
            _apply_config(config, data)
            routing.files.append(path)

    for service in proxies.values():
        _apply_command_args(config, service.command)

    for path in _resolve_file_provider_paths(config, proxies):
        data = _load_document(path)
        if data is not None:
            _apply_config(config, data)
            routing.files.append(path)

    _resolve_routing(config, proxies, stack, routing)
    routing.proxy_services |= set(proxies)
    return routing


# ---------------------------------------------------------------------------
# Document loading


def _load_document(path: Path) -> dict[str, Any] | None:
    """Load a YAML or TOML document, returning its lower-cased-key mapping."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        if path.suffix.lower() == ".toml":
            if tomllib is None:  # pragma: no cover - only without tomli on 3.10
                return None
            data = tomllib.loads(text)
        else:
            data = yaml.safe_load(text)
    except (yaml.YAMLError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return _lower_keys(data)


def _lower_keys(value: Any) -> Any:
    """Recursively lower-case mapping keys (Traefik keys are case-insensitive)."""
    if isinstance(value, dict):
        return {str(key).lower(): _lower_keys(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_lower_keys(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Static / dynamic config application


def _apply_config(config: _TraefikConfig, data: dict[str, Any]) -> None:
    _apply_entrypoints(config, data.get("entrypoints"))
    _apply_providers(config, data.get("providers"))
    for protocol in ("http", "tcp", "udp"):
        section = data.get(protocol)
        if isinstance(section, dict):
            _apply_routers(config, section.get("routers"))
            _apply_services(config, section.get("services"))


def _apply_entrypoints(config: _TraefikConfig, section: Any) -> None:
    if not isinstance(section, dict):
        return
    for name, body in section.items():
        address = ""
        if isinstance(body, dict):
            address = str(body.get("address", ""))
        config.entrypoints[str(name)] = _Entrypoint(name=str(name), address=address)


def _apply_providers(config: _TraefikConfig, section: Any) -> None:
    if not isinstance(section, dict):
        return
    docker = section.get("docker")
    if docker is not None:
        config.docker_provider = True
        if isinstance(docker, dict) and "exposedbydefault" in docker:
            config.exposed_by_default = _as_bool(docker.get("exposedbydefault"))
    file_provider = section.get("file")
    if isinstance(file_provider, dict):
        directory = file_provider.get("directory")
        if directory:
            config.file_directories.append(str(directory))
        filename = file_provider.get("filename")
        if filename:
            config.file_filenames.append(str(filename))


def _apply_routers(config: _TraefikConfig, section: Any) -> None:
    if not isinstance(section, dict):
        return
    for name, body in section.items():
        if not isinstance(body, dict):
            continue
        service = body.get("service")
        entrypoints = body.get("entrypoints")
        config.routers.append(
            _Router(
                name=str(name),
                service=_strip_provider(service) if service else None,
                entrypoints=_as_str_list(entrypoints),
            )
        )


def _apply_services(config: _TraefikConfig, section: Any) -> None:
    if not isinstance(section, dict):
        return
    for name, body in section.items():
        if not isinstance(body, dict):
            continue
        load_balancer = body.get("loadbalancer")
        if not isinstance(load_balancer, dict):
            continue
        hosts: list[str] = []
        for server in load_balancer.get("servers", []) or []:
            if isinstance(server, dict):
                target = server.get("url") or server.get("address")
                host = _host_from_target(str(target)) if target else None
                if host:
                    hosts.append(host)
        if hosts:
            config.services.setdefault(str(name), []).extend(hosts)


# ---------------------------------------------------------------------------
# Command-line argument application (traefik service `command:`)


def _apply_command_args(config: _TraefikConfig, args: list[str]) -> None:
    """Read the provider/entrypoint flags Traefik accepts on the command line."""
    for key, value in _iter_cli_flags(args):
        parts = key.split(".")
        if parts[0] == "entrypoints" and len(parts) >= 3 and parts[2] == "address":
            name = parts[1]
            config.entrypoints[name] = _Entrypoint(name=name, address=value)
        elif parts[:2] == ["providers", "docker"]:
            config.docker_provider = True
            if len(parts) >= 3 and parts[2] == "exposedbydefault":
                config.exposed_by_default = _as_bool(value)
        elif parts[:3] == ["providers", "file", "directory"]:
            if value:
                config.file_directories.append(value)
        elif parts[:3] == ["providers", "file", "filename"]:
            if value:
                config.file_filenames.append(value)


def _iter_cli_flags(args: list[str]):
    """Yield ``(lowercased-key, value)`` for ``--key=value`` / ``--key value``."""
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("--"):
            body = token[2:]
            if "=" in body:
                key, value = body.split("=", 1)
            else:
                key = body
                # A following non-flag token is the value; otherwise it is a
                # boolean flag whose presence means "true".
                if index + 1 < len(args) and not args[index + 1].startswith("--"):
                    value = args[index + 1]
                    index += 1
                else:
                    value = "true"
            yield key.lower(), value
        index += 1


# ---------------------------------------------------------------------------
# File-provider path resolution (container paths -> host paths via mounts)


def _resolve_file_provider_paths(
    config: _TraefikConfig, proxies: dict[str, Service]
) -> list[Path]:
    """Translate file-provider container paths to host files through bind mounts."""
    mounts = _bind_mounts(proxies)
    results: list[Path] = []

    for container_dir in config.file_directories:
        host_dir = _to_host_path(container_dir, mounts)
        if host_dir is not None and host_dir.is_dir():
            for child in sorted(host_dir.iterdir()):
                if child.is_file() and child.suffix.lower() in _DYNAMIC_SUFFIXES:
                    results.append(child)
    for container_file in config.file_filenames:
        host_file = _to_host_path(container_file, mounts)
        if host_file is not None and host_file.is_file():
            results.append(host_file)
    return results


def _bind_mounts(proxies: dict[str, Service]) -> list[tuple[str, Path]]:
    """List ``(container_target, host_source_dir)`` bind mounts of the proxies."""
    mounts: list[tuple[str, Path]] = []
    for service in proxies.values():
        base = service.source_file.parent if service.source_file else None
        for mount in service.volumes:
            if mount.kind != "bind" or not mount.source or not mount.target:
                continue
            source = Path(mount.source).expanduser()
            if not source.is_absolute() and base is not None:
                source = (base / source).resolve()
            mounts.append((mount.target.rstrip("/"), source))
    # Longest container path first so the most specific mount wins.
    mounts.sort(key=lambda item: len(item[0]), reverse=True)
    return mounts


def _to_host_path(container_path: str, mounts: list[tuple[str, Path]]) -> Path | None:
    target = container_path.rstrip("/")
    for mount_target, host_source in mounts:
        if target == mount_target:
            return host_source
        if target.startswith(mount_target + "/"):
            remainder = target[len(mount_target) + 1 :]
            return host_source / remainder
    return None


# ---------------------------------------------------------------------------
# Resolution to a routing table


def _resolve_routing(
    config: _TraefikConfig,
    proxies: dict[str, Service],
    stack: Stack,
    routing: RoutingTable,
) -> None:
    has_public_entrypoint = _has_public_entrypoint(config)

    for router in config.routers:
        public = _router_is_public(router, config, has_public_entrypoint)
        for host in _router_upstream_hosts(router, config):
            match = _match_service(host, stack)
            if match is None:
                continue
            (routing.internet_routed if public else routing.host_routed).add(match)

    _apply_exposed_by_default(config, proxies, stack, routing)


def _router_upstream_hosts(router: _Router, config: _TraefikConfig) -> list[str]:
    if router.service and router.service in config.services:
        return config.services[router.service]
    # No load-balancer definition: the router's service name is often the
    # compose service itself (docker provider style).
    return [router.service] if router.service else []


def _router_is_public(
    router: _Router, config: _TraefikConfig, has_public_entrypoint: bool
) -> bool:
    if not router.entrypoints:
        # Bound to every entrypoint: public as soon as one public entrypoint
        # exists, or when we could not read any entrypoint at all.
        return has_public_entrypoint or not config.entrypoints
    resolved = [config.entrypoints.get(name) for name in router.entrypoints]
    known = [entry for entry in resolved if entry is not None]
    if not known:
        return True  # unknown entrypoints: assume public (conservative)
    return any(not entry.loopback_only for entry in known)


def _has_public_entrypoint(config: _TraefikConfig) -> bool:
    return any(not entry.loopback_only for entry in config.entrypoints.values())


def _apply_exposed_by_default(
    config: _TraefikConfig,
    proxies: dict[str, Service],
    stack: Stack,
    routing: RoutingTable,
) -> None:
    """Expose every container sharing a network with Traefik, if configured.

    Traefik's docker provider defaults ``exposedByDefault`` to ``true``: every
    container on a Traefik network is routed unless it sets
    ``traefik.enable=false``. Portcullis mirrors this only when it can confirm
    the docker provider is enabled and the flag was not turned off.
    """
    if not config.docker_provider or config.exposed_by_default is False:
        return
    proxy_networks: set[str] = set()
    for service in proxies.values():
        proxy_networks.update(service.networks)
    if not proxy_networks:
        return
    for name, service in stack.services.items():
        if name in proxies:
            continue
        if service.labels.get("traefik.enable", "").strip().lower() == "false":
            continue
        if proxy_networks.intersection(service.networks):
            routing.internet_routed.add(name)


# ---------------------------------------------------------------------------
# Small helpers


def _find_traefik_services(stack: Stack) -> dict[str, Service]:
    return {
        name: service
        for name, service in stack.services.items()
        if service.image is not None and service.image.name.lower() == TRAEFIK_IMAGE_NAME
    }


def _match_service(host: str, stack: Stack) -> str | None:
    """Map an upstream host to a compose service key (exact or last segment)."""
    host = host.strip().lower()
    if not host:
        return None
    for key, service in stack.services.items():
        if host in (key.lower(), key.rsplit("/", 1)[-1].lower(), service.name.lower()):
            return key
    return None


def _strip_provider(reference: Any) -> str:
    """``myservice@docker`` / ``myservice@file`` -> ``myservice`` (lower-cased)."""
    return str(reference).split("@", 1)[0].strip().lower()


def _host_from_target(target: str) -> str | None:
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname
    # TCP servers use a bare "host:port" address.
    return _address_host(target) or None


def _address_host(address: str) -> str:
    address = address.strip()
    if not address:
        return ""
    if address.startswith("["):  # [::1]:8080
        end = address.find("]")
        return address[1:end] if end != -1 else address
    if ":" in address:
        return address.rsplit(":", 1)[0]
    return address


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]
