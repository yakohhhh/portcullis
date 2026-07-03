"""Configuration file discovery.

Given a path (a file or a directory tree, typically a homelab Git
repository), find the docker-compose files to analyse and group each base
file with its override files, mirroring what ``docker compose`` would load
from the same directory.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path

COMPOSE_BASENAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)

OVERRIDE_BASENAMES = (
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
)

#: Static Traefik configuration files, matched by name anywhere in the tree.
#: Dynamic (file-provider) configuration has arbitrary names and is located
#: instead through the Traefik service's bind mounts (see the traefik parser).
TRAEFIK_STATIC_BASENAMES = (
    "traefik.yml",
    "traefik.yaml",
    "traefik.toml",
)

#: Caddyfile names, matched anywhere in the tree.
CADDYFILE_BASENAMES = (
    "Caddyfile",
    "caddyfile",
)

#: nginx configuration files have arbitrary names; we collect ``.conf`` files
#: living in directories that conventionally hold reverse-proxy config (raw
#: nginx and Nginx Proxy Manager's generated ``proxy_host`` files), plus the
#: two canonical basenames. Files that turn out not to route to a known
#: compose service contribute nothing (see the nginx parser).
NGINX_CONFIG_BASENAMES = (
    "nginx.conf",
    "default.conf",
)
NGINX_CONFIG_DIRS = {
    "nginx",
    "conf.d",
    "sites-enabled",
    "sites-available",
    "proxy_host",
    "vhost.d",
    "servers",
}

#: Nginx Proxy Manager's SQLite database (its default filename).
NPM_DATABASE_BASENAMES = (
    "database.sqlite",
)

#: Directories that never contain user infrastructure files.
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".idea",
    ".vscode",
}


@dataclass
class ComposeGroup:
    """A base compose file together with the override files applied to it."""

    base: Path
    overrides: list[Path] = field(default_factory=list)

    @property
    def files(self) -> list[Path]:
        return [self.base, *self.overrides]


class DiscoveryError(Exception):
    """No usable configuration file was found under the given path."""


def find_compose_groups(path: Path) -> list[ComposeGroup]:
    """Return every compose file group found under ``path``.

    ``path`` may be a compose file (its sibling override is picked up
    automatically) or a directory that is walked recursively.
    """
    path = path.resolve()
    if path.is_file():
        return [_group_for(path)]

    groups: list[ComposeGroup] = []
    for directory in _walk_dirs(path):
        base = _first_existing(directory, COMPOSE_BASENAMES)
        if base is not None:
            groups.append(_group_for(base))
    if not groups:
        raise DiscoveryError(
            f"No docker-compose file found under {path}. "
            "Expected one of: " + ", ".join(COMPOSE_BASENAMES)
        )
    return groups


def find_traefik_configs(path: Path) -> list[Path]:
    """Return every static Traefik configuration file under ``path``.

    Matches only by well-known basename; dynamic file-provider configuration
    is resolved later from the Traefik service's volume mounts.
    """
    return _find_by_basename(path, TRAEFIK_STATIC_BASENAMES)


def find_caddy_configs(path: Path) -> list[Path]:
    """Return every Caddyfile under ``path``, matched by name."""
    return _find_by_basename(path, CADDYFILE_BASENAMES)


def find_nginx_configs(path: Path) -> list[Path]:
    """Return candidate nginx / NPM ``.conf`` files under ``path``.

    Collects the canonical basenames plus every ``.conf`` in a conventional
    nginx directory. Precision comes from the parser, which ignores any file
    that does not route to a known compose service.
    """
    path = path.resolve()
    if path.is_file():
        if path.name in NGINX_CONFIG_BASENAMES or (
            path.suffix == ".conf" and path.parent.name in NGINX_CONFIG_DIRS
        ):
            return [path]
        return []

    found: list[Path] = []
    for directory in _walk_dirs(path):
        for name in NGINX_CONFIG_BASENAMES:
            candidate = directory / name
            if candidate.is_file():
                found.append(candidate)
        if directory.name in NGINX_CONFIG_DIRS:
            with contextlib.suppress(OSError):
                found.extend(
                    child for child in sorted(directory.iterdir())
                    if child.is_file() and child.suffix == ".conf"
                    and child.name not in NGINX_CONFIG_BASENAMES
                )
    return found


def find_npm_databases(path: Path) -> list[Path]:
    """Return Nginx Proxy Manager SQLite databases under ``path``."""
    return _find_by_basename(path, NPM_DATABASE_BASENAMES)


def _find_by_basename(path: Path, names: tuple[str, ...]) -> list[Path]:
    path = path.resolve()
    if path.is_file():
        return [path] if path.name in names else []

    found: list[Path] = []
    for directory in _walk_dirs(path):
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                found.append(candidate)
    return found


def _group_for(base: Path) -> ComposeGroup:
    group = ComposeGroup(base=base)
    override = _first_existing(base.parent, OVERRIDE_BASENAMES)
    if override is not None and override != base:
        group.overrides.append(override)
    return group


def _first_existing(directory: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _walk_dirs(root: Path):
    """Yield ``root`` and every subdirectory, skipping noise directories.

    Unreadable directories are skipped instead of aborting the walk:
    homelab trees routinely contain bind-mount data directories owned by
    container users (e.g. a mode-700 postgres data dir).
    """
    yield root
    try:
        children = sorted(root.iterdir())
    except OSError:
        return
    for child in children:
        try:
            recurse = (child.is_dir() and child.name not in IGNORED_DIRS
                       and not child.is_symlink())
        except OSError:
            continue
        if recurse:
            yield from _walk_dirs(child)
