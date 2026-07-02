"""Configuration file discovery.

Given a path (a file or a directory tree, typically a homelab Git
repository), find the docker-compose files to analyse and group each base
file with its override files, mirroring what ``docker compose`` would load
from the same directory.
"""

from __future__ import annotations

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
