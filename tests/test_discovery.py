"""Tests for compose file discovery (:mod:`portcullis.discovery`).

Covers walking a directory tree, grouping base files with their overrides,
skipping noise directories (``.git``, ``node_modules``, ...) and the
:class:`DiscoveryError` raised when nothing usable is found.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portcullis.discovery import ComposeGroup, DiscoveryError, find_compose_groups
from portcullis.parsers.compose import parse_compose_groups

MINIMAL_COMPOSE = "services:\n  app:\n    image: nginx\n"


def write(path: Path, content: str = MINIMAL_COMPOSE) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def relative_bases(groups: list[ComposeGroup], root: Path) -> list[str]:
    return sorted(group.base.relative_to(root.resolve()).as_posix() for group in groups)


class TestFindComposeGroups:
    def test_direct_file_path(self, tmp_path: Path) -> None:
        file = write(tmp_path / "docker-compose.yml")
        groups = find_compose_groups(file)
        assert len(groups) == 1
        group = groups[0]
        assert isinstance(group, ComposeGroup)
        assert group.base.name == "docker-compose.yml"
        assert group.overrides == []
        assert group.files == [group.base]

    def test_recursive_walk_finds_nested_files(self, tmp_path: Path) -> None:
        write(tmp_path / "compose.yaml")
        write(tmp_path / "media" / "jellyfin" / "docker-compose.yml")
        groups = find_compose_groups(tmp_path)
        assert relative_bases(groups, tmp_path) == [
            "compose.yaml",
            "media/jellyfin/docker-compose.yml",
        ]

    def test_one_group_per_directory(self, tmp_path: Path) -> None:
        write(tmp_path / "compose.yaml")
        write(tmp_path / "docker-compose.yml")
        groups = find_compose_groups(tmp_path)
        assert len(groups) == 1
        assert groups[0].base.name == "compose.yaml"  # first known basename wins

    def test_override_grouped_with_base(self, tmp_path: Path) -> None:
        write(tmp_path / "compose.yaml")
        write(tmp_path / "compose.override.yaml")
        groups = find_compose_groups(tmp_path)
        assert len(groups) == 1
        assert [file.name for file in groups[0].files] == [
            "compose.yaml",
            "compose.override.yaml",
        ]

    def test_override_found_from_direct_base_path(self, tmp_path: Path) -> None:
        base = write(tmp_path / "docker-compose.yml")
        write(tmp_path / "docker-compose.override.yml")
        groups = find_compose_groups(base)
        assert [file.name for file in groups[0].files] == [
            "docker-compose.yml",
            "docker-compose.override.yml",
        ]


class TestIgnoredDirectories:
    @pytest.mark.parametrize("noise", [".git", "node_modules", ".venv", "__pycache__"])
    def test_compose_files_in_noise_dirs_are_skipped(self, tmp_path: Path, noise: str) -> None:
        write(tmp_path / noise / "compose.yaml")
        write(tmp_path / "app" / "compose.yaml")
        groups = find_compose_groups(tmp_path)
        assert relative_bases(groups, tmp_path) == ["app/compose.yaml"]

    def test_only_noise_dirs_raises(self, tmp_path: Path) -> None:
        write(tmp_path / ".git" / "compose.yaml")
        write(tmp_path / "node_modules" / "pkg" / "docker-compose.yml")
        with pytest.raises(DiscoveryError):
            find_compose_groups(tmp_path)


class TestDiscoveryError:
    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        (tmp_path / "docs").mkdir()
        with pytest.raises(DiscoveryError):
            find_compose_groups(tmp_path)

    def test_non_compose_yaml_is_not_discovered(self, tmp_path: Path) -> None:
        write(tmp_path / "config.yaml")
        write(tmp_path / "docs" / "notes.yml")
        with pytest.raises(DiscoveryError):
            find_compose_groups(tmp_path)


class TestDiscoveryToParsePipeline:
    def test_discovered_groups_parse_into_a_stack(self, tmp_path: Path) -> None:
        write(tmp_path / "web" / "compose.yaml", "services:\n  web:\n    image: nginx:1.27\n")
        write(tmp_path / "db" / "compose.yaml", "services:\n  db:\n    image: postgres:16\n")
        stack = parse_compose_groups(find_compose_groups(tmp_path), tmp_path)
        assert set(stack.services) == {"web", "db"}
        assert len(stack.files) == 2
        assert all(service.image is not None for service in stack.services.values())
