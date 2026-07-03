"""Tests for mechanical patch suggestions (:mod:`portcullis.patches`).

The key property is round-trip safety: a generated diff must apply cleanly to
the original file (checked with ``git apply``) and the re-scanned stack must no
longer show the finding the patch addressed.
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from portcullis import patches, scanner


def write_compose(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "docker-compose.yml"
    path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return path


def apply_patch(tmp_path: Path, diff: str) -> None:
    """Apply a unified diff with `git apply` from tmp_path (fails the test if it does not apply)."""
    (tmp_path / ".p.patch").write_text(diff, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "apply", "--check", ".p.patch"], cwd=tmp_path, check=True)
    subprocess.run(["git", "apply", ".p.patch"], cwd=tmp_path, check=True)


def rule_ids(path: Path) -> set[str]:
    return {f.rule_id for f in scanner.scan(path, use_trivy=False).findings}


def removed(diff: str) -> list[str]:
    """Content of the lines a diff removes (`-` prefix, excluding the `---` header)."""
    return [line[1:] for line in diff.splitlines()
            if line.startswith("-") and not line.startswith("---")]


class TestGeneration:
    def test_removes_privileged(self, tmp_path: Path) -> None:
        write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                privileged: true
        """)
        result = scanner.scan(tmp_path, use_trivy=False)
        [patch] = patches.generate_patches(result)
        assert "privileged: true" in patch.diff
        assert patch.diff.count("\n-") >= 1
        assert any("PC-002" in r for r in patch.reasons)

    def test_removes_bypassing_port(self, tmp_path: Path) -> None:
        write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                labels:
                  - traefik.enable=true
                ports:
                  - "8081:80"
        """)
        result = scanner.scan(tmp_path, use_trivy=False)
        patchset = patches.generate_patches(result)
        assert patchset
        assert any('8081:80' in p.diff for p in patchset)

    def test_drops_dangerous_capability(self, tmp_path: Path) -> None:
        write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                cap_add:
                  - SYS_ADMIN
                  - NET_BIND_SERVICE
        """)
        result = scanner.scan(tmp_path, use_trivy=False)
        [patch] = patches.generate_patches(result)
        removed_lines = removed(patch.diff)
        # the dangerous cap is removed, the harmless one and the key are kept
        assert any("SYS_ADMIN" in line for line in removed_lines)
        assert not any("NET_BIND_SERVICE" in line for line in removed_lines)
        assert not any("cap_add" in line for line in removed_lines)

    def test_rebinds_database_port_to_loopback(self, tmp_path: Path) -> None:
        write_compose(tmp_path, """
            services:
              db:
                image: postgres:16
                environment:
                  POSTGRES_PASSWORD: s3cret-not-weak-value
                ports:
                  - "5432:5432"
        """)
        result = scanner.scan(tmp_path, use_trivy=False)
        patchset = patches.generate_patches(result)
        assert any("127.0.0.1:5432:5432" in p.diff for p in patchset)

    def test_removes_docker_socket_mount(self, tmp_path: Path) -> None:
        write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
                  - data:/data
        """)
        result = scanner.scan(tmp_path, use_trivy=False)
        [patch] = patches.generate_patches(result)
        removed_lines = removed(patch.diff)
        assert any("docker.sock" in line for line in removed_lines)
        assert not any("data:/data" in line for line in removed_lines)  # good mount untouched

    def test_no_patch_for_clean_stack(self, tmp_path: Path) -> None:
        write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
        """)
        result = scanner.scan(tmp_path, use_trivy=False)
        assert patches.generate_patches(result) == []


class TestRoundTrip:
    def test_privileged_patch_applies_and_clears_finding(self, tmp_path: Path) -> None:
        path = write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                privileged: true
        """)
        assert "PC-002" in rule_ids(path)
        [patch] = patches.generate_patches(scanner.scan(path, use_trivy=False))
        apply_patch(tmp_path, patch.diff)
        assert "PC-002" not in rule_ids(path)

    def test_capability_patch_applies_and_clears_finding(self, tmp_path: Path) -> None:
        path = write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                cap_add:
                  - SYS_ADMIN
        """)
        assert "PC-004" in rule_ids(path)
        [patch] = patches.generate_patches(scanner.scan(path, use_trivy=False))
        apply_patch(tmp_path, patch.diff)
        remaining = rule_ids(path)
        assert "PC-004" not in remaining

    def test_socket_patch_applies_and_clears_finding(self, tmp_path: Path) -> None:
        path = write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
        """)
        assert "PC-001" in rule_ids(path)
        [patch] = patches.generate_patches(scanner.scan(path, use_trivy=False))
        apply_patch(tmp_path, patch.diff)
        assert "PC-001" not in rule_ids(path)

    def test_combined_edits_one_file_apply_together(self, tmp_path: Path) -> None:
        # Two independent findings on the same file must combine into one clean diff.
        path = write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                privileged: true
                pid: host
        """)
        before = rule_ids(path)
        assert {"PC-002", "PC-007"} <= before
        [patch] = patches.generate_patches(scanner.scan(path, use_trivy=False))
        apply_patch(tmp_path, patch.diff)
        after = rule_ids(path)
        assert "PC-002" not in after and "PC-007" not in after


class TestCli:
    def test_suggest_patches_writes_a_file(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from portcullis.cli import main

        write_compose(tmp_path, """
            services:
              app:
                image: nginx:1.27
                privileged: true
        """)
        patch_file = tmp_path / "out.patch"
        result = CliRunner().invoke(
            main,
            ["scan", str(tmp_path), "--no-trivy", "--suggest-patches", str(patch_file)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert patch_file.is_file()
        assert "privileged: true" in patch_file.read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _git_identity(monkeypatch):
    # git apply needs no identity, but git init in a bare tmp dir should be quiet.
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")
