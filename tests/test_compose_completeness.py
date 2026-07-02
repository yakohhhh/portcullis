"""Tests for the compose parser's newer constructs (issue #10).

Covers project ``.env`` interpolation, ``profiles:``, ``extends:`` (same file
and cross file, with cycle protection), ``include:`` (with cycle protection),
top-level ``secrets:``/``configs:`` parsing, and the PC-012 rule.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from portcullis.discovery import find_compose_groups
from portcullis.parsers.compose import parse_compose_groups
from portcullis.rules import RuleContext, run_all


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return path


def parse_dir(tmp_path: Path):
    return parse_compose_groups(find_compose_groups(tmp_path), tmp_path)


class TestProjectEnvInterpolation:
    def test_image_tag_from_project_env(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: myapp:${APP_TAG}
        """)
        write(tmp_path / ".env", "APP_TAG=1.4.2\n")
        stack = parse_dir(tmp_path)
        assert stack.services["app"].image.raw == "myapp:1.4.2"
        assert stack.services["app"].image.tag == "1.4.2"

    def test_port_from_project_env(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                ports:
                  - "${WEB_PORT}:80"
        """)
        write(tmp_path / ".env", "WEB_PORT=8080\n")
        ports = parse_dir(tmp_path).services["app"].ports
        assert len(ports) == 1
        assert (ports[0].host_port, ports[0].container_port) == (8080, 80)

    def test_unknown_variable_stays_literal_and_is_skipped(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                ports:
                  - "${MISSING_PORT}:80"
        """)
        # No .env defines MISSING_PORT: the entry is unparseable, skipped, no crash.
        assert parse_dir(tmp_path).services["app"].ports == []

    def test_default_value_used_when_not_in_env(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:${NGINX_TAG:-1.27}
        """)
        assert parse_dir(tmp_path).services["app"].image.tag == "1.27"


class TestProfiles:
    def test_profiles_are_parsed_and_service_kept(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                profiles: [debug, dev]
        """)
        service = parse_dir(tmp_path).services["app"]
        assert service.profiles == ["debug", "dev"]  # all profiles scanned by default


class TestExtends:
    def test_same_file_extends_merges_base(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              base:
                image: nginx:1.27
                ports:
                  - "8080:80"
              app:
                extends:
                  service: base
                privileged: true
        """)
        app = parse_dir(tmp_path).services["app"]
        assert app.image.raw == "nginx:1.27"      # inherited from base
        assert app.privileged is True             # its own field
        assert len(app.ports) == 1                # inherited

    def test_cross_file_extends(self, tmp_path: Path) -> None:
        write(tmp_path / "common.yml", """
            services:
              base:
                image: redis:7.2
                privileged: true
        """)
        write(tmp_path / "docker-compose.yml", """
            services:
              cache:
                extends:
                  file: common.yml
                  service: base
        """)
        cache = parse_dir(tmp_path).services["cache"]
        assert cache.image.raw == "redis:7.2"
        assert cache.privileged is True

    def test_extends_cycle_is_broken_with_a_warning(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              a:
                image: nginx:1.27
                extends:
                  service: b
              b:
                extends:
                  service: a
        """)
        stack = parse_dir(tmp_path)  # must not hang or raise
        assert "a" in stack.services and "b" in stack.services
        assert any("circular extends" in w for w in stack.warnings)


class TestInclude:
    def test_included_services_are_present(self, tmp_path: Path) -> None:
        write(tmp_path / "db.yml", """
            services:
              db:
                image: postgres:16
        """)
        write(tmp_path / "docker-compose.yml", """
            include:
              - db.yml
            services:
              app:
                image: nginx:1.27
        """)
        stack = parse_dir(tmp_path)
        assert set(stack.services) == {"app", "db"}

    def test_include_dict_path_form(self, tmp_path: Path) -> None:
        write(tmp_path / "db.yml", """
            services:
              db:
                image: postgres:16
        """)
        write(tmp_path / "docker-compose.yml", """
            include:
              - path: db.yml
            services:
              app:
                image: nginx:1.27
        """)
        assert set(parse_dir(tmp_path).services) == {"app", "db"}

    def test_include_cycle_does_not_hang(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            include:
              - docker-compose.yml
            services:
              app:
                image: nginx:1.27
        """)
        assert set(parse_dir(tmp_path).services) == {"app"}


class TestSecretsAndConfigs:
    def test_top_level_secrets_and_service_secrets_parsed(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                secrets:
                  - db_password
            secrets:
              db_password:
                file: ./db_password.txt
            configs:
              nginx_conf:
                file: ./nginx.conf
        """)
        stack = parse_dir(tmp_path)
        assert stack.secret_names == {"db_password"}
        assert stack.services["app"].secrets == ["db_password"]


class TestPc012:
    def _findings(self, tmp_path: Path):
        stack = parse_dir(tmp_path)
        return run_all(RuleContext(stack=stack)), stack

    def test_fires_when_secret_in_env_and_secrets_section_exists(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                environment:
                  API_TOKEN: s3cr3t-Abc123-Long-Enough
            secrets:
              other:
                file: ./other.txt
        """)
        findings, _ = self._findings(tmp_path)
        assert any(f.rule_id == "PC-012" and f.service == "app" for f in findings)

    def test_silent_without_secrets_section(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                environment:
                  API_TOKEN: s3cr3t-Abc123-Long-Enough
        """)
        findings, _ = self._findings(tmp_path)
        assert not any(f.rule_id == "PC-012" for f in findings)

    def test_weak_value_is_pc008_not_pc012(self, tmp_path: Path) -> None:
        write(tmp_path / "docker-compose.yml", """
            services:
              app:
                image: nginx:1.27
                environment:
                  API_TOKEN: changeme
            secrets:
              other:
                file: ./other.txt
        """)
        findings, _ = self._findings(tmp_path)
        rule_ids = {f.rule_id for f in findings if f.service == "app"}
        assert "PC-008" in rule_ids
        assert "PC-012" not in rule_ids
