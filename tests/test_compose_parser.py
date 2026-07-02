"""Tests for the compose parser (:mod:`portcullis.parsers.compose`).

Every test writes real compose files into ``tmp_path`` and parses them through
the public pipeline (:func:`find_compose_groups` + :func:`parse_compose_groups`)
so discovery, override merging and service parsing are exercised together,
without any filesystem mocking.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from portcullis.discovery import find_compose_groups
from portcullis.model import ImageRef, PortMapping, Stack, VolumeMount
from portcullis.parsers.compose import parse_compose_groups


def write_compose(directory: Path, content: str, name: str = "compose.yaml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    file = directory / name
    file.write_text(dedent(content), encoding="utf-8")
    return file


def parse_tree(root: Path) -> Stack:
    return parse_compose_groups(find_compose_groups(root), root)


def parse_ports(directory: Path, *entries: str) -> list[PortMapping]:
    """Write a one-service compose file with the given short-syntax ``ports:`` entries."""
    lines = "".join(f'      - "{entry}"\n' for entry in entries)
    content = "services:\n  app:\n    image: nginx\n    ports:\n" + lines
    (directory / "compose.yaml").write_text(content, encoding="utf-8")
    return parse_tree(directory).services["app"].ports


class TestPortShortSyntax:
    def test_container_port_only(self, tmp_path: Path) -> None:
        (mapping,) = parse_ports(tmp_path, "80")
        assert isinstance(mapping, PortMapping)
        assert mapping.container_port == 80
        assert mapping.host_port is None
        assert mapping.host_ip == ""
        assert mapping.protocol == "tcp"

    def test_host_and_container_ports(self, tmp_path: Path) -> None:
        (mapping,) = parse_ports(tmp_path, "8080:80")
        assert mapping.host_port == 8080
        assert mapping.container_port == 80
        assert mapping.host_ip == ""
        assert mapping.raw == "8080:80"

    def test_ipv4_host_ip(self, tmp_path: Path) -> None:
        (mapping,) = parse_ports(tmp_path, "127.0.0.1:5432:5432")
        assert mapping.host_ip == "127.0.0.1"
        assert mapping.host_port == 5432
        assert mapping.container_port == 5432
        assert mapping.loopback_only is True

    def test_bracketed_ipv6_host_ip(self, tmp_path: Path) -> None:
        (mapping,) = parse_ports(tmp_path, "[::1]:8080:80")
        assert mapping.host_ip == "::1"
        assert mapping.host_port == 8080
        assert mapping.container_port == 80
        assert mapping.loopback_only is True

    def test_port_range_expands_pairwise(self, tmp_path: Path) -> None:
        mappings = parse_ports(tmp_path, "8000-8002:9000-9002")
        assert [(m.host_port, m.container_port) for m in mappings] == [
            (8000, 9000),
            (8001, 9001),
            (8002, 9002),
        ]

    def test_protocol_suffix(self, tmp_path: Path) -> None:
        (mapping,) = parse_ports(tmp_path, "53:53/udp")
        assert mapping.protocol == "udp"
        assert mapping.host_port == 53
        assert mapping.container_port == 53

    def test_unresolved_variable_is_skipped_without_crashing(self, tmp_path: Path) -> None:
        mappings = parse_ports(tmp_path, "${WEB_PORT}:80", "8080:80")
        assert len(mappings) == 1
        assert mappings[0].host_port == 8080
        assert mappings[0].container_port == 80


class TestPortLongSyntax:
    def test_long_syntax_fields(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                ports:
                  - target: 80
                    published: 8080
                    host_ip: 127.0.0.1
                    protocol: udp
                  - target: 443
                  - published: 9999
            """,
        )
        ports = parse_tree(tmp_path).services["app"].ports
        assert len(ports) == 2  # the entry without a target is dropped
        first, second = ports
        assert (first.container_port, first.host_port) == (80, 8080)
        assert first.host_ip == "127.0.0.1"
        assert first.protocol == "udp"
        assert (second.container_port, second.host_port) == (443, None)
        assert second.host_ip == ""
        assert second.protocol == "tcp"


class TestEnvironment:
    def test_mapping_form(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                environment:
                  DB_HOST: db
                  DB_PORT: 5432
                  EMPTY: ""
                  PASSTHROUGH:
            """,
        )
        env = parse_tree(tmp_path).services["app"].environment
        # A null value ("PASSTHROUGH:") means "resolve from the host env at
        # deploy time" and is dropped; an explicit empty string is kept.
        assert env == {"DB_HOST": "db", "DB_PORT": "5432", "EMPTY": ""}

    def test_list_form(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                environment:
                  - DB_HOST=db
                  - EXPLICIT_EMPTY=
                  - PASSTHROUGH
            """,
        )
        env = parse_tree(tmp_path).services["app"].environment
        # "- PASSTHROUGH" (no "=") is a host pass-through and is dropped;
        # "- EXPLICIT_EMPTY=" really is an empty value and is kept.
        assert env == {"DB_HOST": "db", "EXPLICIT_EMPTY": ""}

    def test_env_file_loaded_and_environment_wins(self, tmp_path: Path) -> None:
        (tmp_path / "app.env").write_text(
            "# a comment\n"
            "FROM_FILE=file-value\n"
            "SHARED=file-value\n"
            "QUOTED='secret'\n"
            "no equal sign on this line\n",
            encoding="utf-8",
        )
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                env_file: app.env
                environment:
                  SHARED: env-value
            """,
        )
        env = parse_tree(tmp_path).services["app"].environment
        assert env["FROM_FILE"] == "file-value"
        assert env["QUOTED"] == "secret"
        assert env["SHARED"] == "env-value"  # environment overrides env_file
        assert len(env) == 3  # comment and malformed lines are skipped

    def test_interpolation_defaults(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                environment:
                  PORT: "${PORT:-8080}"
                  URL: "postgres://db:${DB_PORT:-5432}/app"
                  TOKEN: "${TOKEN}"
            """,
        )
        env = parse_tree(tmp_path).services["app"].environment
        assert env["PORT"] == "8080"
        assert env["URL"] == "postgres://db:5432/app"
        assert env["TOKEN"] == "${TOKEN}"  # no default: kept verbatim


class TestLabels:
    def test_mapping_form(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                labels:
                  traefik.enable: "true"
                  com.example.weight: 3
            """,
        )
        labels = parse_tree(tmp_path).services["app"].labels
        assert labels == {"traefik.enable": "true", "com.example.weight": "3"}

    def test_list_form(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                labels:
                  - "traefik.enable=true"
                  - "traefik.http.routers.app.rule=Host(`app.example.com`)"
                  - "bare-flag"
            """,
        )
        labels = parse_tree(tmp_path).services["app"].labels
        assert labels["traefik.enable"] == "true"
        assert labels["traefik.http.routers.app.rule"] == "Host(`app.example.com`)"
        assert labels["bare-flag"] == ""
        assert len(labels) == 3


class TestVolumes:
    def test_short_syntax(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                volumes:
                  - ./data:/data
                  - media:/srv/media
                  - /var/run/docker.sock:/var/run/docker.sock:ro
            """,
        )
        volumes = parse_tree(tmp_path).services["app"].volumes
        assert len(volumes) == 3
        assert all(isinstance(mount, VolumeMount) for mount in volumes)
        bind, named, sock = volumes
        assert (bind.source, bind.target) == ("./data", "/data")
        assert bind.kind == "bind"
        assert bind.read_only is False
        assert (named.source, named.target) == ("media", "/srv/media")
        assert named.kind == "volume"
        assert named.read_only is False
        assert (sock.source, sock.target) == ("/var/run/docker.sock", "/var/run/docker.sock")
        assert sock.kind == "bind"
        assert sock.read_only is True

    def test_long_syntax(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                volumes:
                  - type: bind
                    source: ./config
                    target: /config
                    read_only: true
            """,
        )
        (mount,) = parse_tree(tmp_path).services["app"].volumes
        assert mount.kind == "bind"
        assert mount.source == "./config"
        assert mount.target == "/config"
        assert mount.read_only is True


class TestImageRef:
    def test_bare_name(self) -> None:
        ref = ImageRef.parse("nginx")
        assert ref.repository == "nginx"
        assert ref.tag is None
        assert ref.digest is None
        assert ref.name == "nginx"

    def test_name_and_tag(self) -> None:
        ref = ImageRef.parse("nginx:1.25-alpine")
        assert ref.repository == "nginx"
        assert ref.tag == "1.25-alpine"
        assert ref.digest is None

    def test_registry_with_port(self) -> None:
        ref = ImageRef.parse("localhost:5000/team/app:2.1")
        assert ref.repository == "localhost:5000/team/app"
        assert ref.tag == "2.1"
        assert ref.name == "app"

    def test_digest(self) -> None:
        ref = ImageRef.parse("nginx@sha256:" + "0" * 64)
        assert ref.repository == "nginx"
        assert ref.tag is None
        assert ref.digest == "sha256:" + "0" * 64

    def test_tag_and_digest(self) -> None:
        ref = ImageRef.parse("ghcr.io/owner/app:v1@sha256:" + "a" * 64)
        assert ref.repository == "ghcr.io/owner/app"
        assert ref.tag == "v1"
        assert ref.digest == "sha256:" + "a" * 64
        assert ref.name == "app"

    def test_name_property_strips_namespace(self) -> None:
        assert ImageRef.parse("vaultwarden/server:latest").name == "server"


class TestOverrideMerging:
    def test_override_semantics(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx:1.0
                ports:
                  - "8080:80"
                environment:
                  KEEP: base
                  SHARED: base
            """,
        )
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx:2.0
                ports:
                  - "8080:80"
                  - "9090:90"
                environment:
                  SHARED: override
                  ADDED: override
            """,
            name="compose.override.yaml",
        )
        groups = find_compose_groups(tmp_path)
        assert len(groups) == 1
        assert [file.name for file in groups[0].files] == [
            "compose.yaml",
            "compose.override.yaml",
        ]

        stack = parse_compose_groups(groups, tmp_path)
        assert len(stack.files) == 2
        app = stack.services["app"]
        assert app.image is not None
        assert app.image.tag == "2.0"  # scalar: the override wins
        # Lists are concatenated with duplicates removed, order preserved.
        assert [(m.host_port, m.container_port) for m in app.ports] == [(8080, 80), (9090, 90)]
        # Mappings are deep-merged key by key.
        assert app.environment == {"KEEP": "base", "SHARED": "override", "ADDED": "override"}


class TestDuplicateServiceNames:
    def test_duplicates_across_groups_are_namespaced(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path / "alpha",
            """
            services:
              app:
                image: nginx:1.0
            """,
        )
        write_compose(
            tmp_path / "beta",
            """
            services:
              app:
                image: nginx:2.0
            """,
        )
        stack = parse_tree(tmp_path)
        assert set(stack.services) == {"app", "beta/app"}
        first = stack.services["app"]
        second = stack.services["beta/app"]
        assert second.name == "beta/app"
        assert first.image is not None
        assert second.image is not None
        assert first.image.tag == "1.0"
        assert second.image.tag == "2.0"


class TestNetworks:
    def test_top_level_networks(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              db:
                image: postgres:16
                networks:
                  - backend
            networks:
              backend:
                internal: true
              frontend:
            """,
        )
        stack = parse_tree(tmp_path)
        assert set(stack.networks) == {"backend", "frontend"}
        assert stack.networks["backend"].internal is True
        assert stack.networks["frontend"].internal is False
        assert stack.services["db"].networks == ["backend"]

    def test_service_networks_mapping_form(self, tmp_path: Path) -> None:
        write_compose(
            tmp_path,
            """
            services:
              app:
                image: nginx
                networks:
                  frontend:
                    aliases:
                      - web
                  backend:
            networks:
              frontend:
              backend:
                internal: true
            """,
        )
        stack = parse_tree(tmp_path)
        assert stack.services["app"].networks == ["frontend", "backend"]
        assert stack.networks["backend"].internal is True
