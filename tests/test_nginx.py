"""Tests for nginx and Nginx Proxy Manager parsing (:mod:`portcullis.parsers.nginx`)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from portcullis import exposure as exposure_engine
from portcullis.discovery import find_nginx_configs, find_npm_databases
from portcullis.model import Exposure, ImageRef, PortMapping, Service, Stack
from portcullis.parsers import nginx


def make_service(name: str, image: str = "app:1.0", **kwargs) -> Service:
    return Service(name=name, image=ImageRef.parse(image), **kwargs)


def make_stack(tmp_path: Path, *services: Service) -> Stack:
    return Stack(root=tmp_path, services={s.name: s for s in services})


def write_conf(tmp_path: Path, content: str, name: str = "default.conf") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestRawNginx:
    def test_proxy_pass_marks_service_internet(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server {
                listen 443 ssl;
                server_name vault.example.com;
                location / {
                    proxy_pass http://vaultwarden:80;
                }
            }
        """)
        stack = make_stack(tmp_path, make_service("vaultwarden"))
        routing = nginx.analyze(stack, [conf])
        assert routing.routes_to_internet("vaultwarden")
        exposures = exposure_engine.classify(stack, routing)
        assert exposures["vaultwarden"] == Exposure.INTERNET

    def test_loopback_listen_routes_to_host(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server {
                listen 127.0.0.1:8080;
                server_name admin.local;
                location / { proxy_pass http://dashboard:3000; }
            }
        """)
        stack = make_stack(tmp_path, make_service("dashboard"))
        routing = nginx.analyze(stack, [conf])
        assert routing.routes_to_host("dashboard")
        assert not routing.routes_to_internet("dashboard")
        assert exposure_engine.classify(stack, routing)["dashboard"] == Exposure.HOST

    def test_multiple_server_blocks(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server { listen 80; server_name a; location / { proxy_pass http://app_a:80; } }
            server { listen 80; server_name b; location / { proxy_pass http://app_b:80; } }
        """)
        stack = make_stack(tmp_path, make_service("app_a"), make_service("app_b"))
        routing = nginx.analyze(stack, [conf])
        assert routing.routes_to_internet("app_a")
        assert routing.routes_to_internet("app_b")

    def test_upstream_with_port_no_scheme(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server { listen 80; location / { proxy_pass http://backend:8080/; } }
        """)
        stack = make_stack(tmp_path, make_service("backend"))
        assert nginx.analyze(stack, [conf]).routes_to_internet("backend")

    def test_variable_upstream_is_skipped(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server {
                listen 80;
                set $upstream http://backend:80;
                location / { proxy_pass $upstream; }
            }
        """)
        stack = make_stack(tmp_path, make_service("backend"))
        assert not nginx.analyze(stack, [conf]).internet_routed

    def test_unknown_upstream_not_matched(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server { listen 80; location / { proxy_pass http://not-a-service:80; } }
        """)
        stack = make_stack(tmp_path, make_service("backend"))
        assert not nginx.analyze(stack, [conf]).internet_routed

    def test_comments_and_quotes_ignored(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            # a comment
            server {
                listen 80;  # inline
                server_name "app.example.com";
                location / { proxy_pass http://webapp:8080; }
            }
        """)
        stack = make_stack(tmp_path, make_service("webapp"))
        assert nginx.analyze(stack, [conf]).routes_to_internet("webapp")

    def test_bypass_detected(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server { listen 80; location / { proxy_pass http://webapp:8080; } }
        """)
        webapp = make_service("webapp", ports=[PortMapping(container_port=8080, host_port=8080)])
        stack = make_stack(tmp_path, webapp)
        routing = nginx.analyze(stack, [conf])
        assert exposure_engine.bypasses_proxy(webapp, routing)

    def test_malformed_config_skipped(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, 'server { listen 80; location / { proxy_pass "unterminated')
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = nginx.analyze(stack, [conf])
        assert isinstance(routing.internet_routed, set)

    def test_nginx_image_recorded_as_proxy(self, tmp_path: Path) -> None:
        conf = write_conf(tmp_path, """
            server { listen 80; location / { proxy_pass http://webapp:80; } }
        """)
        stack = make_stack(
            tmp_path, make_service("proxy", image="nginx:1.27"), make_service("webapp")
        )
        assert "proxy" in nginx.analyze(stack, [conf]).proxy_services


def build_npm_db(path: Path, rows: list[dict]) -> Path:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE proxy_host (id INTEGER PRIMARY KEY, domain_names TEXT, "
        "forward_host TEXT, forward_port INTEGER, forward_scheme TEXT, "
        "enabled INTEGER, is_deleted INTEGER)"
    )
    for i, row in enumerate(rows, 1):
        conn.execute(
            "INSERT INTO proxy_host VALUES (?, ?, ?, ?, ?, ?, ?)",
            (i, json.dumps(row.get("domains", ["x.example.com"])), row["forward_host"],
             row.get("forward_port", 80), "http", row.get("enabled", 1),
             row.get("is_deleted", 0)),
        )
    conn.commit()
    conn.close()
    return path


class TestNpmDatabase:
    def test_enabled_proxy_host_routes_internet(self, tmp_path: Path) -> None:
        db = build_npm_db(tmp_path / "database.sqlite",
                          [{"forward_host": "vaultwarden", "domains": ["vault.example.com"]}])
        stack = make_stack(tmp_path, make_service("vaultwarden"))
        routing = nginx.analyze(stack, [], [db])
        assert routing.routes_to_internet("vaultwarden")

    def test_disabled_host_ignored(self, tmp_path: Path) -> None:
        db = build_npm_db(tmp_path / "database.sqlite",
                          [{"forward_host": "vaultwarden", "enabled": 0}])
        stack = make_stack(tmp_path, make_service("vaultwarden"))
        assert not nginx.analyze(stack, [], [db]).internet_routed

    def test_deleted_host_ignored(self, tmp_path: Path) -> None:
        db = build_npm_db(tmp_path / "database.sqlite",
                          [{"forward_host": "vaultwarden", "is_deleted": 1}])
        stack = make_stack(tmp_path, make_service("vaultwarden"))
        assert not nginx.analyze(stack, [], [db]).internet_routed

    def test_non_npm_database_skipped(self, tmp_path: Path) -> None:
        db = tmp_path / "database.sqlite"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE other (id INTEGER)")
        conn.commit()
        conn.close()
        stack = make_stack(tmp_path, make_service("vaultwarden"))
        routing = nginx.analyze(stack, [], [db])  # must not raise
        assert not routing.internet_routed


class TestDiscovery:
    def test_finds_confs_in_conventional_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "conf.d").mkdir()
        (tmp_path / "conf.d" / "app.conf").write_text("server {}", encoding="utf-8")
        (tmp_path / "nginx.conf").write_text("server {}", encoding="utf-8")
        (tmp_path / "unrelated.conf").write_text("x", encoding="utf-8")
        found = {p.name for p in find_nginx_configs(tmp_path)}
        assert "app.conf" in found
        assert "nginx.conf" in found
        assert "unrelated.conf" not in found  # not in a conventional dir

    def test_finds_npm_database(self, tmp_path: Path) -> None:
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "database.sqlite").write_text("", encoding="utf-8")
        found = [p.name for p in find_npm_databases(tmp_path)]
        assert found == ["database.sqlite"]


@pytest.mark.parametrize(
    ("listen", "public"),
    [("80", True), ("443 ssl", True), ("0.0.0.0:80", True),
     ("127.0.0.1:8080", False), ("[::1]:80", False)],
)
def test_listen_publicness(tmp_path: Path, listen: str, public: bool) -> None:
    conf = write_conf(tmp_path, f"""
        server {{ listen {listen}; location / {{ proxy_pass http://app:80; }} }}
    """)
    stack = make_stack(tmp_path, make_service("app"))
    routing = nginx.analyze(stack, [conf])
    assert routing.routes_to_internet("app") is public
    assert routing.routes_to_host("app") is not public
