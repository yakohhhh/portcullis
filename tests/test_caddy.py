"""Tests for Caddyfile parsing (:mod:`portcullis.parsers.caddy`).

Writes realistic Caddyfiles to ``tmp_path`` and checks that the resulting
routing table drives the exposure engine: site addresses decide public vs
loopback, and ``reverse_proxy`` upstreams map back to compose services.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portcullis import exposure as exposure_engine
from portcullis.model import Exposure, ImageRef, PortMapping, Service, Stack
from portcullis.parsers import caddy


def make_service(name: str, image: str = "nginx:latest", **kwargs) -> Service:
    return Service(name=name, image=ImageRef.parse(image), **kwargs)


def make_stack(tmp_path: Path, *services: Service) -> Stack:
    return Stack(root=tmp_path, services={s.name: s for s in services})


def write_caddyfile(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "Caddyfile"
    path.write_text(content, encoding="utf-8")
    return path


class TestSiteBlocks:
    def test_simple_site_marks_upstream_internet(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            vault.example.com {
                reverse_proxy vaultwarden:80
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("vaultwarden"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("vaultwarden")
        exposures = exposure_engine.classify(stack, routing)
        assert exposures["vaultwarden"] == Exposure.INTERNET

    def test_multiple_addresses_one_block(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com, www.example.com {
                reverse_proxy webapp:8080
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")

    def test_multiple_sites(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            vault.example.com {
                reverse_proxy vaultwarden:80
            }

            grafana.example.com {
                reverse_proxy grafana:3000
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("vaultwarden"), make_service("grafana"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("vaultwarden")
        assert routing.routes_to_internet("grafana")

    def test_http_scheme_is_public(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            http://app.example.com {
                reverse_proxy webapp:8080
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")

    def test_port_only_address_is_public(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            :8080 {
                reverse_proxy webapp:9000
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")


class TestLoopbackSites:
    def test_localhost_site_routes_to_host(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            localhost:8080 {
                reverse_proxy dashboard:3000
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("dashboard"))
        routing = caddy.analyze(stack, [path])
        assert not routing.routes_to_internet("dashboard")
        assert routing.routes_to_host("dashboard")
        exposures = exposure_engine.classify(stack, routing)
        assert exposures["dashboard"] == Exposure.HOST

    def test_loopback_ip_site_routes_to_host(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            127.0.0.1:8080 {
                reverse_proxy dashboard:3000
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("dashboard"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_host("dashboard")
        assert not routing.routes_to_internet("dashboard")


class TestReverseProxyForms:
    def test_matcher_prefixed_upstream(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                reverse_proxy /api/* backend:8080
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("backend"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("backend")

    def test_block_form_with_to_directives(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                reverse_proxy {
                    to backend1:8080 backend2:8080
                    lb_policy round_robin
                }
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("backend1"), make_service("backend2"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("backend1")
        assert routing.routes_to_internet("backend2")

    def test_upstream_with_scheme(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                reverse_proxy https://webapp:8443
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")

    def test_nested_handle_block(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                handle /api/* {
                    reverse_proxy backend:8080
                }
                handle {
                    reverse_proxy frontend:3000
                }
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("backend"), make_service("frontend"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("backend")
        assert routing.routes_to_internet("frontend")


class TestSnippetsAndGlobals:
    def test_import_snippet_upstreams(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            (proxy_app) {
                reverse_proxy webapp:8080
            }

            app.example.com {
                import proxy_app
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")

    def test_global_options_block_is_ignored(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            {
                email admin@example.com
                admin off
            }

            app.example.com {
                reverse_proxy webapp:8080
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")
        # The email address in the global block must not be treated as a site.
        assert len(routing.internet_routed) == 1

    def test_comments_and_placeholders_are_ignored(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            # a comment
            {$SITE_ADDRESS} {
                # route to the app
                reverse_proxy webapp:8080 # inline comment
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        # The site address is an unresolved placeholder, so it defaults to
        # public; the upstream is still extracted.
        assert routing.routes_to_internet("webapp")


class TestOneLinerAndEdgeCases:
    def test_one_liner_form_without_braces(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            "app.example.com\nreverse_proxy webapp:8080\n",
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert routing.routes_to_internet("webapp")

    def test_unknown_upstream_is_not_matched(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                reverse_proxy not-a-service:8080
            }
            """,
        )
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        assert not routing.internet_routed

    def test_bypass_detected_for_published_port(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                reverse_proxy webapp:8080
            }
            """,
        )
        webapp = make_service("webapp", ports=[PortMapping(container_port=8080, host_port=8080)])
        stack = make_stack(tmp_path, webapp)
        routing = caddy.analyze(stack, [path])
        assert exposure_engine.bypasses_proxy(webapp, routing)

    def test_malformed_caddyfile_is_skipped(self, tmp_path: Path) -> None:
        path = write_caddyfile(tmp_path, 'app.example.com {\n  reverse_proxy "unterminated\n')
        stack = make_stack(tmp_path, make_service("webapp"))
        routing = caddy.analyze(stack, [path])
        # No crash; nothing confidently matched.
        assert isinstance(routing.internet_routed, set)

    def test_caddy_service_recorded_as_proxy(self, tmp_path: Path) -> None:
        path = write_caddyfile(
            tmp_path,
            """
            app.example.com {
                reverse_proxy webapp:8080
            }
            """,
        )
        stack = make_stack(
            tmp_path, make_service("caddy", image="caddy:2.8"), make_service("webapp")
        )
        routing = caddy.analyze(stack, [path])
        assert "caddy" in routing.proxy_services


@pytest.mark.parametrize(
    ("caddyfile", "expected_public"),
    [
        ("example.com {\n reverse_proxy app:80\n}", True),
        ("https://example.com:8443 {\n reverse_proxy app:80\n}", True),
        ("*.example.com {\n reverse_proxy app:80\n}", True),
        ("localhost {\n reverse_proxy app:80\n}", False),
    ],
)
def test_site_publicness(tmp_path: Path, caddyfile: str, expected_public: bool) -> None:
    path = write_caddyfile(tmp_path, caddyfile)
    stack = make_stack(tmp_path, make_service("app"))
    routing = caddy.analyze(stack, [path])
    assert routing.routes_to_internet("app") is expected_public
    assert routing.routes_to_host("app") is not expected_public
