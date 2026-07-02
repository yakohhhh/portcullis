"""Tests for Traefik file-configuration parsing (:mod:`portcullis.parsers.traefik`).

Builds a stack in memory, writes realistic Traefik configuration (YAML, TOML,
command-line flags, a file-provider directory reached through a bind mount)
to ``tmp_path``, and checks that the resulting routing table drives the
exposure engine correctly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portcullis import exposure as exposure_engine
from portcullis.model import (
    Exposure,
    ImageRef,
    PortMapping,
    Service,
    Stack,
    VolumeMount,
)
from portcullis.parsers import traefik


def make_service(name: str, image: str = "nginx:latest", **kwargs) -> Service:
    return Service(name=name, image=ImageRef.parse(image), **kwargs)


def make_stack(tmp_path: Path, *services: Service) -> Stack:
    compose = tmp_path / "docker-compose.yml"
    for service in services:
        if service.source_file is None:
            service.source_file = compose
    return Stack(root=tmp_path, services={s.name: s for s in services})


def traefik_service(tmp_path: Path, **kwargs) -> Service:
    svc = make_service("traefik", image="traefik:v3.1", **kwargs)
    svc.source_file = tmp_path / "docker-compose.yml"
    return svc


class TestDynamicRouting:
    def test_yaml_router_to_service_url_marks_internet(self, tmp_path: Path) -> None:
        (tmp_path / "traefik.yml").write_text(
            """
            entryPoints:
              websecure:
                address: ":443"
            http:
              routers:
                vault:
                  rule: "Host(`vault.example.com`)"
                  entryPoints: [websecure]
                  service: vault-svc
              services:
                vault-svc:
                  loadBalancer:
                    servers:
                      - url: "http://vaultwarden:80"
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("vaultwarden"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert routing.routes_to_internet("vaultwarden")
        exposures = exposure_engine.classify(stack, routing)
        assert exposures["vaultwarden"] == Exposure.INTERNET

    def test_toml_configuration_is_equivalent(self, tmp_path: Path) -> None:
        (tmp_path / "traefik.toml").write_text(
            """
            [entryPoints.websecure]
              address = ":443"
            [http.routers.vault]
              rule = "Host(`vault.example.com`)"
              entryPoints = ["websecure"]
              service = "vault-svc"
            [http.services.vault-svc.loadBalancer]
              [[http.services.vault-svc.loadBalancer.servers]]
                url = "http://vaultwarden:80"
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("vaultwarden"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.toml"])
        assert routing.routes_to_internet("vaultwarden")

    def test_router_service_suffix_is_stripped(self, tmp_path: Path) -> None:
        (tmp_path / "traefik.yml").write_text(
            """
            http:
              routers:
                app:
                  rule: "Host(`app.example.com`)"
                  service: app-svc@file
              services:
                app-svc:
                  loadBalancer:
                    servers:
                      - url: "http://webapp:8080"
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("webapp"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert routing.routes_to_internet("webapp")

    def test_router_without_loadbalancer_uses_service_name_as_host(self, tmp_path: Path) -> None:
        # A router whose service is not defined as a load balancer: the service
        # reference is treated as the compose service name directly.
        (tmp_path / "traefik.yml").write_text(
            """
            http:
              routers:
                grafana:
                  rule: "Host(`grafana.example.com`)"
                  service: grafana
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("grafana"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert routing.routes_to_internet("grafana")


class TestEntrypointAwareness:
    def test_loopback_entrypoint_routes_to_host_not_internet(self, tmp_path: Path) -> None:
        (tmp_path / "traefik.yml").write_text(
            """
            entryPoints:
              internal:
                address: "127.0.0.1:8081"
            http:
              routers:
                admin:
                  rule: "Host(`admin.example.com`)"
                  entryPoints: [internal]
                  service: admin-svc
              services:
                admin-svc:
                  loadBalancer:
                    servers:
                      - url: "http://dashboard:3000"
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("dashboard"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert not routing.routes_to_internet("dashboard")
        assert routing.routes_to_host("dashboard")
        exposures = exposure_engine.classify(stack, routing)
        assert exposures["dashboard"] == Exposure.HOST

    def test_public_entrypoint_wins_over_loopback(self, tmp_path: Path) -> None:
        (tmp_path / "traefik.yml").write_text(
            """
            entryPoints:
              web:
                address: ":80"
              internal:
                address: "127.0.0.1:8081"
            http:
              routers:
                app:
                  rule: "Host(`app.example.com`)"
                  entryPoints: [web, internal]
                  service: app-svc
              services:
                app-svc:
                  loadBalancer:
                    servers:
                      - url: "http://webapp:8080"
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("webapp"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert routing.routes_to_internet("webapp")


class TestCommandArgs:
    def test_entrypoints_and_provider_read_from_command(self, tmp_path: Path) -> None:
        proxy = traefik_service(
            tmp_path,
            command=[
                "--providers.docker=true",
                "--providers.docker.exposedByDefault=false",
                "--entrypoints.web.address=:80",
            ],
            networks=["proxy"],
        )
        # A router in a dynamic file, entrypoints declared only on the CLI.
        (tmp_path / "traefik.yml").write_text(
            """
            http:
              routers:
                app:
                  rule: "Host(`app.example.com`)"
                  entryPoints: [web]
                  service: app
            """,
            encoding="utf-8",
        )
        stack = make_stack(tmp_path, proxy, make_service("app", networks=["proxy"]))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert routing.routes_to_internet("app")


class TestExposedByDefault:
    def test_default_true_exposes_services_on_the_proxy_network(self, tmp_path: Path) -> None:
        proxy = traefik_service(
            tmp_path, command=["--providers.docker=true"], networks=["proxy"]
        )
        stack = make_stack(
            tmp_path,
            proxy,
            make_service("app", networks=["proxy"]),
            make_service("isolated", networks=["backend"]),
        )
        routing = traefik.analyze(stack, [])
        assert routing.routes_to_internet("app")
        assert not routing.routes_to_internet("isolated")

    def test_exposed_by_default_false_disables_expansion(self, tmp_path: Path) -> None:
        proxy = traefik_service(
            tmp_path,
            command=["--providers.docker=true", "--providers.docker.exposedByDefault=false"],
            networks=["proxy"],
        )
        stack = make_stack(tmp_path, proxy, make_service("app", networks=["proxy"]))
        routing = traefik.analyze(stack, [])
        assert not routing.routes_to_internet("app")

    def test_traefik_enable_false_opts_a_service_out(self, tmp_path: Path) -> None:
        proxy = traefik_service(
            tmp_path, command=["--providers.docker=true"], networks=["proxy"]
        )
        opted_out = make_service("private", networks=["proxy"],
                                 labels={"traefik.enable": "false"})
        stack = make_stack(tmp_path, proxy, opted_out, make_service("app", networks=["proxy"]))
        routing = traefik.analyze(stack, [])
        assert routing.routes_to_internet("app")
        assert not routing.routes_to_internet("private")


class TestFileProvider:
    def test_dynamic_directory_resolved_through_bind_mount(self, tmp_path: Path) -> None:
        dynamic_dir = tmp_path / "dynamic"
        dynamic_dir.mkdir()
        (dynamic_dir / "routes.yml").write_text(
            """
            http:
              routers:
                app:
                  rule: "Host(`app.example.com`)"
                  service: app-svc
              services:
                app-svc:
                  loadBalancer:
                    servers:
                      - url: "http://webapp:8080"
            """,
            encoding="utf-8",
        )
        proxy = traefik_service(
            tmp_path,
            command=["--providers.file.directory=/etc/traefik/dynamic"],
            volumes=[
                VolumeMount(source="./dynamic", target="/etc/traefik/dynamic", kind="bind")
            ],
        )
        stack = make_stack(tmp_path, proxy, make_service("webapp"))
        routing = traefik.analyze(stack, [])
        assert routing.routes_to_internet("webapp")


class TestBypassAndNoConfig:
    def test_file_routed_service_with_published_port_bypasses_proxy(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "traefik.yml").write_text(
            """
            entryPoints:
              web:
                address: ":80"
            http:
              routers:
                app:
                  rule: "Host(`app.example.com`)"
                  service: app
            """,
            encoding="utf-8",
        )
        app = make_service("app", ports=[PortMapping(container_port=80, host_port=8080)])
        stack = make_stack(tmp_path, traefik_service(tmp_path), app)
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert exposure_engine.bypasses_proxy(app, routing)

    def test_no_traefik_config_yields_empty_routing(self, tmp_path: Path) -> None:
        stack = make_stack(tmp_path, make_service("app"))
        routing = traefik.analyze(stack, [])
        assert not routing.internet_routed
        assert not routing.host_routed

    def test_malformed_config_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "traefik.yml").write_text("http: [unclosed\n", encoding="utf-8")
        stack = make_stack(tmp_path, traefik_service(tmp_path), make_service("app"))
        routing = traefik.analyze(stack, [tmp_path / "traefik.yml"])
        assert not routing.internet_routed


@pytest.mark.parametrize(
    ("address", "loopback"),
    [
        (":80", False),
        ("0.0.0.0:80", False),
        ("127.0.0.1:8080", True),
        ("[::1]:8080", True),
        ("localhost:9000", True),
    ],
)
def test_entrypoint_loopback_detection(address: str, loopback: bool) -> None:
    entry = traefik._Entrypoint(name="e", address=address)
    assert entry.loopback_only is loopback
