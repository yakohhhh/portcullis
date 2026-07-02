"""Tests for the exposure engine (:mod:`portcullis.exposure`).

Covers the full classification matrix: published ports (loopback vs all
interfaces), reverse proxy routing (Traefik, caddy-docker-proxy,
nginx-proxy), ``internal: true`` networks, host networking and the
proxy-bypass detection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portcullis.exposure import bypasses_proxy, classify, classify_service, is_proxied
from portcullis.model import Exposure, Network, PortMapping, Service, Stack


def make_stack(*services: Service, networks: dict[str, Network] | None = None) -> Stack:
    return Stack(
        root=Path("."),
        services={service.name: service for service in services},
        networks=networks or {},
    )


def lan_port() -> PortMapping:
    """A port published on all interfaces (compose default, empty host_ip)."""
    return PortMapping(container_port=80, host_port=8080)


def loopback_port(host_ip: str = "127.0.0.1") -> PortMapping:
    return PortMapping(container_port=80, host_port=8080, host_ip=host_ip)


class TestClassifyPorts:
    def test_no_ports_no_proxy_is_internal(self) -> None:
        service = Service(name="db")
        assert classify_service(service, make_stack(service)) is Exposure.INTERNAL

    @pytest.mark.parametrize("host_ip", ["127.0.0.1", "::1", "localhost"])
    def test_loopback_only_published_port_is_host(self, host_ip: str) -> None:
        service = Service(name="app", ports=[loopback_port(host_ip)])
        assert classify_service(service, make_stack(service)) is Exposure.HOST

    def test_port_on_all_interfaces_is_lan(self) -> None:
        service = Service(name="app", ports=[lan_port()])
        assert classify_service(service, make_stack(service)) is Exposure.LAN

    def test_explicit_0_0_0_0_is_lan(self) -> None:
        port = PortMapping(container_port=80, host_port=8080, host_ip="0.0.0.0")
        service = Service(name="app", ports=[port])
        assert classify_service(service, make_stack(service)) is Exposure.LAN

    def test_mixed_loopback_and_lan_ports_is_lan(self) -> None:
        service = Service(name="app", ports=[loopback_port(), lan_port()])
        assert classify_service(service, make_stack(service)) is Exposure.LAN


class TestClassifyProxy:
    def test_traefik_enable_true_is_internet(self) -> None:
        service = Service(name="app", labels={"traefik.enable": "true"})
        assert classify_service(service, make_stack(service)) is Exposure.INTERNET

    @pytest.mark.parametrize("value", ["true", "True", "TRUE", " true "])
    def test_traefik_enable_value_is_case_insensitive(self, value: str) -> None:
        service = Service(name="app", labels={"traefik.enable": value})
        assert is_proxied(service) is True
        assert classify_service(service, make_stack(service)) is Exposure.INTERNET

    def test_traefik_enable_false_is_not_proxied(self) -> None:
        service = Service(name="app", labels={"traefik.enable": "false"})
        assert is_proxied(service) is False
        assert classify_service(service, make_stack(service)) is Exposure.INTERNAL

    @pytest.mark.parametrize("key", ["caddy", "caddy.reverse_proxy"])
    def test_caddy_labels_are_proxied(self, key: str) -> None:
        service = Service(name="app", labels={key: "example.com"})
        assert is_proxied(service) is True
        assert classify_service(service, make_stack(service)) is Exposure.INTERNET

    def test_virtual_host_env_is_proxied(self) -> None:
        service = Service(name="app", environment={"VIRTUAL_HOST": "app.example.com"})
        assert is_proxied(service) is True
        assert classify_service(service, make_stack(service)) is Exposure.INTERNET

    def test_no_proxy_signal_is_not_proxied(self) -> None:
        service = Service(name="app", labels={"com.example.foo": "bar"})
        assert is_proxied(service) is False


class TestClassifyHostNetworking:
    def test_network_mode_host_without_proxy_is_lan(self) -> None:
        service = Service(name="app", network_mode="host")
        assert classify_service(service, make_stack(service)) is Exposure.LAN

    def test_network_mode_host_with_proxy_is_internet(self) -> None:
        service = Service(
            name="app",
            network_mode="host",
            labels={"traefik.enable": "true"},
        )
        assert classify_service(service, make_stack(service)) is Exposure.INTERNET


class TestClassifyInternalNetworks:
    def test_published_ports_on_only_internal_networks_is_internal(self) -> None:
        service = Service(name="app", ports=[lan_port()], networks=["backend"])
        stack = make_stack(service, networks={"backend": Network(name="backend", internal=True)})
        assert classify_service(service, stack) is Exposure.INTERNAL

    def test_mix_of_internal_and_normal_networks_is_lan(self) -> None:
        service = Service(name="app", ports=[lan_port()], networks=["backend", "frontend"])
        stack = make_stack(
            service,
            networks={
                "backend": Network(name="backend", internal=True),
                "frontend": Network(name="frontend", internal=False),
            },
        )
        assert classify_service(service, stack) is Exposure.LAN

    def test_unknown_network_name_ports_still_count(self) -> None:
        service = Service(name="app", ports=[lan_port()], networks=["ghost"])
        stack = make_stack(service)  # "ghost" is not declared in stack.networks
        assert classify_service(service, stack) is Exposure.LAN


class TestBypassesProxy:
    def test_proxied_with_lan_port_bypasses(self) -> None:
        service = Service(
            name="app",
            labels={"traefik.enable": "true"},
            ports=[lan_port()],
        )
        assert bypasses_proxy(service) is True

    def test_proxied_with_loopback_only_port_does_not_bypass(self) -> None:
        service = Service(
            name="app",
            labels={"traefik.enable": "true"},
            ports=[loopback_port()],
        )
        assert bypasses_proxy(service) is False

    def test_proxied_without_ports_does_not_bypass(self) -> None:
        service = Service(name="app", labels={"traefik.enable": "true"})
        assert bypasses_proxy(service) is False

    def test_unproxied_with_lan_port_does_not_bypass(self) -> None:
        service = Service(name="app", ports=[lan_port()])
        assert bypasses_proxy(service) is False


class TestClassifyStack:
    def test_classify_returns_every_service_keyed_by_name(self) -> None:
        internal = Service(name="db")
        host = Service(name="cache", ports=[loopback_port()])
        lan = Service(name="app", ports=[lan_port()])
        internet = Service(name="web", labels={"traefik.enable": "true"})
        stack = make_stack(internal, host, lan, internet)
        assert classify(stack) == {
            "db": Exposure.INTERNAL,
            "cache": Exposure.HOST,
            "app": Exposure.LAN,
            "web": Exposure.INTERNET,
        }
