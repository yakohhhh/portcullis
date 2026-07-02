"""Tests for the foot-gun rules (PC-001 .. PC-011, :mod:`portcullis.rules.footguns`).

Every rule gets at least one positive and one negative case, built from
in-memory :class:`Stack`/:class:`Service` objects and an in-memory
:class:`KnowledgeBase` — no YAML files, no compose parsing involved.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portcullis.kb import AppInfo, KnowledgeBase
from portcullis.model import (
    Exposure,
    Finding,
    ImageRef,
    PortMapping,
    Service,
    Severity,
    Stack,
    VolumeMount,
)
from portcullis.rules import footguns
from portcullis.rules.base import RuleContext, run_all

DOCKER_SOCKET = "/var/run/docker.sock"


def make_ctx(
    *services: Service,
    exposures: dict[str, Exposure] | None = None,
    kb: KnowledgeBase | None = None,
) -> RuleContext:
    stack = Stack(root=Path("."), services={service.name: service for service in services})
    return RuleContext(stack=stack, exposures=exposures or {}, kb=kb)


def lan_port(container: int = 80, host: int = 8080) -> PortMapping:
    """A port published on all interfaces (compose default, empty host_ip)."""
    return PortMapping(container_port=container, host_port=host)


def loopback_port(container: int = 80, host: int = 8080) -> PortMapping:
    return PortMapping(container_port=container, host_port=host, host_ip="127.0.0.1")


def socket_mount(read_only: bool = False) -> VolumeMount:
    return VolumeMount(source=DOCKER_SOCKET, target=DOCKER_SOCKET, read_only=read_only,
                       kind="bind")


VAULTWARDEN = AppInfo(
    id="vaultwarden",
    name="Vaultwarden",
    category="passwords",
    sensitivity="critical",
    image_patterns=("vaultwarden/server", "*/vaultwarden"),
    exposure_recommendation="proxy-only",
)

POSTGRES = AppInfo(
    id="postgres",
    name="PostgreSQL",
    category="database",
    sensitivity="high",
    image_patterns=("postgres", "*/postgres"),
    exposure_recommendation="never",
)


def make_kb() -> KnowledgeBase:
    return KnowledgeBase([VAULTWARDEN, POSTGRES])


class TestDockerSocketMounted:
    """PC-001 — Docker socket mounted into a container."""

    def test_socket_mount_is_critical(self) -> None:
        service = Service(name="portainer", volumes=[socket_mount()])
        findings = list(footguns.docker_socket_mounted(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-001"
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].service == "portainer"

    def test_read_only_socket_mount_is_still_critical(self) -> None:
        service = Service(name="watchtower", volumes=[socket_mount(read_only=True)])
        findings = list(footguns.docker_socket_mounted(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-001"
        assert findings[0].severity is Severity.CRITICAL

    def test_regular_volume_is_clean(self) -> None:
        mount = VolumeMount(source="appdata", target="/data")
        service = Service(name="app", volumes=[mount])
        assert list(footguns.docker_socket_mounted(make_ctx(service))) == []


class TestPrivilegedContainer:
    """PC-002 — privileged mode."""

    def test_privileged_is_critical(self) -> None:
        service = Service(name="agent", privileged=True)
        findings = list(footguns.privileged_container(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-002"
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].service == "agent"

    def test_unprivileged_is_clean(self) -> None:
        service = Service(name="app", privileged=False)
        assert list(footguns.privileged_container(make_ctx(service))) == []


class TestHostNetworkMode:
    """PC-003 — host networking."""

    def test_network_mode_host_is_high(self) -> None:
        service = Service(name="homeassistant", network_mode="host")
        findings = list(footguns.host_network_mode(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-003"
        assert findings[0].severity is Severity.HIGH
        assert findings[0].service == "homeassistant"

    @pytest.mark.parametrize("mode", [None, "bridge"])
    def test_other_network_modes_are_clean(self, mode: str | None) -> None:
        service = Service(name="app", network_mode=mode)
        assert list(footguns.host_network_mode(make_ctx(service))) == []


class TestDangerousCapabilities:
    """PC-004 — dangerous Linux capabilities, including CAP_ prefix normalization."""

    @pytest.mark.parametrize(
        ("cap", "severity"),
        [
            ("SYS_ADMIN", Severity.HIGH),
            ("NET_ADMIN", Severity.MEDIUM),
            ("CAP_SYS_ADMIN", Severity.HIGH),
            ("CAP_NET_ADMIN", Severity.MEDIUM),
        ],
    )
    def test_dangerous_cap_severity(self, cap: str, severity: Severity) -> None:
        service = Service(name="vpn", cap_add=[cap])
        findings = list(footguns.dangerous_capabilities(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-004"
        assert findings[0].severity is severity
        assert findings[0].service == "vpn"

    def test_one_finding_per_dangerous_cap(self) -> None:
        service = Service(name="vpn", cap_add=["SYS_ADMIN", "NET_ADMIN"])
        findings = list(footguns.dangerous_capabilities(make_ctx(service)))
        assert [f.severity for f in findings] == [Severity.HIGH, Severity.MEDIUM]

    def test_harmless_cap_is_clean(self) -> None:
        service = Service(name="app", cap_add=["CHOWN"])
        assert list(footguns.dangerous_capabilities(make_ctx(service))) == []


class TestMutableImageTag:
    """PC-005 — no tag or ``latest``."""

    @pytest.mark.parametrize("raw", ["nginx:latest", "nginx"])
    def test_latest_or_missing_tag_is_low(self, raw: str) -> None:
        service = Service(name="web", image=ImageRef.parse(raw))
        findings = list(footguns.mutable_image_tag(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-005"
        assert findings[0].severity is Severity.LOW
        assert findings[0].service == "web"

    @pytest.mark.parametrize(
        "raw",
        [
            "nginx:1.27",
            "nginx@sha256:" + "a" * 64,
            "nginx:latest@sha256:" + "a" * 64,
        ],
    )
    def test_pinned_images_are_clean(self, raw: str) -> None:
        service = Service(name="web", image=ImageRef.parse(raw))
        assert list(footguns.mutable_image_tag(make_ctx(service))) == []

    def test_build_only_service_is_clean(self) -> None:
        service = Service(name="local", build=True, image=None)
        assert list(footguns.mutable_image_tag(make_ctx(service))) == []


class TestExplicitRootUser:
    """PC-006 — explicit root user."""

    @pytest.mark.parametrize("user", ["0", "root", "root:root"])
    def test_root_user_is_low(self, user: str) -> None:
        service = Service(name="app", user=user)
        findings = list(footguns.explicit_root_user(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-006"
        assert findings[0].severity is Severity.LOW
        assert findings[0].service == "app"

    @pytest.mark.parametrize("user", [None, "1000:1000", "1000", "www-data"])
    def test_non_root_user_is_clean(self, user: str | None) -> None:
        service = Service(name="app", user=user)
        assert list(footguns.explicit_root_user(make_ctx(service))) == []


class TestHostPidNamespace:
    """PC-007 — host PID namespace."""

    def test_pid_host_is_high(self) -> None:
        service = Service(name="monitor", pid="host")
        findings = list(footguns.host_pid_namespace(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-007"
        assert findings[0].severity is Severity.HIGH
        assert findings[0].service == "monitor"

    def test_default_pid_namespace_is_clean(self) -> None:
        service = Service(name="app")
        assert list(footguns.host_pid_namespace(make_ctx(service))) == []


class TestWeakOrDefaultSecrets:
    """PC-008 — weak, default or empty secrets, escalated by exposure."""

    def test_default_value_without_exposure_is_high(self) -> None:
        service = Service(name="db", environment={"MYSQL_PASSWORD": "changeme"})
        findings = list(footguns.weak_or_default_secrets(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-008"
        assert findings[0].severity is Severity.HIGH
        assert findings[0].service == "db"

    def test_empty_value_is_flagged(self) -> None:
        service = Service(name="db", environment={"ADMIN_TOKEN": ""})
        findings = list(footguns.weak_or_default_secrets(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-008"
        assert findings[0].severity is Severity.HIGH

    @pytest.mark.parametrize("exposure", [Exposure.LAN, Exposure.INTERNET])
    def test_reachable_service_escalates_to_critical(self, exposure: Exposure) -> None:
        service = Service(name="db", environment={"MYSQL_PASSWORD": "changeme"})
        ctx = make_ctx(service, exposures={"db": exposure})
        findings = list(footguns.weak_or_default_secrets(ctx))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_host_only_exposure_stays_high(self) -> None:
        service = Service(name="db", environment={"MYSQL_PASSWORD": "changeme"})
        ctx = make_ctx(service, exposures={"db": Exposure.HOST})
        findings = list(footguns.weak_or_default_secrets(ctx))
        assert findings[0].severity is Severity.HIGH

    def test_externally_provided_value_is_skipped(self) -> None:
        service = Service(name="db", environment={"MYSQL_PASSWORD": "${DB_PASSWORD}"})
        assert list(footguns.weak_or_default_secrets(make_ctx(service))) == []

    def test_strong_value_is_clean(self) -> None:
        service = Service(name="db", environment={"MYSQL_PASSWORD": "x8Fj2kQ9pLm4vRt7"})
        assert list(footguns.weak_or_default_secrets(make_ctx(service))) == []

    def test_non_secret_key_is_ignored(self) -> None:
        service = Service(name="app", environment={"LOG_LEVEL": "changeme"})
        assert list(footguns.weak_or_default_secrets(make_ctx(service))) == []


class TestSensitiveServiceExposed:
    """PC-009 — sensitive application more exposed than the KB recommends."""

    def test_proxy_only_app_on_lan_is_critical(self) -> None:
        service = Service(name="vault", image=ImageRef.parse("vaultwarden/server:1.32"))
        ctx = make_ctx(service, exposures={"vault": Exposure.LAN}, kb=make_kb())
        findings = list(footguns.sensitive_service_exposed(ctx))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-009"
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].service == "vault"

    def test_proxy_only_app_behind_proxy_is_clean(self) -> None:
        # INTERNET means "through the reverse proxy", which is exactly what
        # the proxy-only recommendation describes — not a violation.
        service = Service(name="vault", image=ImageRef.parse("vaultwarden/server:1.32"))
        ctx = make_ctx(service, exposures={"vault": Exposure.INTERNET}, kb=make_kb())
        assert list(footguns.sensitive_service_exposed(ctx)) == []

    @pytest.mark.parametrize("exposure", [Exposure.LAN, Exposure.INTERNET])
    def test_never_app_exposed_is_high(self, exposure: Exposure) -> None:
        service = Service(name="db", image=ImageRef.parse("postgres:16"))
        ctx = make_ctx(service, exposures={"db": exposure}, kb=make_kb())
        findings = list(footguns.sensitive_service_exposed(ctx))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-009"
        assert findings[0].severity is Severity.HIGH
        assert findings[0].service == "db"

    def test_host_only_exposure_is_clean(self) -> None:
        service = Service(name="vault", image=ImageRef.parse("vaultwarden/server:1.32"))
        ctx = make_ctx(service, exposures={"vault": Exposure.HOST}, kb=make_kb())
        assert list(footguns.sensitive_service_exposed(ctx)) == []

    def test_unknown_image_is_clean(self) -> None:
        service = Service(name="blog", image=ImageRef.parse("ghost:5"))
        ctx = make_ctx(service, exposures={"blog": Exposure.LAN}, kb=make_kb())
        assert list(footguns.sensitive_service_exposed(ctx)) == []

    def test_without_kb_is_clean(self) -> None:
        service = Service(name="vault", image=ImageRef.parse("vaultwarden/server:1.32"))
        ctx = make_ctx(service, exposures={"vault": Exposure.LAN}, kb=None)
        assert list(footguns.sensitive_service_exposed(ctx)) == []


class TestDatabasePublished:
    """PC-010 — database port published on the host."""

    def test_published_database_port_is_high(self) -> None:
        service = Service(
            name="db",
            image=ImageRef.parse("postgres:16"),
            ports=[lan_port(container=5432, host=5432)],
        )
        findings = list(footguns.database_published(make_ctx(service, kb=make_kb())))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-010"
        assert findings[0].severity is Severity.HIGH
        assert findings[0].service == "db"

    def test_loopback_only_binding_is_clean(self) -> None:
        service = Service(
            name="db",
            image=ImageRef.parse("postgres:16"),
            ports=[loopback_port(container=5432, host=5432)],
        )
        assert list(footguns.database_published(make_ctx(service, kb=make_kb()))) == []

    def test_no_published_ports_is_clean(self) -> None:
        service = Service(name="db", image=ImageRef.parse("postgres:16"))
        assert list(footguns.database_published(make_ctx(service, kb=make_kb()))) == []

    def test_non_database_category_is_clean(self) -> None:
        service = Service(
            name="vault",
            image=ImageRef.parse("vaultwarden/server:1.32"),
            ports=[lan_port()],
        )
        assert list(footguns.database_published(make_ctx(service, kb=make_kb()))) == []

    def test_without_kb_is_clean(self) -> None:
        service = Service(
            name="db",
            image=ImageRef.parse("postgres:16"),
            ports=[lan_port(container=5432, host=5432)],
        )
        assert list(footguns.database_published(make_ctx(service, kb=None))) == []


class TestServiceBypassesProxy:
    """PC-011 — proxied service also publishing non-loopback ports."""

    def test_proxied_with_published_port_is_medium(self) -> None:
        service = Service(
            name="app",
            labels={"traefik.enable": "true"},
            ports=[lan_port()],
        )
        findings = list(footguns.service_bypasses_proxy(make_ctx(service)))
        assert len(findings) == 1
        assert findings[0].rule_id == "PC-011"
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].service == "app"

    def test_proxied_with_loopback_only_port_is_clean(self) -> None:
        service = Service(
            name="app",
            labels={"traefik.enable": "true"},
            ports=[loopback_port()],
        )
        assert list(footguns.service_bypasses_proxy(make_ctx(service))) == []

    def test_unproxied_with_published_port_is_clean(self) -> None:
        service = Service(name="app", ports=[lan_port()])
        assert list(footguns.service_bypasses_proxy(make_ctx(service))) == []


class TestRunAll:
    def test_bad_service_triggers_multiple_rules(self) -> None:
        bad = Service(
            name="bad",
            image=ImageRef.parse("nginx:latest"),
            privileged=True,
            network_mode="host",
            cap_add=["CAP_SYS_ADMIN"],
            user="root",
            pid="host",
            environment={"ADMIN_PASSWORD": "admin"},
            volumes=[socket_mount()],
        )
        ctx = make_ctx(bad, exposures={"bad": Exposure.LAN})
        findings = run_all(ctx)

        assert {f.rule_id for f in findings} >= {
            "PC-001", "PC-002", "PC-003", "PC-004", "PC-005", "PC-006", "PC-007", "PC-008",
        }
        assert all(f.service == "bad" for f in findings)

        by_rule: dict[str, Finding] = {f.rule_id: f for f in findings}
        assert by_rule["PC-001"].severity is Severity.CRITICAL
        assert by_rule["PC-002"].severity is Severity.CRITICAL
        assert by_rule["PC-004"].severity is Severity.HIGH
        assert by_rule["PC-008"].severity is Severity.CRITICAL  # escalated by LAN exposure

    def test_clean_service_yields_no_findings(self) -> None:
        clean = Service(
            name="clean",
            image=ImageRef.parse("nginx:1.27"),
            user="1000:1000",
            ports=[loopback_port()],
        )
        ctx = make_ctx(clean, exposures={"clean": Exposure.HOST}, kb=make_kb())
        assert run_all(ctx) == []
