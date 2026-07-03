"""Tests for the live reachability probe (:mod:`portcullis.probe`).

The connection function is injected, so nothing here touches the network. The
central property is the safety rail: the probe only ever targets ports the
scanned stack declares.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from portcullis import probe
from portcullis.cli import main
from portcullis.model import Exposure, Finding, ImageRef, PortMapping, Service, Severity, Stack


def service(name: str, *ports: PortMapping) -> Service:
    return Service(name=name, image=ImageRef.parse("app:1"), ports=list(ports))


def stack(*services: Service) -> Stack:
    return Stack(root=Path("/x"), services={s.name: s for s in services})


class TestTargetCollection:
    def test_only_published_ports_are_targeted(self) -> None:
        s = stack(
            service("web", PortMapping(container_port=80, host_port=8080)),
            service("nolisten"),  # no ports -> never targeted
        )
        targets = probe.collect_targets(s, {"web": Exposure.LAN})
        assert len(targets) == 1
        assert targets[0].service == "web"
        assert targets[0].port == 8080
        assert targets[0].host == "127.0.0.1"  # local mode

    def test_ephemeral_ports_skipped(self) -> None:
        s = stack(service("web", PortMapping(container_port=80, host_port=None)))
        assert probe.collect_targets(s, {}) == []

    def test_external_mode_skips_loopback_bound_ports(self) -> None:
        s = stack(
            service("public", PortMapping(container_port=80, host_port=8080)),
            service("localonly", PortMapping(container_port=80, host_port=9000,
                                             host_ip="127.0.0.1")),
        )
        targets = probe.collect_targets(s, {}, external_host="example.com")
        assert [t.service for t in targets] == ["public"]
        assert targets[0].host == "example.com"
        assert targets[0].mode == "external"

    def test_local_mode_probes_loopback_of_loopback_ports(self) -> None:
        s = stack(service("db", PortMapping(container_port=5432, host_port=5432,
                                            host_ip="127.0.0.1")))
        [target] = probe.collect_targets(s, {})
        assert target.host == "127.0.0.1"
        assert target.mode == "local"


class TestRun:
    def test_uses_injected_connect(self) -> None:
        s = stack(service("web", PortMapping(container_port=80, host_port=8080)))
        targets = probe.collect_targets(s, {"web": Exposure.LAN})
        outcomes = probe.run(targets, connect=lambda h, p, t: (True, "open"))
        assert outcomes[0].reachable is True
        assert outcomes[0].detail == "open"

    def test_records_unreachable_detail(self) -> None:
        s = stack(service("web", PortMapping(container_port=80, host_port=8080)))
        targets = probe.collect_targets(s, {"web": Exposure.LAN})
        outcomes = probe.run(targets, connect=lambda h, p, t: (False, "refused"))
        assert outcomes[0].reachable is False
        assert outcomes[0].detail == "refused"


def make_target(mode="external", predicted=Exposure.INTERNET):
    return probe.ProbeTarget("svc", "h", 80, predicted, mode)


class TestVerdicts:
    def test_external_reachable_is_confirmed(self) -> None:
        o = probe.ProbeOutcome(make_target("external"), True, "open")
        assert o.verdict == "CONFIRMED reachable"

    def test_local_reachable_is_listening(self) -> None:
        o = probe.ProbeOutcome(make_target("local"), True, "open")
        assert o.verdict == "listening on the host"

    def test_predicted_but_unreachable_is_flagged(self) -> None:
        o = probe.ProbeOutcome(make_target("external", Exposure.LAN), False, "timeout")
        assert "no answer" in o.verdict

    def test_internal_unreachable_is_quiet(self) -> None:
        o = probe.ProbeOutcome(make_target("local", Exposure.INTERNAL), False, "refused")
        assert o.verdict == "not answering"


class TestAnnotation:
    def _finding(self, service: str) -> Finding:
        return Finding(rule_id="PC-010", title="db exposed", severity=Severity.HIGH,
                       description="", risk="", remediation="", service=service)

    def test_confirmed_service_promotes_finding(self) -> None:
        outcome = probe.ProbeOutcome(make_target("external"), True, "open")
        annotated = probe.annotate_findings([self._finding("svc")], [outcome])
        assert annotated[0][1] == "confirmed reachable by the probe"

    def test_unreachable_service_gets_caveat(self) -> None:
        target = probe.ProbeTarget("svc", "h", 80, Exposure.LAN, "external")
        outcome = probe.ProbeOutcome(target, False, "timeout")
        annotated = probe.annotate_findings([self._finding("svc")], [outcome])
        assert "could not reach" in annotated[0][1]


class TestCli:
    def _stack_dir(self, tmp_path: Path) -> Path:
        d = tmp_path / "stack"
        d.mkdir()
        (d / "docker-compose.yml").write_text(
            'services:\n  web:\n    image: nginx:1.27\n    ports:\n      - "8080:80"\n',
            encoding="utf-8")
        return d

    def test_probe_json_local(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(probe, "tcp_connect", lambda h, p, t: (True, "open"))
        d = self._stack_dir(tmp_path)
        result = CliRunner().invoke(main, ["probe", str(d), "--no-trivy", "--json"],
                                    catch_exceptions=False)
        assert result.exit_code == 0
        doc = json.loads(result.stdout)
        assert doc["results"][0]["service"] == "web"
        assert doc["results"][0]["host"] == "127.0.0.1"
        assert doc["results"][0]["reachable"] is True

    def test_probe_no_ports(self, tmp_path: Path) -> None:
        d = tmp_path / "s"
        d.mkdir()
        (d / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8")
        result = CliRunner().invoke(main, ["probe", str(d), "--no-trivy"],
                                    catch_exceptions=False)
        assert result.exit_code == 0
        assert "No published ports" in result.output

    def test_external_probe_requires_confirmation(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(probe, "tcp_connect", lambda h, p, t: (True, "open"))
        d = self._stack_dir(tmp_path)
        # Declining the consent prompt aborts.
        result = CliRunner().invoke(
            main, ["probe", str(d), "--no-trivy", "--host", "example.com"],
            input="n\n", catch_exceptions=False)
        assert result.exit_code != 0
        assert "Aborted" in result.output
