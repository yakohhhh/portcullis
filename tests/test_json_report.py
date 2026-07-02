"""Tests for the JSON report (:mod:`portcullis.report.json`).

The JSON report is a stable integration contract, so the tests pin the shape,
the by-name enum serialisation, and a full round-trip of every finding field.
"""

from __future__ import annotations

import json
from pathlib import Path

from portcullis import __version__
from portcullis.model import (
    Exposure,
    Finding,
    ImageRef,
    ScanResult,
    Service,
    Severity,
    Stack,
)
from portcullis.report.json import SCHEMA_VERSION, build_document, render_json


def make_result(findings: list[Finding], *, services: dict[str, Service] | None = None,
                score: int = 60, grade: str = "C") -> ScanResult:
    stack = Stack(root=Path("/home/user/homelab"), services=services or {})
    exposures = {name: Exposure.HOST for name in stack.services}
    return ScanResult(stack=stack, exposures=exposures, findings=findings,
                      score=score, grade=grade)


def sample_finding(**overrides) -> Finding:
    base = {
        "rule_id": "PC-008",
        "title": "Weak or default secret in 'db'",
        "severity": Severity.HIGH,
        "description": "A default value.",
        "risk": "Bots try defaults first.",
        "remediation": "Set a random value.",
        "service": "db",
        "exposure": Exposure.LAN,
        "source": "portcullis",
        "references": ["https://example.com/x"],
    }
    base.update(overrides)
    return Finding(**base)


class TestDocument:
    def test_top_level_shape(self) -> None:
        doc = build_document(make_result([sample_finding()]))
        assert doc["schema_version"] == SCHEMA_VERSION
        assert doc["tool"] == "portcullis"
        assert doc["tool_version"] == __version__
        assert doc["scanned_path"] == "/home/user/homelab"
        assert doc["score"] == 60
        assert doc["grade"] == "C"

    def test_summary_counts(self) -> None:
        findings = [
            sample_finding(severity=Severity.HIGH),
            sample_finding(severity=Severity.MEDIUM),
        ]
        doc = build_document(make_result(findings))
        assert doc["summary"]["findings"] == 2
        assert doc["summary"]["by_severity"]["HIGH"] == 1
        assert doc["summary"]["by_severity"]["MEDIUM"] == 1
        assert doc["summary"]["by_severity"]["CRITICAL"] == 0

    def test_services_are_sorted_and_serialised(self) -> None:
        services = {
            "web": Service(name="web", image=ImageRef.parse("nginx:1.27")),
            "builder": Service(name="builder", build=True),
        }
        doc = build_document(make_result([], services=services, score=100, grade="A"))
        names = [s["name"] for s in doc["services"]]
        assert names == ["builder", "web"]  # sorted
        builder = doc["services"][0]
        assert builder["image"] is None
        assert builder["build"] is True


class TestEnumSerialisation:
    def test_severity_and_exposure_serialised_by_name(self) -> None:
        finding = sample_finding(severity=Severity.CRITICAL, exposure=Exposure.INTERNET)
        doc = build_document(make_result([finding]))
        entry = doc["findings"][0]
        assert entry["severity"] == "CRITICAL"
        assert entry["exposure"] == "INTERNET"
        assert doc["services"] == []  # no services in this result

    def test_finding_without_exposure_is_null(self) -> None:
        finding = sample_finding(exposure=None, service=None)
        entry = build_document(make_result([finding]))["findings"][0]
        assert entry["exposure"] is None
        assert entry["service"] is None


class TestRoundTrip:
    def test_every_finding_field_is_present(self) -> None:
        finding = sample_finding()
        entry = build_document(make_result([finding]))["findings"][0]
        assert entry == {
            "rule_id": "PC-008",
            "title": "Weak or default secret in 'db'",
            "severity": "HIGH",
            "service": "db",
            "exposure": "LAN",
            "source": "portcullis",
            "description": "A default value.",
            "risk": "Bots try defaults first.",
            "remediation": "Set a random value.",
            "references": ["https://example.com/x"],
        }

    def test_render_json_is_valid_json(self) -> None:
        text = render_json(make_result([sample_finding()]))
        parsed = json.loads(text)
        assert parsed["grade"] == "C"
        assert parsed["findings"][0]["rule_id"] == "PC-008"

    def test_min_severity_filters_findings_and_summary(self) -> None:
        findings = [
            sample_finding(rule_id="PC-005", severity=Severity.LOW),
            sample_finding(rule_id="PC-002", severity=Severity.CRITICAL),
        ]
        doc = build_document(make_result(findings), min_severity=Severity.HIGH)
        rule_ids = [f["rule_id"] for f in doc["findings"]]
        assert rule_ids == ["PC-002"]
        assert doc["summary"]["findings"] == 1
        # score/grade come from the unfiltered result
        assert doc["score"] == 60
