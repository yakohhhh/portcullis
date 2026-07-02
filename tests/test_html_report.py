"""Tests for the HTML report (:mod:`portcullis.report.html`).

Focus on the two contracts that matter: the document is self-contained (no
external resource is referenced, so opening it makes no network request), and
untrusted values are escaped.
"""

from __future__ import annotations

import re
from pathlib import Path

from portcullis.model import (
    Exposure,
    Finding,
    ImageRef,
    ScanResult,
    Service,
    Severity,
    Stack,
)
from portcullis.report.html import render_html

#: Resources the browser fetches automatically on load. An ``<a href>`` is
#: NOT one of these (it is only followed when clicked), so it is allowed.
_LOADED_RESOURCE = re.compile(
    r"""(\bsrc\s*=|<link\b|<script\b|<iframe\b|<img\b|@import|url\(\s*['"]?https?:)""",
    re.IGNORECASE,
)


def make_result(findings: list[Finding], *, services: dict[str, Service] | None = None,
                score: int = 60, grade: str = "C") -> ScanResult:
    stack = Stack(root=Path("/home/user/homelab"), services=services or {})
    exposures = {name: Exposure.INTERNET for name in stack.services}
    return ScanResult(stack=stack, exposures=exposures, findings=findings,
                      score=score, grade=grade)


def sample_finding(**overrides) -> Finding:
    base = {
        "rule_id": "PC-008",
        "title": "Weak or default secret in 'db' (POSTGRES_PASSWORD)",
        "severity": Severity.HIGH,
        "description": "The environment variable POSTGRES_PASSWORD is a default value.",
        "risk": "Default credentials are the first thing bots try.",
        "remediation": "Set a long random value and keep it out of Git.",
        "service": "db",
        "exposure": Exposure.LAN,
        "references": ["https://example.com/hardening"],
    }
    base.update(overrides)
    return Finding(**base)


class TestStructure:
    def test_is_a_full_html_document(self) -> None:
        html = render_html(make_result([sample_finding()]))
        assert html.startswith("<!DOCTYPE html>")
        assert "<title>Portcullis security report</title>" in html
        assert "</html>" in html.strip()[-10:]

    def test_contains_grade_and_finding(self) -> None:
        html = render_html(make_result([sample_finding()], grade="C"))
        assert "Portcullis security report" in html
        assert "PC-008" in html
        assert "Why it matters:" in html
        assert "Fix:" in html

    def test_exposure_table_lists_services(self) -> None:
        services = {"web": Service(name="web", image=ImageRef.parse("nginx:1.27"))}
        html = render_html(make_result([], services=services, score=100, grade="A"))
        assert "web" in html
        assert "nginx:1.27" in html
        assert "Service exposure" in html

    def test_no_findings_message(self) -> None:
        html = render_html(make_result([], score=100, grade="A"))
        assert "No findings at or above the requested severity." in html

    def test_min_severity_filters_findings(self) -> None:
        findings = [
            sample_finding(rule_id="PC-005", severity=Severity.LOW, title="mutable tag"),
            sample_finding(rule_id="PC-002", severity=Severity.CRITICAL, title="privileged"),
        ]
        html = render_html(make_result(findings), min_severity=Severity.HIGH)
        assert "PC-002" in html
        assert "PC-005" not in html


class TestSelfContained:
    def test_no_external_resource_is_referenced(self) -> None:
        # A reference URL is present, but only as a clickable link, never as a
        # resource the page loads on open.
        html = render_html(make_result([sample_finding()]))
        assert not _LOADED_RESOURCE.search(html), "found an auto-loaded external resource"

    def test_no_script_tags(self) -> None:
        html = render_html(make_result([sample_finding()]))
        assert "<script" not in html.lower()

    def test_reference_links_are_present_but_inert(self) -> None:
        html = render_html(make_result([sample_finding()]))
        # The reference appears inside an <a href>, which is not fetched on load.
        assert 'href="https://example.com/hardening"' in html


class TestEscaping:
    def test_untrusted_values_are_escaped(self) -> None:
        malicious = "<script>alert('xss')</script>"
        services = {malicious: Service(name=malicious, image=ImageRef.parse("evil:<img>"))}
        finding = sample_finding(
            title="<b>bad</b>", description=malicious, service=malicious
        )
        html = render_html(make_result([finding], services=services))
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html
        assert "&lt;b&gt;bad&lt;/b&gt;" in html
