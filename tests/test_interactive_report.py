"""Tests for the interactive report and score history (#14)."""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from portcullis import history
from portcullis.cli import main
from portcullis.model import (
    Exposure,
    Finding,
    ImageRef,
    RoutingTable,
    ScanResult,
    Service,
    Severity,
    Stack,
)
from portcullis.report.interactive import render_interactive

_LOADED_RESOURCE = re.compile(
    r"""(\bsrc\s*=|<link\b|<iframe\b|<img\b|@import|url\(\s*['"]?https?:|fetch\(|XMLHttpRequest)""",
    re.IGNORECASE,
)


def make_result(findings, *, services=None, routing=None, score=60, grade="C") -> ScanResult:
    stack = Stack(root=Path("/home/user/homelab"), services=services or {})
    exposures = {name: Exposure.INTERNET for name in stack.services}
    return ScanResult(stack=stack, exposures=exposures, findings=findings,
                      score=score, grade=grade, routing=routing or RoutingTable())


def finding(**kw) -> Finding:
    base = dict(rule_id="PC-008", title="Weak secret in 'db'", severity=Severity.HIGH,
                description="d", risk="r", remediation="fix", service="db",
                exposure=Exposure.LAN, references=[])
    base.update(kw)
    return Finding(**base)


class TestRender:
    def test_full_document_with_filters_and_findings(self) -> None:
        html = render_interactive(make_result([finding()]))
        assert html.startswith("<!DOCTYPE html>")
        assert "Exposure graph" in html
        assert 'id="search"' in html
        assert 'class="finding"' in html
        assert "PC-008" in html

    def test_self_contained_no_external_or_network(self) -> None:
        html = render_interactive(make_result([finding(references=["https://example.com/x"])]))
        assert not _LOADED_RESOURCE.search(html), "found an external/network resource"
        # the reference is an inert <a href>, which is allowed
        assert 'href="https://example.com/x"' in html

    def test_graph_marks_proxy_and_columns(self) -> None:
        services = {
            "traefik": Service(name="traefik", image=ImageRef.parse("traefik:v3")),
            "app": Service(name="app", image=ImageRef.parse("nginx:1.27")),
        }
        routing = RoutingTable(internet_routed={"app"}, proxy_services={"traefik"})
        html = render_interactive(make_result([], services=services, routing=routing))
        assert "traefik" in html and "app" in html
        assert "INTERNET" in html and "INTERNAL" in html
        assert "<line" in html  # an edge from the proxy to the routed service

    def test_escaping(self) -> None:
        html = render_interactive(make_result([finding(title="<script>alert(1)</script>")]))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_min_severity_filters(self) -> None:
        findings = [finding(rule_id="PC-005", severity=Severity.LOW),
                    finding(rule_id="PC-002", severity=Severity.CRITICAL)]
        html = render_interactive(make_result(findings), min_severity=Severity.HIGH)
        assert "PC-002" in html
        assert 'data-rule="PC-005"' not in html

    def test_sparkline_appears_with_history(self) -> None:
        runs = [history.Run("2026-01-01T00:00:00", 40, "E", 6, 3),
                history.Run("2026-01-02T00:00:00", 70, "B", 2, 3)]
        html = render_interactive(make_result([finding()]), history=runs)
        assert "<polyline" in html
        assert "2 runs" in html


class TestHistory:
    def test_record_appends_and_persists(self, tmp_path: Path) -> None:
        hist = tmp_path / "h.json"
        r1 = history.record(hist, make_result([finding()], score=50, grade="D"),
                            timestamp="2026-01-01T00:00:00")
        assert len(r1) == 1 and r1[0].score == 50
        r2 = history.record(hist, make_result([], score=100, grade="A"),
                            timestamp="2026-01-02T00:00:00")
        assert [r.score for r in r2] == [50, 100]
        # persisted and reloadable
        assert [r.score for r in history.load(hist)] == [50, 100]

    def test_load_missing_file_is_empty(self, tmp_path: Path) -> None:
        assert history.load(tmp_path / "nope.json") == []

    def test_corrupt_history_is_ignored(self, tmp_path: Path) -> None:
        bad = tmp_path / "h.json"
        bad.write_text("{ not json", encoding="utf-8")
        assert history.load(bad) == []
        # recording still works, replacing the corrupt content
        runs = history.record(bad, make_result([], score=90, grade="A"),
                              timestamp="2026-01-01T00:00:00")
        assert len(runs) == 1


class TestReportCommand:
    def test_report_writes_html_and_history(self, tmp_path: Path) -> None:
        stack = tmp_path / "stack"
        stack.mkdir()
        (stack / "docker-compose.yml").write_text(
            "services:\n  app:\n    image: nginx:1.27\n", encoding="utf-8")
        out = tmp_path / "r.html"
        hist = tmp_path / "h.json"
        result = CliRunner().invoke(
            main,
            ["report", str(stack), "--no-trivy", "-o", str(out), "--history", str(hist)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert out.is_file()
        assert out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
        assert hist.is_file()
        assert len(history.load(hist)) == 1
