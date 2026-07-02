"""Tests for the GitHub Action summary generator (``.github/action/summarize.py``).

The script is a plain consumer of the ``--format json`` contract. It is loaded
by path (it lives outside the package) and its pure ``_md`` renderer is checked
against a sample document, plus a full ``main()`` run writing to fake
``GITHUB_OUTPUT`` / ``GITHUB_STEP_SUMMARY`` files.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "action" / "summarize.py"


@pytest.fixture(scope="module")
def summarize():
    spec = importlib.util.spec_from_file_location("summarize", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SAMPLE = {
    "schema_version": "1.0",
    "tool": "portcullis",
    "tool_version": "0.1.0",
    "scanned_path": "/home/user/homelab",
    "score": 45,
    "grade": "D",
    "summary": {
        "services": 2,
        "findings": 1,
        "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    },
    "services": [
        {"name": "db", "image": "postgres:16", "build": False, "exposure": "HOST"},
        {"name": "builder", "image": None, "build": True, "exposure": "INTERNAL"},
    ],
    "findings": [
        {
            "rule_id": "PC-008",
            "title": "Weak or default secret in 'db'",
            "severity": "HIGH",
            "service": "db",
            "exposure": "HOST",
            "source": "portcullis",
            "description": "A default value.",
            "risk": "Bots try defaults first.",
            "remediation": "Set a random value.",
            "references": [],
        }
    ],
}


class TestMarkdown:
    def test_header_and_counts(self, summarize) -> None:
        md = summarize._md(SAMPLE)
        assert "grade D" in md
        assert "Score 45/100" in md
        assert "High: 1" in md

    def test_exposure_table_and_build_service(self, summarize) -> None:
        md = summarize._md(SAMPLE)
        assert "`db`" in md and "HOST" in md
        assert "(build)" in md  # image is null -> build placeholder

    def test_findings_are_collapsible(self, summarize) -> None:
        md = summarize._md(SAMPLE)
        assert "<details>" in md
        assert "PC-008" in md
        assert "**Fix:**" in md

    def test_no_findings_message(self, summarize) -> None:
        doc = dict(SAMPLE)
        doc["findings"] = []
        doc["summary"] = {"services": 2, "findings": 0,
                          "by_severity": dict.fromkeys(
                              ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], 0)}
        md = summarize._md(doc)
        assert "No findings" in md
        assert "<details>" not in md


class TestMain:
    def test_writes_report_summary_and_outputs(self, summarize, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "portcullis-report.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
        gh_output = tmp_path / "gh_output"
        gh_summary = tmp_path / "gh_summary"
        monkeypatch.setenv("GITHUB_OUTPUT", str(gh_output))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(gh_summary))

        summarize.main()

        assert (tmp_path / "portcullis-report.md").is_file()
        outputs = gh_output.read_text(encoding="utf-8")
        assert "grade=D" in outputs
        assert "score=45" in outputs
        assert "grade D" in gh_summary.read_text(encoding="utf-8")
