"""Tests for the command line interface (:mod:`portcullis.cli`).

Runs ``portcullis scan`` end to end through click's CliRunner: exit codes,
the ``--fail-on`` CI gate, both report formats, ``--output`` and the error
paths when there is nothing to scan. Trivy is always disabled so the tests
never depend on (or invoke) an installed binary.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from portcullis.cli import main

CLEAN_COMPOSE = """\
services:
  myapp:
    image: alpine:3.20
"""

PRIVILEGED_COMPOSE = """\
services:
  myapp:
    image: alpine:3.20
    privileged: true
"""


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def write_stack(directory: Path, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "docker-compose.yml").write_text(content, encoding="utf-8")
    return directory


class TestScanExitCodes:
    def test_clean_stack_exits_zero_and_prints_a_grade(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        stack = write_stack(tmp_path / "stack", CLEAN_COMPOSE)
        result = runner.invoke(main, ["scan", str(stack), "--no-trivy"],
                               catch_exceptions=False)
        assert result.exit_code == 0
        # One pinned service without ports has no findings: grade A.
        assert re.search(r"Grade:\s+A\b", result.output)

    def test_fail_on_high_exits_one_for_a_privileged_container(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        stack = write_stack(tmp_path / "stack", PRIVILEGED_COMPOSE)
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--fail-on", "high"],
            catch_exceptions=False,
        )
        assert result.exit_code == 1

    def test_fail_on_never_exits_zero_for_a_privileged_container(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        stack = write_stack(tmp_path / "stack", PRIVILEGED_COMPOSE)
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--fail-on", "never"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "PC-002" in result.output  # the finding is still reported

    def test_fail_on_info_exits_zero_when_there_are_no_findings(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        # The gate fires on findings at or above the level - zero findings
        # must always pass, even at the lowest gate.
        stack = write_stack(tmp_path / "stack", CLEAN_COMPOSE)
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--fail-on", "info"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0


class TestMarkdownFormat:
    def test_markdown_report_on_stdout(self, runner: CliRunner, tmp_path: Path) -> None:
        stack = write_stack(tmp_path / "stack", CLEAN_COMPOSE)
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--format", "markdown"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "# Portcullis security report" in result.output
        assert "myapp" in result.output

    def test_markdown_report_written_to_a_file(self, runner: CliRunner, tmp_path: Path) -> None:
        stack = write_stack(tmp_path / "stack", CLEAN_COMPOSE)
        report = tmp_path / "report.md"
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--format", "markdown", "-o", str(report)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert report.is_file()
        text = report.read_text(encoding="utf-8")
        assert text.startswith("# Portcullis security report")
        assert "myapp" in text
        assert "Report written to" in result.output


class TestHtmlFormat:
    def test_html_report_on_stdout(self, runner: CliRunner, tmp_path: Path) -> None:
        stack = write_stack(tmp_path / "stack", CLEAN_COMPOSE)
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--format", "html"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert result.output.lstrip().startswith("<!DOCTYPE html>")
        assert "Portcullis security report" in result.output
        assert "myapp" in result.output

    def test_html_report_written_to_a_file(self, runner: CliRunner, tmp_path: Path) -> None:
        stack = write_stack(tmp_path / "stack", CLEAN_COMPOSE)
        report = tmp_path / "report.html"
        result = runner.invoke(
            main,
            ["scan", str(stack), "--no-trivy", "--format", "html", "-o", str(report)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert report.is_file()
        text = report.read_text(encoding="utf-8")
        assert text.startswith("<!DOCTYPE html>")
        assert "Report written to" in result.output


class TestScanErrors:
    def test_directory_without_compose_file_fails_cleanly(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(main, ["scan", str(empty), "--no-trivy"],
                               catch_exceptions=False)
        assert result.exit_code != 0
        assert "No docker-compose file found" in result.output
        assert "Traceback" not in result.output

    def test_nonexistent_path_is_a_usage_error(self, runner: CliRunner, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        result = runner.invoke(main, ["scan", str(missing), "--no-trivy"],
                               catch_exceptions=False)
        assert result.exit_code == 2
        assert "does not exist" in result.output
        assert "Traceback" not in result.output
