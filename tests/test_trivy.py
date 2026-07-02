"""Tests for the Trivy integration (:mod:`portcullis.trivy`).

The JSON parsing is exercised through pure functions with sample Trivy output
- no subprocess, no network, no Trivy binary required in CI. A couple of
orchestration tests monkeypatch the subprocess boundary to prove graceful
degradation and PC-008 deduplication.
"""

from __future__ import annotations

from pathlib import Path

from portcullis import trivy
from portcullis.model import Finding, ImageRef, Service, Severity, Stack


class TestVulnReport:
    REPORT = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2023-0001", "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-2023-0002", "Severity": "HIGH"},
                    {"VulnerabilityID": "CVE-2023-0003", "Severity": "HIGH"},
                ]
            }
        ]
    }

    def test_aggregates_to_one_finding_with_counts(self) -> None:
        finding = trivy._parse_vuln_report(self.REPORT, "nginx:1.20", ["web"])
        assert finding is not None
        assert finding.rule_id == "TRIVY-CVE"
        assert finding.severity == Severity.CRITICAL  # a critical is present
        assert "1 critical and 2 high" in finding.description
        assert finding.service == "web"
        assert finding.source == "trivy"

    def test_high_only_is_high_severity(self) -> None:
        report = {
            "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-x", "Severity": "HIGH"}]}]
        }
        finding = trivy._parse_vuln_report(report, "img", ["a", "b"])
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.service is None  # multiple services -> no single owner

    def test_no_vulnerabilities_yields_nothing(self) -> None:
        assert trivy._parse_vuln_report({"Results": []}, "img", ["web"]) is None


class TestSecretReport:
    REPORT = {
        "Results": [
            {
                "Target": "stack/.env",
                "Secrets": [
                    {"RuleID": "aws-access-key-id", "Title": "AWS Access Key ID",
                     "Severity": "CRITICAL", "StartLine": 3},
                    {"RuleID": "generic-api-key", "Title": "Generic API Key",
                     "Severity": "HIGH", "StartLine": 5},
                ],
            }
        ]
    }

    def test_one_finding_per_file_with_max_severity(self) -> None:
        findings = trivy._parse_secret_report(self.REPORT, Path("/repo"), set())
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "TRIVY-SECRET"
        assert finding.severity == Severity.CRITICAL
        assert "2 secret(s)" in finding.title
        assert "stack/.env" in finding.title
        assert "AWS Access Key ID" in finding.description

    def test_file_covered_by_pc008_is_skipped(self) -> None:
        covered = {(Path("/repo") / "stack/.env").resolve()}
        findings = trivy._parse_secret_report(self.REPORT, Path("/repo"), covered)
        assert findings == []

    def test_result_without_secrets_is_ignored(self) -> None:
        report = {"Results": [{"Target": "compose.yml", "Secrets": []}]}
        assert trivy._parse_secret_report(report, Path("/repo"), set()) == []


class TestDockerfileReport:
    REPORT = {
        "Results": [
            {
                "Target": "app/Dockerfile",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {"ID": "DS002", "Title": "Image user should not be root", "Severity": "HIGH"},
                    {"ID": "DS026", "Title": "No HEALTHCHECK defined", "Severity": "LOW"},
                ],
            },
            {
                "Target": "docker-compose.yml",
                "Type": "docker-compose",
                "Misconfigurations": [
                    {"ID": "XXX", "Title": "compose thing", "Severity": "HIGH"}
                ],
            },
        ]
    }

    def test_only_dockerfiles_are_reported(self) -> None:
        findings = trivy._parse_dockerfile_report(self.REPORT, Path("/repo"))
        assert len(findings) == 1  # the docker-compose result is ignored
        finding = findings[0]
        assert finding.rule_id == "TRIVY-DOCKERFILE"
        assert finding.severity == Severity.HIGH
        assert "DS002" in finding.description
        assert "app/Dockerfile" in finding.title

    def test_no_misconfigurations_yields_nothing(self) -> None:
        report = {"Results": [{"Target": "Dockerfile", "Type": "dockerfile",
                               "Misconfigurations": []}]}
        assert trivy._parse_dockerfile_report(report, Path("/repo")) == []


class TestDedupHelper:
    def test_pc008_covered_files_collects_compose_and_env_files(self, tmp_path: Path) -> None:
        compose = tmp_path / "docker-compose.yml"
        env_file = tmp_path / "db.env"
        service = Service(name="db", image=ImageRef.parse("postgres:16"),
                          source_file=compose, env_files=[env_file])
        stack = Stack(root=tmp_path, services={"db": service})
        pc008 = Finding(rule_id="PC-008", title="weak secret", severity=Severity.HIGH,
                        description="", risk="", remediation="", service="db")
        covered = trivy._pc008_covered_files(stack, [pc008])
        assert compose.resolve() in covered
        assert env_file.resolve() in covered

    def test_unrelated_findings_do_not_cover_files(self, tmp_path: Path) -> None:
        service = Service(name="db", image=ImageRef.parse("postgres:16"),
                          source_file=tmp_path / "compose.yml")
        stack = Stack(root=tmp_path, services={"db": service})
        other = Finding(rule_id="PC-001", title="socket", severity=Severity.CRITICAL,
                        description="", risk="", remediation="", service="db")
        assert trivy._pc008_covered_files(stack, [other]) == set()


class TestOrchestration:
    def test_scan_stack_degrades_when_trivy_unavailable(self, monkeypatch, tmp_path: Path) -> None:
        # Every trivy invocation returns None (binary missing / failed).
        monkeypatch.setattr(trivy, "_run_trivy_json", lambda args: None)
        stack = Stack(root=tmp_path,
                      services={"web": Service(name="web", image=ImageRef.parse("nginx:1.27"))})
        assert trivy.scan_stack(stack) == []

    def test_scan_stack_merges_all_three_scanners(self, monkeypatch, tmp_path: Path) -> None:
        def fake_run(args: list[str]):
            if args[0] == "image":
                return TestVulnReport.REPORT
            if args[0] == "fs":
                return {"Results": [{"Target": "x.env",
                                     "Secrets": [{"RuleID": "k", "Severity": "HIGH"}]}]}
            if args[0] == "config":
                return TestDockerfileReport.REPORT
            return None

        monkeypatch.setattr(trivy, "_run_trivy_json", fake_run)
        stack = Stack(root=tmp_path,
                      services={"web": Service(name="web", image=ImageRef.parse("nginx:1.27"))})
        findings = trivy.scan_stack(stack)
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"TRIVY-CVE", "TRIVY-SECRET", "TRIVY-DOCKERFILE"}
        assert all(f.source == "trivy" for f in findings)
