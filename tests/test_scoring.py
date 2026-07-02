"""Tests for scoring (:mod:`portcullis.scoring`).

Covers the documented severity weights, the 0 floor, every grade threshold
boundary and the report ordering of findings.
"""

from __future__ import annotations

import pytest

from portcullis.model import Exposure, Finding, Severity
from portcullis.scoring import WEIGHTS, grade, score, sort_findings


def make_finding(
    severity: Severity,
    exposure: Exposure | None = None,
    rule_id: str = "PC-000",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="stub",
        severity=severity,
        description="stub",
        risk="stub",
        remediation="stub",
        service="app",
        exposure=exposure,
    )


class TestScore:
    def test_no_findings_scores_100(self) -> None:
        assert score([]) == 100

    def test_documented_weights(self) -> None:
        assert WEIGHTS[Severity.CRITICAL] == 25
        assert WEIGHTS[Severity.HIGH] == 10
        assert WEIGHTS[Severity.MEDIUM] == 4
        assert WEIGHTS[Severity.LOW] == 1
        assert WEIGHTS[Severity.INFO] == 0

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (Severity.CRITICAL, 75),
            (Severity.HIGH, 90),
            (Severity.MEDIUM, 96),
            (Severity.LOW, 99),
            (Severity.INFO, 100),
        ],
    )
    def test_single_finding_subtracts_its_weight(
        self, severity: Severity, expected: int
    ) -> None:
        assert score([make_finding(severity)]) == expected

    def test_penalties_accumulate(self) -> None:
        findings = [
            make_finding(Severity.CRITICAL),
            make_finding(Severity.HIGH),
            make_finding(Severity.MEDIUM),
            make_finding(Severity.LOW),
            make_finding(Severity.INFO),
        ]
        assert score(findings) == 100 - 25 - 10 - 4 - 1 - 0

    def test_score_floors_at_zero(self) -> None:
        findings = [make_finding(Severity.CRITICAL) for _ in range(5)]  # 125 points of penalty
        assert score(findings) == 0


class TestGrade:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (100, "A"),
            (90, "A"),
            (89, "B"),
            (75, "B"),
            (74, "C"),
            (60, "C"),
            (59, "D"),
            (45, "D"),
            (44, "E"),
            (30, "E"),
            (29, "F"),
            (0, "F"),
        ],
    )
    def test_grade_threshold_boundaries(self, value: int, expected: str) -> None:
        assert grade(value) == expected


class TestSortFindings:
    def test_orders_by_severity_descending(self) -> None:
        findings = [
            make_finding(Severity.LOW),
            make_finding(Severity.CRITICAL),
            make_finding(Severity.MEDIUM),
            make_finding(Severity.HIGH),
        ]
        assert [f.severity for f in sort_findings(findings)] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

    def test_orders_by_exposure_descending_within_severity(self) -> None:
        findings = [
            make_finding(Severity.HIGH, Exposure.INTERNAL),
            make_finding(Severity.HIGH, Exposure.INTERNET),
            make_finding(Severity.HIGH, Exposure.LAN),
            make_finding(Severity.HIGH, Exposure.HOST),
        ]
        assert [f.exposure for f in sort_findings(findings)] == [
            Exposure.INTERNET,
            Exposure.LAN,
            Exposure.HOST,
            Exposure.INTERNAL,
        ]

    def test_none_exposure_sorts_last_within_severity(self) -> None:
        findings = [
            make_finding(Severity.HIGH, None),
            make_finding(Severity.HIGH, Exposure.INTERNAL),
            make_finding(Severity.HIGH, Exposure.INTERNET),
        ]
        assert [f.exposure for f in sort_findings(findings)] == [
            Exposure.INTERNET,
            Exposure.INTERNAL,
            None,
        ]

    def test_severity_takes_precedence_over_exposure(self) -> None:
        low_internet = make_finding(Severity.LOW, Exposure.INTERNET)
        high_unset = make_finding(Severity.HIGH, None)
        result = sort_findings([low_internet, high_unset])
        assert [(f.severity, f.exposure) for f in result] == [
            (Severity.HIGH, None),
            (Severity.LOW, Exposure.INTERNET),
        ]

    def test_input_list_is_not_mutated(self) -> None:
        findings = [
            make_finding(Severity.LOW),
            make_finding(Severity.CRITICAL),
        ]
        sort_findings(findings)
        assert [f.severity for f in findings] == [Severity.LOW, Severity.CRITICAL]
