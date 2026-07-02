"""Scoring: turn a list of findings into a 0-100 score and an A-F grade.

The score starts at 100 and each finding subtracts a weight based on its
severity. The mapping is deliberately simple and documented so users can
understand - and challenge - their grade.
"""

from __future__ import annotations

from portcullis.model import Exposure, Finding, Severity

#: Points subtracted from the score per finding, by severity.
WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

#: Minimum score (inclusive) for each grade, from best to worst.
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (45, "D"),
    (30, "E"),
    (0, "F"),
]


def score(findings: list[Finding]) -> int:
    penalty = sum(WEIGHTS[finding.severity] for finding in findings)
    return max(0, 100 - penalty)


def grade(value: int) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if value >= threshold:
            return letter
    return "F"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings the way the report presents them.

    Most severe first; at equal severity, the most exposed service first
    (a problem on an Internet-facing service matters more than the same
    problem on an internal one).
    """
    return sorted(
        findings,
        key=lambda f: (f.severity, f.exposure if f.exposure is not None else Exposure.UNKNOWN),
        reverse=True,
    )
