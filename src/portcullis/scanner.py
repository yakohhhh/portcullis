"""Scan orchestration: the pipeline behind ``portcullis scan``.

1. Discover configuration files (compose files and their overrides).
2. Parse them into the service graph (:class:`~portcullis.model.Stack`).
3. Classify exposure, run the rules, enrich with the knowledge base and -
   when available and enabled - with Trivy.
4. Aggregate, score and prioritise.

Reporters then render the returned :class:`~portcullis.model.ScanResult`.
"""

from __future__ import annotations

from pathlib import Path

from portcullis import exposure as exposure_engine
from portcullis import scoring, trivy
from portcullis.discovery import find_compose_groups
from portcullis.kb import KnowledgeBase
from portcullis.model import ScanResult
from portcullis.parsers.compose import parse_compose_groups
from portcullis.rules import RuleContext, run_all


def scan(path: Path, *, use_trivy: bool | None = None) -> ScanResult:
    """Scan ``path`` (a compose file or a directory tree) and return the result.

    ``use_trivy``: ``True`` forces Trivy (error if missing is silently
    degraded), ``False`` disables it, ``None`` auto-detects the binary.
    """
    root = path.resolve() if path.is_dir() else path.resolve().parent
    groups = find_compose_groups(path)
    stack = parse_compose_groups(groups, root)

    exposures = exposure_engine.classify(stack)
    kb = KnowledgeBase.load_default()
    context = RuleContext(stack=stack, exposures=exposures, kb=kb)
    findings = run_all(context)

    if use_trivy is None:
        use_trivy = trivy.is_available()
    if use_trivy and trivy.is_available():
        findings.extend(trivy.scan_stack(stack))

    findings = scoring.sort_findings(findings)
    total = scoring.score(findings)
    return ScanResult(
        stack=stack,
        exposures=exposures,
        findings=findings,
        score=total,
        grade=scoring.grade(total),
    )
