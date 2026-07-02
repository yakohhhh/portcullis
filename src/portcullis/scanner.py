"""Scan orchestration: the pipeline behind ``portcullis scan``.

1. Discover configuration files (compose files and their overrides).
2. Parse them into the service graph (:class:`~portcullis.model.Stack`).
3. Classify exposure, run the rules, enrich with the knowledge base and -
   when available and enabled - with Trivy.
4. Aggregate, score and prioritise.

Reporters then render the returned :class:`~portcullis.model.ScanResult`.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from portcullis import exposure as exposure_engine
from portcullis import scoring, trivy
from portcullis.discovery import (
    find_caddy_configs,
    find_compose_groups,
    find_traefik_configs,
)
from portcullis.kb import KnowledgeBase
from portcullis.model import RoutingTable, ScanResult, Stack
from portcullis.parsers import caddy, traefik
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

    routing = _build_routing(path, stack)
    exposures = exposure_engine.classify(stack, routing)
    kb = KnowledgeBase.load_default()
    context = RuleContext(stack=stack, exposures=exposures, kb=kb, routing=routing)
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


def _build_routing(path: Path, stack: Stack) -> RoutingTable:
    """Discover and parse reverse-proxy file configuration into a routing table.

    Defensive by design: reverse-proxy configuration is untrusted input, so a
    parsing problem degrades the exposure analysis rather than failing the
    scan.
    """
    routing = RoutingTable()
    with contextlib.suppress(OSError):
        routing.merge(traefik.analyze(stack, find_traefik_configs(path)))
    with contextlib.suppress(OSError):
        routing.merge(caddy.analyze(stack, find_caddy_configs(path)))
    return routing
