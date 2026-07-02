"""Machine-readable JSON report.

Consumed by integrations (the GitHub Action, dashboards, scripts), so the
shape is a documented, stable contract rather than a pretty-printing concern.
A ``schema_version`` is emitted from day one: additive changes keep the major,
breaking changes bump it. Enums are serialised by name (``"HIGH"``,
``"INTERNET"``) so consumers never depend on our integer values.

The schema is documented in ``docs/json-schema.md``.
"""

from __future__ import annotations

import json

from portcullis import __version__
from portcullis.model import Exposure, Finding, ScanResult, Service, Severity

#: Bumped only on a breaking change to the JSON shape.
SCHEMA_VERSION = "1.0"


def render_json(result: ScanResult, *, min_severity: Severity = Severity.INFO) -> str:
    return json.dumps(build_document(result, min_severity=min_severity),
                      indent=2, ensure_ascii=False) + "\n"


def build_document(result: ScanResult, *, min_severity: Severity = Severity.INFO) -> dict:
    """Return the JSON report as a plain dict (the serialisable contract)."""
    findings = [f for f in result.findings if f.severity >= min_severity]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "portcullis",
        "tool_version": __version__,
        "scanned_path": str(result.stack.root),
        "score": result.score,
        "grade": result.grade,
        "summary": {
            "services": len(result.stack.services),
            "findings": len(findings),
            "by_severity": _counts_by_severity(findings),
        },
        "services": [
            _service_dict(name, result.stack.services[name], result.exposures.get(name))
            for name in sorted(result.stack.services)
        ],
        "findings": [_finding_dict(f) for f in findings],
    }


def _service_dict(name: str, service: Service, exposure: Exposure | None) -> dict:
    image = service.image.raw if service.image else None
    return {
        "name": name,
        "image": image,
        "build": service.build,
        "exposure": str(exposure) if exposure is not None else str(Exposure.UNKNOWN),
    }


def _finding_dict(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": str(finding.severity),
        "service": finding.service,
        "exposure": str(finding.exposure) if finding.exposure is not None else None,
        "source": finding.source,
        "description": finding.description,
        "risk": finding.risk,
        "remediation": finding.remediation,
        "references": list(finding.references),
    }


def _counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {str(sev): 0 for sev in sorted(Severity, reverse=True)}
    for finding in findings:
        counts[str(finding.severity)] += 1
    return counts
