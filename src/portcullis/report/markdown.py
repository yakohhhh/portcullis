"""Markdown report, suitable for CI artifacts and pull-request comments."""

from __future__ import annotations

from portcullis.model import Exposure, ScanResult, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


def render_markdown(result: ScanResult, *, min_severity: Severity = Severity.INFO) -> str:
    lines: list[str] = []
    lines.append("# Portcullis security report")
    lines.append("")
    lines.append(f"**Grade: {result.grade}** — score {result.score}/100 · "
                 f"{len(result.stack.services)} services · {len(result.findings)} findings")
    lines.append("")
    lines.append(f"Scanned path: `{result.stack.root}`")
    lines.append("")

    lines.append("## Service exposure")
    lines.append("")
    lines.append("| Service | Image | Exposure |")
    lines.append("| --- | --- | --- |")
    for name in sorted(result.stack.services):
        service = result.stack.services[name]
        image = service.image.raw if service.image else ("(build)" if service.build else "?")
        exposure = result.exposures.get(name, Exposure.UNKNOWN)
        lines.append(f"| `{name}` | `{image}` | {exposure} |")
    lines.append("")

    findings = [f for f in result.findings if f.severity >= min_severity]
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings at or above the requested severity.")
    for finding in findings:
        emoji = SEVERITY_EMOJI[finding.severity]
        lines.append(f"### {emoji} [{finding.severity}] {finding.title}")
        lines.append("")
        meta = f"`{finding.rule_id}`"
        if finding.service:
            meta += f" · service `{finding.service}`"
        if finding.exposure is not None:
            meta += f" · exposure **{finding.exposure}**"
        lines.append(meta)
        lines.append("")
        lines.append(finding.description)
        lines.append("")
        lines.append(f"**Why it matters:** {finding.risk}")
        lines.append("")
        lines.append(f"**Fix:** {finding.remediation}")
        if finding.references:
            lines.append("")
            lines.append("References: " + ", ".join(f"<{ref}>" for ref in finding.references))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
