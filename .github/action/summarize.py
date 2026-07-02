"""Turn a Portcullis JSON report into a GitHub Action summary and outputs.

Reads ``portcullis-report.json`` (the documented ``--format json`` output,
see docs/json-schema.md), writes a markdown report to
``portcullis-report.md``, appends it to the job summary, and exposes the
grade and score as step outputs. It is a plain consumer of the JSON contract,
so it doubles as a worked example of that schema.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_EMOJI = {
    "CRITICAL": "\U0001f7e5",
    "HIGH": "\U0001f7e7",
    "MEDIUM": "\U0001f7e8",
    "LOW": "\U0001f7e6",
    "INFO": "⬜",
}


def _md(doc: dict) -> str:
    lines: list[str] = []
    lines.append(f"## Portcullis security report - grade {doc['grade']}")
    lines.append("")
    summary = doc["summary"]
    counts = summary["by_severity"]
    chips = " ".join(f"{_EMOJI.get(sev, '')} {sev.title()}: {counts[sev]}"
                     for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts.get(sev))
    lines.append(f"**Score {doc['score']}/100** - {summary['services']} services - "
                 f"{summary['findings']} findings")
    if chips:
        lines.append("")
        lines.append(chips)
    lines.append("")

    lines.append("| Service | Image | Exposure |")
    lines.append("| --- | --- | --- |")
    for service in doc["services"]:
        image = service["image"] or ("(build)" if service["build"] else "?")
        lines.append(f"| `{service['name']}` | `{image}` | {service['exposure']} |")
    lines.append("")

    findings = doc["findings"]
    if not findings:
        lines.append("No findings at or above the requested severity. :white_check_mark:")
        return "\n".join(lines) + "\n"

    lines.append("### Findings")
    lines.append("")
    for finding in findings:
        emoji = _EMOJI.get(finding["severity"], "")
        lines.append(f"<details><summary>{emoji} <strong>[{finding['severity']}]</strong> "
                     f"{finding['title']}</summary>")
        lines.append("")
        meta = f"`{finding['rule_id']}`"
        if finding.get("service"):
            meta += f" - service `{finding['service']}`"
        if finding.get("exposure"):
            meta += f" - exposure **{finding['exposure']}**"
        lines.append(meta)
        lines.append("")
        lines.append(finding["description"])
        lines.append("")
        lines.append(f"**Why it matters:** {finding['risk']}")
        lines.append("")
        lines.append(f"**Fix:** {finding['remediation']}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines) + "\n"


def _emit(name: str, env_var: str, value: str) -> None:
    target = os.environ.get(env_var)
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(f"{name}{value}")


def main() -> None:
    doc = json.loads(Path("portcullis-report.json").read_text(encoding="utf-8"))
    markdown = _md(doc)
    Path("portcullis-report.md").write_text(markdown, encoding="utf-8")

    _emit("", "GITHUB_STEP_SUMMARY", markdown)
    _emit("grade=", "GITHUB_OUTPUT", f"{doc['grade']}\n")
    _emit("score=", "GITHUB_OUTPUT", f"{doc['score']}\n")


if __name__ == "__main__":
    main()
