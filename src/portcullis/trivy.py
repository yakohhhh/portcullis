"""Optional Trivy integration.

Portcullis deliberately does not reimplement what Trivy already does well.
When the ``trivy`` binary is available it is invoked for three things and its
results are merged into the report as regular findings:

* ``trivy image`` - known image vulnerabilities (CVEs), one finding per image;
* ``trivy fs --scanners secret`` - secrets committed in the scanned tree, one
  finding per file;
* ``trivy config`` - Dockerfile misconfigurations, one finding per Dockerfile.

When the binary is missing, or an individual scan fails (an image that cannot
be pulled offline, a parse error), the scan works exactly the same without
that data - degraded, never broken.

Two design choices keep the report readable (precision over noise):

* results are **aggregated per image / file / Dockerfile**, never one finding
  per CVE or per secret occurrence;
* secrets Trivy reports in a file that Portcullis's own PC-008 rule already
  flagged (the compose file or an ``env_file`` of a service with a weak-secret
  finding) are **skipped**, so the same secret is not reported twice - PC-008
  already explains it in plain language.

The JSON parsing lives in pure functions (``_parse_*_report``) so it can be
unit-tested without invoking Trivy or the network.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from portcullis.model import Finding, Severity, Stack

TRIVY_TIMEOUT_SECONDS = 600

_TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def is_available() -> bool:
    return shutil.which("trivy") is not None


def scan_stack(stack: Stack, *, existing_findings: list[Finding] | None = None) -> list[Finding]:
    """Run Trivy's image, secret and Dockerfile scanners and merge the results.

    ``existing_findings`` (the findings Portcullis produced on its own) is used
    to deduplicate secrets against the PC-008 rule.
    """
    findings: list[Finding] = []
    findings.extend(_scan_images(stack))
    findings.extend(_scan_secrets(stack, existing_findings or []))
    findings.extend(_scan_dockerfiles(stack))
    return findings


# ---------------------------------------------------------------------------
# Subprocess


def _run_trivy_json(args: list[str]) -> dict | None:
    try:
        completed = subprocess.run(
            ["trivy", *args],
            capture_output=True,
            text=True,
            timeout=TRIVY_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# Image vulnerabilities


def _scan_images(stack: Stack) -> list[Finding]:
    findings: list[Finding] = []
    images: dict[str, list[str]] = {}
    for name, service in stack.services.items():
        if service.image is not None:
            images.setdefault(service.image.raw, []).append(name)

    for image, service_names in sorted(images.items()):
        data = _run_trivy_json(
            ["image", "--quiet", "--format", "json", "--scanners", "vuln",
             "--severity", "CRITICAL,HIGH", image]
        )
        if data is None:
            continue
        finding = _parse_vuln_report(data, image, service_names)
        if finding is not None:
            findings.append(finding)
    return findings


def _parse_vuln_report(data: dict, image: str, service_names: list[str]) -> Finding | None:
    vulnerabilities = [
        vuln
        for result in data.get("Results", []) or []
        for vuln in result.get("Vulnerabilities", []) or []
    ]
    if not vulnerabilities:
        return None

    counts = Counter(v.get("Severity", "").upper() for v in vulnerabilities)
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    worst_first = sorted(
        vulnerabilities,
        key=lambda v: (v.get("Severity", "").upper() != "CRITICAL", v.get("VulnerabilityID", "")),
    )
    sample = ", ".join(
        v.get("VulnerabilityID", "?") for v in worst_first[:5] if v.get("VulnerabilityID")
    )
    services = ", ".join(f"'{name}'" for name in service_names)

    return Finding(
        rule_id="TRIVY-CVE",
        title=f"{image}: {critical} critical / {high} high CVEs",
        severity=Severity.CRITICAL if critical else Severity.HIGH,
        service=service_names[0] if len(service_names) == 1 else None,
        description=(
            f"Trivy found {critical} critical and {high} high known vulnerabilities "
            f"in the image `{image}` (used by {services}). "
            f"Most severe: {sample}."
        ),
        risk=(
            "Known CVEs have public write-ups and often public exploits; "
            "Internet-facing services running vulnerable images are exploited by "
            "bots within days of disclosure."
        ),
        remediation=(
            "Update the image to a patched tag (`docker compose pull` after pinning "
            "a newer version). Run `trivy image " + image + "` locally for the full "
            "list and check the project's release notes."
        ),
        source="trivy",
    )


# ---------------------------------------------------------------------------
# Secrets committed in files


def _scan_secrets(stack: Stack, existing_findings: list[Finding]) -> list[Finding]:
    data = _run_trivy_json(
        ["fs", "--quiet", "--format", "json", "--scanners", "secret", str(stack.root)]
    )
    if data is None:
        return []
    return _parse_secret_report(data, stack.root, _pc008_covered_files(stack, existing_findings))


def _pc008_covered_files(stack: Stack, existing_findings: list[Finding]) -> set[Path]:
    """Files whose secrets PC-008 already covers (to avoid double-reporting)."""
    flagged = {f.service for f in existing_findings if f.rule_id == "PC-008" and f.service}
    covered: set[Path] = set()
    for name in flagged:
        service = stack.services.get(name)
        if service is None:
            continue
        if service.source_file is not None:
            covered.add(_resolve(service.source_file))
        for env_file in service.env_files:
            covered.add(_resolve(env_file))
    return covered


def _parse_secret_report(data: dict, root: Path, covered_files: set[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        secrets = result.get("Secrets") or []
        if not secrets:
            continue
        target = str(result.get("Target", ""))
        if _resolve(root / target) in covered_files:
            continue  # already reported by PC-008
        severity = _max_severity(s.get("Severity", "") for s in secrets)
        kinds = _unique(s.get("Title") or s.get("RuleID") or "secret" for s in secrets)
        findings.append(
            Finding(
                rule_id="TRIVY-SECRET",
                title=f"{len(secrets)} secret(s) committed in {_display(target, root)}",
                severity=severity,
                description=(
                    f"Trivy detected {len(secrets)} hard-coded secret(s) in "
                    f"`{_display(target, root)}`: {', '.join(kinds)}."
                ),
                risk=(
                    "A secret committed to the repository is exposed to everyone with "
                    "read access, stays in the git history even after deletion, and is "
                    "a prime target for automated credential scanners."
                ),
                remediation=(
                    "Remove the secret from the file and from the git history "
                    "(git filter-repo or BFG), rotate the credential, and load it at "
                    "runtime from an untracked `.env` file or a Docker secret."
                ),
                source="trivy",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Dockerfile misconfigurations


def _scan_dockerfiles(stack: Stack) -> list[Finding]:
    data = _run_trivy_json(
        ["config", "--quiet", "--format", "json",
         "--severity", "CRITICAL,HIGH,MEDIUM", str(stack.root)]
    )
    if data is None:
        return []
    return _parse_dockerfile_report(data, stack.root)


def _parse_dockerfile_report(data: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        if str(result.get("Type", "")).lower() != "dockerfile":
            continue  # only Dockerfiles: compose/k8s misconfig is Portcullis's own job
        misconfigs = result.get("Misconfigurations") or []
        if not misconfigs:
            continue
        target = str(result.get("Target", ""))
        severity = _max_severity(m.get("Severity", "") for m in misconfigs)
        ids = _unique(m.get("ID") or m.get("AVDID") or "" for m in misconfigs)
        titles = _unique(m.get("Title") or "" for m in misconfigs)
        findings.append(
            Finding(
                rule_id="TRIVY-DOCKERFILE",
                title=f"{_display(target, root)}: {len(misconfigs)} Dockerfile issue(s)",
                severity=severity,
                description=(
                    f"Trivy found {len(misconfigs)} misconfiguration(s) in the Dockerfile "
                    f"`{_display(target, root)}` ({', '.join(i for i in ids if i)}): "
                    f"{'; '.join(t for t in titles if t)}."
                ),
                risk=(
                    "Dockerfile weaknesses - running as root, an unpinned base image, "
                    "secrets baked into layers - weaken every container built from it and "
                    "widen the blast radius of any later compromise."
                ),
                remediation=(
                    "Fix the flagged instructions (add a non-root `USER`, pin the base "
                    "image by tag or digest, use build secrets). Run "
                    f"`trivy config {_display(target, root)}` for line-level guidance."
                ),
                source="trivy",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Helpers


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:  # pragma: no cover - resolve rarely raises for plain paths
        return path


def _display(target: str, root: Path) -> str:
    """A short, repo-relative display path for a Trivy target."""
    if not target:
        return "(unknown)"
    candidate = Path(target)
    try:
        absolute = candidate if candidate.is_absolute() else root / candidate
        return str(absolute.resolve().relative_to(root.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        return target.replace("\\", "/")


def _max_severity(names) -> Severity:
    return max((_TRIVY_SEVERITY.get(str(n).upper(), Severity.INFO) for n in names),
               default=Severity.INFO)


def _unique(values) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen[text] = None
    return list(seen)
