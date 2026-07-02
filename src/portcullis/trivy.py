"""Optional Trivy integration.

Portcullis deliberately does not reimplement what Trivy already does well
(image CVE scanning, secret detection, Dockerfile analysis). When the
``trivy`` binary is available, it is invoked per unique image and its
results are merged into the report as regular findings. When it is not,
the scan works exactly the same without CVE data - degraded, never broken.

To keep the report readable (precision over noise), CVE results are
aggregated into **one finding per image**, summarising counts and the most
severe identifiers, instead of one finding per CVE.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter

from portcullis.model import Finding, Severity, Stack

TRIVY_TIMEOUT_SECONDS = 600


def is_available() -> bool:
    return shutil.which("trivy") is not None


def scan_stack(stack: Stack) -> list[Finding]:
    """Run ``trivy image`` on every unique image of the stack."""
    findings: list[Finding] = []
    images: dict[str, list[str]] = {}
    for name, service in stack.services.items():
        if service.image is not None:
            images.setdefault(service.image.raw, []).append(name)

    for image, service_names in sorted(images.items()):
        finding = _scan_image(image, service_names)
        if finding is not None:
            findings.append(finding)
    return findings


def _scan_image(image: str, service_names: list[str]) -> Finding | None:
    try:
        completed = subprocess.run(
            [
                "trivy", "image",
                "--quiet",
                "--format", "json",
                "--scanners", "vuln",
                "--severity", "CRITICAL,HIGH",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=TRIVY_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if completed.returncode != 0 or not completed.stdout.strip():
        return None  # image not pullable offline, or trivy failed: stay silent

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None

    vulnerabilities = [
        vuln
        for result in report.get("Results", []) or []
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
