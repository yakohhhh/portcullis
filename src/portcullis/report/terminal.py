"""Colour terminal report, rendered with rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from portcullis.model import Exposure, ScanResult, Severity

GRADE_STYLES = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "E": "red",
    "F": "bold red",
}

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "dark_orange",
    Severity.LOW: "yellow",
    Severity.INFO: "cyan",
}

EXPOSURE_STYLES = {
    Exposure.INTERNET: "bold red",
    Exposure.LAN: "dark_orange",
    Exposure.HOST: "yellow",
    Exposure.INTERNAL: "green",
    Exposure.UNKNOWN: "dim",
}


def render_terminal(result: ScanResult, *, min_severity: Severity = Severity.INFO,
                    console: Console | None = None) -> None:
    console = console or Console()

    grade_style = GRADE_STYLES.get(result.grade, "white")
    header = Text.assemble(
        ("Portcullis", "bold"),
        " — security report for ",
        (str(result.stack.root), "italic"),
        "\nGrade: ",
        (f" {result.grade} ", grade_style),
        f"  (score {result.score}/100, {len(result.stack.services)} services, "
        f"{len(result.findings)} findings)",
    )
    console.print(Panel(header, expand=False))

    _print_exposure_table(result, console)

    findings = [f for f in result.findings if f.severity >= min_severity]
    hidden = len(result.findings) - len(findings)
    if not findings:
        console.print("\n[green]No findings at or above the requested severity. "
                      "Nice stack.[/green]")
    for finding in findings:
        severity_label = Text(f" {finding.severity} ", SEVERITY_STYLES[finding.severity])
        title = Text.assemble(severity_label, " ", (finding.title, "bold"))
        body = Text()
        body.append(finding.description + "\n\n")
        body.append("Why it matters: ", style="bold")
        body.append(finding.risk + "\n\n")
        body.append("Fix: ", style="bold green")
        body.append(finding.remediation)
        if finding.references:
            body.append("\n\nReferences: " + ", ".join(finding.references), style="dim")
        subtitle = f"{finding.rule_id}" + (f" · exposure: {finding.exposure}"
                                           if finding.exposure is not None else "")
        console.print(Panel(body, title=title, subtitle=subtitle, subtitle_align="right",
                            expand=True, border_style=SEVERITY_STYLES[finding.severity]))
    if hidden:
        console.print(f"[dim]{hidden} finding(s) below the severity threshold not shown "
                      f"(use --min-severity info to see everything).[/dim]")


def _print_exposure_table(result: ScanResult, console: Console) -> None:
    table = Table(title="Service exposure", title_style="bold")
    table.add_column("Service")
    table.add_column("Image", overflow="fold")
    table.add_column("Exposure")
    for name in sorted(result.stack.services):
        service = result.stack.services[name]
        exposure = result.exposures.get(name, Exposure.UNKNOWN)
        table.add_row(
            name,
            service.image.raw if service.image else ("(build)" if service.build else "?"),
            Text(str(exposure), style=EXPOSURE_STYLES[exposure]),
        )
    console.print(table)
