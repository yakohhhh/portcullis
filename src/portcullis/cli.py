"""Command line interface: ``portcullis scan <path>``."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from portcullis import __version__, scanner
from portcullis.discovery import DiscoveryError
from portcullis.model import Severity
from portcullis.parsers.compose import ComposeParseError
from portcullis.report import render_html, render_markdown, render_terminal

SEVERITY_CHOICES = [s.name.lower() for s in sorted(Severity, reverse=True)]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="portcullis")
def main() -> None:
    """Portcullis - security auditor for self-hosted infrastructures.

    Reads your docker-compose files (and soon your reverse proxy
    configuration), reports what is actually exposed to the Internet, what
    is dangerous, and how to fix it. 100% local: nothing leaves your machine.
    """


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--format", "fmt", type=click.Choice(["terminal", "markdown", "html"]),
              default="terminal", show_default=True, help="Report format.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write the report to a file instead of stdout (markdown/html).")
@click.option("--min-severity", type=click.Choice(SEVERITY_CHOICES), default="info",
              show_default=True, help="Hide findings below this severity.")
@click.option("--fail-on", type=click.Choice([*SEVERITY_CHOICES, "never"]), default="never",
              show_default=True,
              help="Exit with code 1 if any finding is at or above this severity "
                   "(for CI pipelines).")
@click.option("--trivy/--no-trivy", "use_trivy", default=None,
              help="Force or disable the Trivy integration (default: use it when "
                   "the binary is installed).")
def scan(path: Path, fmt: str, output: Path | None, min_severity: str,
         fail_on: str, use_trivy: bool | None) -> None:
    """Scan PATH (a compose file or a directory tree) and print the report."""
    try:
        result = scanner.scan(path, use_trivy=use_trivy)
    except (DiscoveryError, ComposeParseError) as exc:
        raise click.ClickException(str(exc)) from exc

    for warning in result.stack.warnings:
        click.echo(f"warning: {warning}", err=True)

    threshold = Severity.from_name(min_severity)
    if fmt in ("markdown", "html"):
        renderer = render_markdown if fmt == "markdown" else render_html
        text = renderer(result, min_severity=threshold)
        if output:
            output.write_text(text, encoding="utf-8")
            click.echo(f"Report written to {output}")
        else:
            click.echo(text)
    else:
        render_terminal(result, min_severity=threshold)
        if output:
            click.echo("Note: --output is only used with --format markdown or html.", err=True)

    if fail_on != "never" and result.findings:
        gate = Severity.from_name(fail_on)
        if max(f.severity for f in result.findings) >= gate:
            sys.exit(1)


if __name__ == "__main__":
    main()
