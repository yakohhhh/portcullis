"""Command line interface: ``portcullis scan <path>``."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from portcullis import __version__, history, patches, scanner
from portcullis.discovery import DiscoveryError
from portcullis.model import Severity
from portcullis.parsers.compose import ComposeParseError
from portcullis.report import (
    render_html,
    render_interactive,
    render_json,
    render_markdown,
    render_terminal,
)

_TEXT_RENDERERS = {
    "markdown": render_markdown,
    "html": render_html,
    "json": render_json,
}

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
@click.option("--format", "fmt", type=click.Choice(["terminal", "markdown", "html", "json"]),
              default="terminal", show_default=True, help="Report format.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write the report to a file instead of stdout (markdown/html/json).")
@click.option("--min-severity", type=click.Choice(SEVERITY_CHOICES), default="info",
              show_default=True, help="Hide findings below this severity.")
@click.option("--fail-on", type=click.Choice([*SEVERITY_CHOICES, "never"]), default="never",
              show_default=True,
              help="Exit with code 1 if any finding is at or above this severity "
                   "(for CI pipelines).")
@click.option("--trivy/--no-trivy", "use_trivy", default=None,
              help="Force or disable the Trivy integration (default: use it when "
                   "the binary is installed).")
@click.option("--rules", "rule_packs", multiple=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Directory of community rule packs to load (repeatable).")
@click.option("--suggest-patches", "patch_output", is_flag=False, flag_value="portcullis.patch",
              default=None, type=click.Path(path_type=Path),
              help="Write suggested fixes as a unified diff (default: portcullis.patch). "
                   "Portcullis never applies them - review and `git apply` yourself.")
def scan(path: Path, fmt: str, output: Path | None, min_severity: str,
         fail_on: str, use_trivy: bool | None, rule_packs: tuple[Path, ...],
         patch_output: Path | None) -> None:
    """Scan PATH (a compose file or a directory tree) and print the report."""
    try:
        result = scanner.scan(path, use_trivy=use_trivy, rule_packs=list(rule_packs))
    except (DiscoveryError, ComposeParseError) as exc:
        raise click.ClickException(str(exc)) from exc

    for warning in result.stack.warnings:
        click.echo(f"warning: {warning}", err=True)

    if patch_output is not None:
        _write_patches(result, patch_output)

    threshold = Severity.from_name(min_severity)
    renderer = _TEXT_RENDERERS.get(fmt)
    if renderer is not None:
        text = renderer(result, min_severity=threshold)
        if output:
            output.write_text(text, encoding="utf-8")
            click.echo(f"Report written to {output}")
        else:
            click.echo(text)
    else:
        render_terminal(result, min_severity=threshold)
        if output:
            click.echo("Note: --output is only used with a file format "
                       "(markdown/html/json).", err=True)

    if fail_on != "never" and result.findings:
        gate = Severity.from_name(fail_on)
        if max(f.severity for f in result.findings) >= gate:
            sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--output", "-o", type=click.Path(path_type=Path),
              default=Path("portcullis-report.html"), show_default=True,
              help="Where to write the interactive HTML report.")
@click.option("--min-severity", type=click.Choice(SEVERITY_CHOICES), default="info",
              show_default=True, help="Hide findings below this severity.")
@click.option("--trivy/--no-trivy", "use_trivy", default=None,
              help="Force or disable the Trivy integration.")
@click.option("--rules", "rule_packs", multiple=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Directory of community rule packs to load (repeatable).")
@click.option("--history", "history_file", type=click.Path(path_type=Path),
              default=Path(".portcullis-history.json"), show_default=True,
              help="Local JSON file the score trend is appended to.")
@click.option("--serve", is_flag=True,
              help="Serve the report on localhost instead of only writing it.")
@click.option("--port", type=int, default=8765, show_default=True,
              help="Port for --serve (bound to 127.0.0.1 only).")
def report(path: Path, output: Path, min_severity: str, use_trivy: bool | None,
           rule_packs: tuple[Path, ...], history_file: Path, serve: bool, port: int) -> None:
    """Build an interactive HTML report (filterable findings, exposure graph, score trend)."""
    try:
        result = scanner.scan(path, use_trivy=use_trivy, rule_packs=list(rule_packs))
    except (DiscoveryError, ComposeParseError) as exc:
        raise click.ClickException(str(exc)) from exc

    for warning in result.stack.warnings:
        click.echo(f"warning: {warning}", err=True)

    runs = history.record(history_file, result)
    html = render_interactive(result, min_severity=Severity.from_name(min_severity), history=runs)
    output.write_text(html, encoding="utf-8")
    click.echo(f"Interactive report written to {output}")

    if serve:
        _serve(output, port)


def _serve(report_path: Path, port: int) -> None:
    """Serve the report directory on 127.0.0.1 only, until interrupted."""
    import functools
    import http.server
    import socketserver

    directory = str(report_path.parent.resolve())
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    url = f"http://127.0.0.1:{port}/{report_path.name}"
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        click.echo(f"Serving on {url} (Ctrl-C to stop). Bound to localhost only.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            click.echo("\nStopped.")


def _write_patches(result, patch_output: Path) -> None:
    file_patches = patches.generate_patches(result)
    if not file_patches:
        click.echo("No mechanical fixes to suggest.", err=True)
        return
    header = [
        "# Suggested fixes generated by Portcullis. Review before applying:",
        "#   git apply " + patch_output.name,
        "# Portcullis never edits your files itself.",
        "#",
    ]
    for fp in file_patches:
        for reason in fp.reasons:
            header.append(f"# - {reason}")
    body = "\n".join(header) + "\n" + "".join(fp.diff for fp in file_patches)
    patch_output.write_text(body, encoding="utf-8")
    click.echo(f"Suggested patches written to {patch_output} "
               f"({len(file_patches)} file(s)).", err=True)


if __name__ == "__main__":
    main()
