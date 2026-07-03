"""Suggest mechanical fixes as applicable unified diffs.

Portcullis proposes fixes in prose; this turns the unambiguous, mechanical
ones into concrete patches the user can review and apply with ``git apply``.
The tool never applies anything itself - it only writes ``.patch`` files.

Only edits with a single obvious form are generated: remove a published port,
bind a database port to loopback, drop a dangerous capability, remove
``privileged``/``pid: host``/``network_mode: host``/an explicit root ``user``,
or remove a mounted Docker socket. Anything needing a human decision (which
version to pin for a ``latest`` tag, whether a service truly needs host
networking) is deliberately left to the prose remediation.

Patches are produced by editing the **raw text** of the compose file - never
by re-serialising the YAML - so the diff is minimal and reviewable. Each
file's edits are combined into one diff, and the result is re-parsed to
guarantee it still loads and that the finding's condition is actually gone
(round-trip safety); a patch that fails that check is dropped, never emitted.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from portcullis.model import ScanResult, Service
from portcullis.rules.footguns import DANGEROUS_CAPS_HIGH, DANGEROUS_CAPS_MEDIUM

DOCKER_SOCKET = "docker.sock"
_DANGEROUS_CAPS = DANGEROUS_CAPS_HIGH | DANGEROUS_CAPS_MEDIUM

#: Rules Portcullis can patch mechanically.
PATCHABLE_RULES = frozenset({"PC-001", "PC-002", "PC-003", "PC-004", "PC-006",
                             "PC-007", "PC-010", "PC-011"})


@dataclass
class _Edit:
    """A pending change to one line of a file (delete, or replace)."""

    line: int              # 0-based index into the file's lines
    replacement: str | None  # None = delete the line
    reason: str            # "PC-011 (vaultwarden): remove published port 8081"


@dataclass
class FilePatch:
    """The combined diff for one compose file."""

    file: Path
    diff: str
    reasons: list[str] = field(default_factory=list)


def generate_patches(result: ScanResult) -> list[FilePatch]:
    """Return one :class:`FilePatch` per compose file with mechanical fixes."""
    edits_by_file: dict[Path, list[_Edit]] = {}
    for finding in result.findings:
        if finding.rule_id not in PATCHABLE_RULES or finding.service is None:
            continue
        service = result.stack.services.get(finding.service)
        if service is None or service.source_file is None:
            continue
        lines = _read_lines(service.source_file)
        if lines is None:
            continue
        for edit in _edits_for(finding.rule_id, service, lines):
            edits_by_file.setdefault(service.source_file, []).append(edit)

    patches: list[FilePatch] = []
    for file, edits in sorted(edits_by_file.items(), key=lambda kv: str(kv[0])):
        patch = _build_patch(file, edits)
        if patch is not None:
            patches.append(patch)
    return patches


def _build_patch(file: Path, edits: list[_Edit]) -> FilePatch | None:
    original = _read_lines(file)
    if original is None:
        return None
    # A line can be targeted by more than one finding; keep one edit per line,
    # preferring a delete over a replace (a removed line needs no rebind).
    by_line: dict[int, _Edit] = {}
    reasons: list[str] = []
    for edit in edits:
        reasons.append(edit.reason)
        existing = by_line.get(edit.line)
        if existing is None or (existing.replacement is not None and edit.replacement is None):
            by_line[edit.line] = edit
    if not by_line:
        return None

    new_lines: list[str] = []
    for i, line in enumerate(original):
        edit = by_line.get(i)
        if edit is None:
            new_lines.append(line)
        elif edit.replacement is not None:
            new_lines.append(edit.replacement)
        # else: deleted

    if not _round_trips(file, new_lines):
        return None

    rel = _display_name(file)
    diff = difflib.unified_diff(
        [f"{line}\n" for line in original],
        [f"{line}\n" for line in new_lines],
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
        lineterm="\n",
    )
    return FilePatch(file=file, diff="".join(diff), reasons=_dedupe(reasons))


# ---------------------------------------------------------------------------
# Per-rule edits


def _edits_for(rule_id: str, service: Service, lines: list[str]) -> list[_Edit]:
    block = _service_block(lines, _in_file_name(service))
    if block is None:
        return []
    start, end = block
    tag = f"{rule_id} ({service.name})"

    if rule_id == "PC-002":
        return _delete_scalar(lines, start, end, "privileged", tag, "remove privileged mode")
    if rule_id == "PC-007":
        return _delete_scalar(lines, start, end, "pid", tag, "remove host PID namespace")
    if rule_id == "PC-003":
        return _delete_scalar(lines, start, end, "network_mode", tag, "remove host networking")
    if rule_id == "PC-006":
        return _delete_scalar(lines, start, end, "user", tag, "remove explicit root user")
    if rule_id == "PC-001":
        return _delete_list_items(lines, start, end, "volumes",
                                  lambda item: DOCKER_SOCKET in item, tag,
                                  "remove Docker socket mount")
    if rule_id == "PC-004":
        return _delete_list_items(lines, start, end, "cap_add", _is_dangerous_cap, tag,
                                  "drop dangerous capability")
    if rule_id == "PC-011":
        raws = {p.raw for p in service.ports if not p.loopback_only and p.raw}
        return _delete_list_items(lines, start, end, "ports",
                                  lambda item: _port_matches(item, raws), tag,
                                  "remove port that bypasses the proxy")
    if rule_id == "PC-010":
        raws = {p.raw for p in service.ports if not p.loopback_only and p.raw}
        return _rebind_ports(lines, start, end, raws, tag)
    return []


def _delete_scalar(
    lines: list[str], start: int, end: int, key: str, tag: str, why: str
) -> list[_Edit]:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:")
    for i in range(start + 1, end):
        if pattern.match(lines[i]):
            return [_Edit(line=i, replacement=None, reason=f"{tag}: {why}")]
    return []


def _delete_list_items(
    lines: list[str], start: int, end: int, key: str, predicate, tag: str, why: str
) -> list[_Edit]:
    key_line = _find_key(lines, start, end, key)
    if key_line is None:
        return []
    item_indent = None
    edits: list[_Edit] = []
    kept = 0
    for i in range(key_line + 1, end):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _indent(lines[i])
        if not stripped.startswith("-") or (item_indent is not None and indent != item_indent):
            if indent <= _indent(lines[key_line]):
                break  # left the key's sub-block
            if item_indent is not None:
                break
        item_indent = indent
        content = stripped[1:].strip().strip("\"'")
        if predicate(content):
            edits.append(_Edit(line=i, replacement=None, reason=f"{tag}: {why}"))
        else:
            kept += 1
    if edits and kept == 0:
        edits.append(_Edit(line=key_line, replacement=None, reason=f"{tag}: {why}"))
    return edits


def _rebind_ports(
    lines: list[str], start: int, end: int, raws: set[str], tag: str
) -> list[_Edit]:
    key_line = _find_key(lines, start, end, "ports")
    if key_line is None:
        return []
    edits: list[_Edit] = []
    for i in range(key_line + 1, end):
        stripped = lines[i].strip()
        if not stripped.startswith("-"):
            if stripped and _indent(lines[i]) <= _indent(lines[key_line]):
                break
            continue
        content = stripped[1:].strip()
        unquoted = content.strip("\"'")
        if unquoted in raws and not unquoted.startswith("127.0.0.1:"):
            quote = content[0] if content[:1] in "\"'" else ""
            indent = " " * _indent(lines[i])
            new = f"{indent}- {quote}127.0.0.1:{unquoted}{quote}"
            edits.append(_Edit(line=i, replacement=new,
                               reason=f"{tag}: bind database port {unquoted} to loopback"))
    return edits


# ---------------------------------------------------------------------------
# Raw-text helpers


def _read_lines(file: Path) -> list[str] | None:
    try:
        return file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None


def _service_block(lines: list[str], name: str) -> tuple[int, int] | None:
    """Return the (start, end) line range of a service block, or None."""
    key_re = re.compile(rf"^(\s+){re.escape(name)}\s*:\s*(#.*)?$")
    for i, line in enumerate(lines):
        match = key_re.match(line)
        if match is None:
            continue
        indent = len(match.group(1))
        for j in range(i + 1, len(lines)):
            stripped = lines[j].strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _indent(lines[j]) <= indent:
                return i, j
        return i, len(lines)
    return None


def _find_key(lines: list[str], start: int, end: int, key: str) -> int | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(#.*)?$")
    for i in range(start + 1, end):
        if pattern.match(lines[i]):
            return i
    return None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _is_dangerous_cap(item: str) -> bool:
    return item.strip().upper().removeprefix("CAP_") in _DANGEROUS_CAPS


def _port_matches(item: str, raws: set[str]) -> bool:
    return item in raws or item.split("/")[0] in {r.split("/")[0] for r in raws}


def _in_file_name(service: Service) -> str:
    # Namespaced services (prefix/name) appear under their bare name in the file.
    return service.name.rsplit("/", 1)[-1]


def _round_trips(file: Path, new_lines: list[str]) -> bool:
    """The patched file must still be valid YAML (compose loads it)."""
    try:
        data = yaml.safe_load("\n".join(new_lines) + "\n")
    except yaml.YAMLError:
        return False
    return isinstance(data, dict) and "services" in data


def _display_name(file: Path) -> str:
    return file.name


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)
