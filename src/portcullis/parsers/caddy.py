"""Caddyfile parsing (milestone 2).

Portcullis already recognises caddy-docker-proxy compose labels (``caddy``,
``caddy.*``) - that logic lives in :mod:`portcullis.exposure`. This module
parses a plain ``Caddyfile`` so that stacks configuring Caddy through a file
rather than labels get the same exposure classification.

What it extracts, per site block:

* the site **addresses** (``vault.example.com``, ``:8080``, ``http://…``),
  which tell whether the site is public or bound to loopback;
* every ``reverse_proxy`` upstream (inline, matcher-prefixed, or in the block
  form with ``to`` directives), including those pulled in through ``import``
  of a snippet, whose host maps back to a compose service.

The Caddyfile grammar is large; this parser is deliberately tolerant. It
tokenises with brace/quote/comment awareness, isolates site blocks, snippets
and the global options block, and ignores every directive it does not care
about. Malformed input degrades the routing analysis, never crashes the scan.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from portcullis.model import RoutingTable, Stack
from portcullis.parsers._common import address_host, is_loopback, match_service

CADDY_IMAGE_NAME = "caddy"
_UPSTREAM_SCHEMES = ("http://", "https://", "h2c://")


def analyze(stack: Stack, config_files: list[Path]) -> RoutingTable:
    """Build a routing table from every Caddyfile in ``config_files``."""
    routing = RoutingTable()
    for path in config_files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            _analyze_text(text, stack, routing)
        except Exception:  # noqa: BLE001 - tolerant by contract, never crash a scan
            continue
        routing.files.append(path)

    routing.proxy_services |= {
        name
        for name, service in stack.services.items()
        if service.image is not None and service.image.name.lower() == CADDY_IMAGE_NAME
    }
    return routing


def _analyze_text(text: str, stack: Stack, routing: RoutingTable) -> None:
    tokens = _tokenize(text)
    entries = _parse_entries(tokens)
    snippets = {
        _snippet_name(head): body
        for kind, head, body in entries
        if kind == "block" and _is_snippet(head)
    }

    sites = [
        (head, body)
        for kind, head, body in entries
        if kind == "block" and head and not _is_snippet(head)
    ]
    if not sites:
        # One-liner form: no braces at all, e.g. "example.com\nreverse_proxy app:80".
        line_entries = [words for kind, _, words in _iter_lines(entries)]
        if line_entries:
            sites = [(line_entries[0], _flatten_lines(line_entries[1:]))]

    for addresses, body in sites:
        public = _site_is_public(addresses)
        for host in _extract_upstream_hosts(body, snippets, set()):
            match = match_service(host, stack)
            if match is None:
                continue
            (routing.internet_routed if public else routing.host_routed).add(match)


# ---------------------------------------------------------------------------
# Tokenizer


def _tokenize(text: str) -> list[str]:
    """Split a Caddyfile into tokens, keeping ``{`` ``}`` and newlines explicit.

    ``{$ENV}`` and ``{placeholder}`` sequences stay single tokens; a brace only
    opens a block when it ends its line (Caddy's own convention).
    """
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char in " \t\r":
            i += 1
        elif char == "\n":
            tokens.append("\n")
            i += 1
        elif char == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif char == '"':
            value, i = _read_quoted(text, i)
            tokens.append(value)
        elif char == "{":
            if _brace_opens_block(text, i):
                tokens.append("{")
                i += 1
            else:  # placeholder such as {$DOMAIN} or {host}
                value, i = _read_placeholder(text, i)
                tokens.append(value)
        elif char == "}":
            tokens.append("}")
            i += 1
        else:
            value, i = _read_word(text, i)
            tokens.append(value)
    return tokens


def _read_quoted(text: str, i: int) -> tuple[str, int]:
    j = i + 1
    buf: list[str] = []
    while j < len(text) and text[j] != '"':
        if text[j] == "\\" and j + 1 < len(text):
            buf.append(text[j + 1])
            j += 2
        else:
            buf.append(text[j])
            j += 1
    return "".join(buf), j + 1


def _read_placeholder(text: str, i: int) -> tuple[str, int]:
    j = i
    depth = 0
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1], j + 1
        elif text[j] in " \t\r\n":
            break
        j += 1
    return text[i:j], j


def _read_word(text: str, i: int) -> tuple[str, int]:
    j = i
    while j < len(text) and text[j] not in " \t\r\n{}#\"":
        j += 1
    return text[i:j], j


def _brace_opens_block(text: str, i: int) -> bool:
    """A ``{`` opens a block when the rest of its line is empty or a comment."""
    j = i + 1
    while j < len(text) and text[j] in " \t\r":
        j += 1
    return j >= len(text) or text[j] in "\n#"


# ---------------------------------------------------------------------------
# Structural parsing


def _parse_entries(tokens: list[str]) -> list[tuple[str, list[str], list[str]]]:
    """Split top-level tokens into ``(kind, head, body)`` entries."""
    entries: list[tuple[str, list[str], list[str]]] = []
    line: list[str] = []
    i, n = 0, len(tokens)
    while i < n:
        token = tokens[i]
        if token == "\n":
            if line:
                entries.append(("line", line, []))
                line = []
            i += 1
        elif token == "{":
            body, i = _read_block(tokens, i + 1)
            entries.append(("block", line, body))
            line = []
        elif token == "}":
            i += 1  # unbalanced close: ignore
        else:
            line.append(token)
            i += 1
    if line:
        entries.append(("line", line, []))
    return entries


def _read_block(tokens: list[str], i: int) -> tuple[list[str], int]:
    """Return the tokens up to the matching ``}`` and the index past it."""
    body: list[str] = []
    depth = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                return body, i + 1
        body.append(token)
        i += 1
    return body, i


# ---------------------------------------------------------------------------
# Upstream extraction


def _extract_upstream_hosts(
    body: list[str], snippets: dict[str, list[str]], seen: set[str]
) -> list[str]:
    """Collect every reverse_proxy upstream host in a site body (recursively)."""
    hosts: list[str] = []
    for line, nested in _iter_directives(body):
        if not line:
            continue
        directive = line[0]
        if directive == "reverse_proxy":
            hosts.extend(_hosts_from_upstreams(line[1:]))
            if nested is not None:
                hosts.extend(_hosts_from_to_directives(nested))
        elif directive == "import":
            for name in line[1:]:
                if name in snippets and name not in seen:
                    hosts.extend(
                        _extract_upstream_hosts(snippets[name], snippets, seen | {name})
                    )
        elif nested is not None:
            # handle / route / handle_path / @matcher blocks: recurse.
            hosts.extend(_extract_upstream_hosts(nested, snippets, seen))
    return hosts


def _hosts_from_upstreams(tokens: list[str]) -> list[str]:
    hosts: list[str] = []
    for token in tokens:
        if token.startswith(("@", "/")) or token.startswith("{"):
            continue  # matcher or placeholder, not an upstream
        host = _upstream_host(token)
        if host:
            hosts.append(host)
    return hosts


def _hosts_from_to_directives(body: list[str]) -> list[str]:
    hosts: list[str] = []
    for line, _ in _iter_directives(body):
        if line and line[0] == "to":
            hosts.extend(_hosts_from_upstreams(line[1:]))
    return hosts


def _upstream_host(token: str) -> str | None:
    token = token.strip()
    if not token or token.startswith("unix/") or token.startswith("{"):
        return None
    if token.startswith(_UPSTREAM_SCHEMES):
        return urlparse(token).hostname
    return address_host(token) or None


# ---------------------------------------------------------------------------
# Directive iteration (over a flat token list with newlines and nested blocks)


def _iter_directives(body: list[str]):
    """Yield ``(line_tokens, nested_block_or_None)`` for each directive in a body."""
    line: list[str] = []
    i, n = 0, len(body)
    while i < n:
        token = body[i]
        if token == "\n":
            if line:
                yield line, None
                line = []
            i += 1
        elif token == "{":
            nested, i = _read_block(body, i + 1)
            yield line, nested
            line = []
        elif token == "}":
            i += 1
        else:
            line.append(token)
            i += 1
    if line:
        yield line, None


def _iter_lines(entries: list[tuple[str, list[str], list[str]]]):
    for kind, head, _ in entries:
        if kind == "line":
            yield kind, None, head


def _flatten_lines(lines: list[list[str]]) -> list[str]:
    body: list[str] = []
    for words in lines:
        body.extend(words)
        body.append("\n")
    return body


# ---------------------------------------------------------------------------
# Site addresses


def _site_is_public(addresses: list[str]) -> bool:
    """A site is public unless every one of its addresses binds to loopback."""
    hosts = [_site_address_host(addr) for addr in addresses if addr and addr != ","]
    hosts = [host for host in hosts if host is not None]
    if not hosts:
        return True
    return any(not is_loopback(host) for host in hosts)


def _site_address_host(address: str) -> str | None:
    address = address.strip().rstrip(",")
    if not address or address.startswith("{"):
        return None
    for scheme in _UPSTREAM_SCHEMES:
        if address.startswith(scheme):
            address = address[len(scheme) :]
            break
    if address.startswith("*."):  # wildcard host is public
        return address[2:]
    return address_host(address)


# ---------------------------------------------------------------------------
# Snippets


def _is_snippet(head: list[str]) -> bool:
    return len(head) == 1 and head[0].startswith("(") and head[0].endswith(")")


def _snippet_name(head: list[str]) -> str:
    return head[0][1:-1]
