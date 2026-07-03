"""Nginx and Nginx Proxy Manager configuration parsing (milestone v2).

Two more ways a homelab puts a reverse proxy in front of its services:

* **raw nginx** - ``server`` blocks in mounted ``.conf`` files, where a
  ``proxy_pass http://<service>:<port>`` in a ``location`` names the compose
  service nginx routes to, and ``listen`` / ``server_name`` say how public it
  is;
* **Nginx Proxy Manager (NPM)** - the same, but the ``server`` blocks are
  generated files under ``data/nginx/proxy_host/*.conf``, and the source of
  truth is NPM's ``database.sqlite`` (a ``proxy_host`` table with the domain
  names and the forward host/port). Portcullis reads whichever it finds.

The output is a :class:`~portcullis.model.RoutingTable` folded into the
exposure engine, exactly like the Traefik and Caddy parsers. Everything here
is defensive: these are untrusted, hand-written or generated files, so a
malformed one degrades the analysis, it never crashes the scan.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from portcullis.model import RoutingTable, Stack
from portcullis.parsers._common import address_host, is_loopback, match_service

#: Image repository last components identifying an nginx-family reverse proxy.
NGINX_IMAGE_NAMES = {"nginx", "nginx-proxy-manager", "nginxproxymanager", "npm"}
_UPSTREAM_SCHEMES = ("http://", "https://")


def analyze(
    stack: Stack, config_files: list[Path], npm_databases: list[Path] | None = None
) -> RoutingTable:
    """Build a routing table from nginx config files and NPM databases."""
    routing = RoutingTable()

    for path in config_files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        matched = False
        try:
            matched = _analyze_nginx_text(text, stack, routing)
        except Exception:  # noqa: BLE001 - tolerant by contract, never crash a scan
            matched = False
        if matched:
            routing.files.append(path)

    for db_path in npm_databases or []:
        try:
            if _analyze_npm_database(db_path, stack, routing):
                routing.files.append(db_path)
        except (sqlite3.Error, OSError):
            continue

    routing.proxy_services |= {
        name
        for name, service in stack.services.items()
        if service.image is not None and service.image.name.lower() in NGINX_IMAGE_NAMES
    }
    return routing


# ---------------------------------------------------------------------------
# Raw nginx configuration


def _analyze_nginx_text(text: str, stack: Stack, routing: RoutingTable) -> bool:
    """Extract routing from an nginx config. Returns True if anything matched.

    Only ``server`` blocks that proxy_pass to a *known compose service* are
    used, so an unrelated ``.conf`` picked up by discovery contributes nothing.
    """
    tokens = _tokenize(text)
    matched = False
    for server in _server_blocks(tokens):
        public = _server_is_public(server)
        for host in _proxy_upstreams(server):
            service = match_service(host, stack)
            if service is None:
                continue
            (routing.internet_routed if public else routing.host_routed).add(service)
            matched = True
    return matched


def _tokenize(text: str) -> list[str]:
    """Split nginx config into ``{``, ``}``, ``;`` and word tokens.

    Comments (``# ...``) and quotes are handled; the grammar is otherwise just
    whitespace-separated words terminated by ``;`` and grouped by ``{ }``.
    """
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char in " \t\r\n":
            i += 1
        elif char == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif char in "{};":
            tokens.append(char)
            i += 1
        elif char in "\"'":
            quote = char
            j = i + 1
            buf: list[str] = []
            while j < n and text[j] != quote:
                buf.append(text[j])
                j += 1
            tokens.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in " \t\r\n{};#\"'":
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def _server_blocks(tokens: list[str]) -> list[list[str]]:
    """Return the token list inside each top-level (or nested) ``server { }``."""
    blocks: list[list[str]] = []
    i, n = 0, len(tokens)
    while i < n:
        if tokens[i] == "server" and i + 1 < n and tokens[i + 1] == "{":
            body, i = _read_block(tokens, i + 2)
            blocks.append(body)
        else:
            i += 1
    return blocks


def _read_block(tokens: list[str], i: int) -> tuple[list[str], int]:
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


def _directives(tokens: list[str]):
    """Yield each ``;``-terminated directive as a list of its word tokens.

    Braces are skipped at this level but their contents are still walked, so a
    ``proxy_pass`` inside a ``location { }`` is found.
    """
    current: list[str] = []
    for token in tokens:
        if token in (";", "{", "}"):
            if current:
                yield current
            current = []
        else:
            current.append(token)
    if current:
        yield current


def _server_is_public(server: list[str]) -> bool:
    """A server block is public unless every ``listen`` binds to loopback."""
    listens = [d for d in _directives(server) if d and d[0] == "listen"]
    hosts: list[str] = []
    for directive in listens:
        for arg in directive[1:]:
            host = _listen_host(arg)
            if host is not None:
                hosts.append(host)
            break  # the address is the first argument of `listen`
    if not hosts:
        return True  # no address parsed: assume public (conservative)
    return any(not is_loopback(host) for host in hosts)


def _listen_host(arg: str) -> str | None:
    """Host part of a ``listen`` argument (``127.0.0.1:443``, ``443``, ``[::]:80``)."""
    arg = arg.strip()
    if not arg or arg in ("ssl", "http2", "default_server", "reuseport"):
        return None
    if arg.isdigit():
        return ""  # bare port: all interfaces
    return address_host(arg)


def _proxy_upstreams(server: list[str]) -> list[str]:
    hosts: list[str] = []
    for directive in _directives(server):
        if directive and directive[0] == "proxy_pass" and len(directive) > 1:
            host = _upstream_host(directive[1])
            if host:
                hosts.append(host)
    return hosts


def _upstream_host(target: str) -> str | None:
    target = target.strip()
    if not target or target.startswith("$"):  # variable upstream: unresolvable
        return None
    if target.startswith(_UPSTREAM_SCHEMES):
        return urlparse(target).hostname
    return address_host(target) or None


# ---------------------------------------------------------------------------
# Nginx Proxy Manager SQLite database


def _analyze_npm_database(db_path: Path, stack: Stack, routing: RoutingTable) -> bool:
    """Read NPM's ``proxy_host`` table and route each enabled host."""
    uri = f"file:{db_path}?mode=ro"
    matched = False
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT domain_names, forward_host, forward_scheme, enabled "
                "FROM proxy_host WHERE is_deleted = 0"
            ).fetchall()
        except sqlite3.Error:
            return False  # not an NPM database
        for row in rows:
            if not row["enabled"]:
                continue
            service = match_service(str(row["forward_host"] or ""), stack)
            if service is None:
                continue
            # NPM proxy hosts are public by definition (domain_names is a list
            # of hostnames served on NPM's public entrypoints).
            if _npm_has_domain(row["domain_names"]):
                routing.internet_routed.add(service)
                matched = True
    return matched


def _npm_has_domain(domain_names: object) -> bool:
    try:
        names = json.loads(domain_names) if isinstance(domain_names, str) else domain_names
    except (json.JSONDecodeError, TypeError):
        return True  # malformed: keep the route (conservative)
    return bool(names) if isinstance(names, list) else True
