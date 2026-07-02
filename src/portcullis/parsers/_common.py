"""Helpers shared by the reverse-proxy parsers (Traefik, Caddy)."""

from __future__ import annotations

from portcullis.model import Stack

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def match_service(host: str, stack: Stack) -> str | None:
    """Map an upstream host to a compose service key.

    A reverse proxy reaches a container by its compose service name over the
    shared Docker network, so an upstream host like ``vaultwarden`` (from
    ``http://vaultwarden:80``) is matched against the stack's service keys -
    exactly, by last path segment (namespaced services), or by service name.
    """
    host = host.strip().lower()
    if not host:
        return None
    for key, service in stack.services.items():
        if host in (key.lower(), key.rsplit("/", 1)[-1].lower(), service.name.lower()):
            return key
    return None


def address_host(address: str) -> str:
    """Return the host part of a ``host:port`` / ``[ipv6]:port`` / ``:port`` address."""
    address = address.strip()
    if not address:
        return ""
    if address.startswith("["):  # [::1]:8080
        end = address.find("]")
        return address[1:end] if end != -1 else address
    if ":" in address:
        return address.rsplit(":", 1)[0]
    return address


def is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS
