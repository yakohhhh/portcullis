"""Caddy configuration parsing — milestone 2.

Portcullis v0.1 recognises caddy-docker-proxy compose labels (``caddy``,
``caddy.reverse_proxy``); that logic lives in :mod:`portcullis.exposure`.

This module will parse Caddyfiles so that exposure classification also
covers stacks where Caddy is configured through a plain Caddyfile rather
than labels. Tracked in the roadmap (milestone 2).
"""

from __future__ import annotations
