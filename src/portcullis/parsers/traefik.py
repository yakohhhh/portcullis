"""Traefik configuration parsing - milestone 2.

Portcullis v0.1 already understands Traefik routing declared as compose
labels (``traefik.enable``, ``traefik.http.routers.*``), which is how the
vast majority of homelab stacks configure it; that logic lives in
:mod:`portcullis.exposure`.

This module will additionally parse the static configuration
(``traefik.yml``: entrypoints, exposedByDefault) and dynamic file providers,
so that exposure classification also covers services routed outside of
compose labels. Tracked in the roadmap (milestone 2).
"""

from __future__ import annotations
