"""Knowledge base of common self-hosted applications.

Each application is described by one YAML file in ``kb/data/apps/`` so the
community can contribute entries without touching Python code. An entry maps
image name patterns to metadata: category, sensitivity, default ports,
default credentials, and the recommended exposure level.

Schema (see any file in ``data/apps/`` for a live example)::

    id: vaultwarden                # unique slug
    name: Vaultwarden              # display name
    category: passwords            # passwords | database | media | ...
    sensitivity: critical          # critical | high | medium | low
    images:                        # fnmatch patterns, matched against the
      - vaultwarden/server         #   image repository and its last component
      - "*/vaultwarden"
    default_ports: [80]
    default_credentials: false     # ships with a default login?
    exposure: proxy-only           # never | proxy-only | lan | public-ok
    risk_note: >                   # optional, used in findings
      Holds every password you own...
    references:
      - https://github.com/dani-garcia/vaultwarden
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from importlib import resources
from pathlib import Path

import yaml

from portcullis.model import Exposure, ImageRef

#: Exposure levels a recommendation allows, from strictest to loosest.
_RECOMMENDATION_CEILING: dict[str, Exposure] = {
    "never": Exposure.HOST,       # nothing beyond the host itself
    "proxy-only": Exposure.INTERNET,  # fine on the Internet, but through the proxy
    "lan": Exposure.LAN,
    "public-ok": Exposure.INTERNET,
}


@dataclass(frozen=True)
class AppInfo:
    """Metadata for one known self-hosted application."""

    id: str
    name: str
    category: str
    sensitivity: str
    image_patterns: tuple[str, ...]
    default_ports: tuple[int, ...] = ()
    default_credentials: bool = False
    exposure_recommendation: str = "proxy-only"
    risk_note: str = ""
    references: tuple[str, ...] = ()

    def matches(self, image: ImageRef) -> bool:
        candidates = (image.repository.lower(), image.name.lower())
        return any(
            fnmatch(candidate, pattern.lower())
            for pattern in self.image_patterns
            for candidate in candidates
        )

    def exposed_beyond_recommendation(self, exposure: Exposure) -> bool:
        """True when ``exposure`` exceeds what this app's recommendation allows.

        ``proxy-only`` deserves a note: reaching INTERNET *through the proxy*
        is what the recommendation describes, so it is only violated by
        direct exposure — which the exposure engine reports as LAN (published
        port). The PC-011 bypass rule covers the proxied-plus-published case.
        """
        recommendation = self.exposure_recommendation
        if recommendation == "proxy-only":
            return exposure == Exposure.LAN
        ceiling = _RECOMMENDATION_CEILING.get(recommendation, Exposure.LAN)
        return exposure > ceiling


class KnowledgeBase:
    """Loads app entries and matches them against image references."""

    def __init__(self, apps: list[AppInfo]):
        self.apps = apps

    @classmethod
    def load_default(cls) -> KnowledgeBase:
        data_dir = resources.files("portcullis.kb") / "data" / "apps"
        return cls.load(Path(str(data_dir)))

    @classmethod
    def load(cls, directory: Path) -> KnowledgeBase:
        apps: list[AppInfo] = []
        if directory.is_dir():
            for file in sorted(directory.glob("*.yaml")):
                entry = _parse_app_file(file)
                if entry is not None:
                    apps.append(entry)
        return cls(apps)

    def match(self, image: ImageRef) -> AppInfo | None:
        for app in self.apps:
            if app.matches(image):
                return app
        return None

    def __len__(self) -> int:
        return len(self.apps)


def _parse_app_file(file: Path) -> AppInfo | None:
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None  # a broken KB entry must never break a scan
    if not isinstance(data, dict) or "id" not in data:
        return None
    if not isinstance(data.get("images"), list) or not data["images"]:
        return None
    try:
        return AppInfo(
            id=str(data["id"]),
            name=str(data.get("name", data["id"])),
            category=str(data.get("category", "other")),
            sensitivity=str(data.get("sensitivity", "medium")),
            image_patterns=tuple(str(p) for p in data["images"]),
            default_ports=tuple(int(p) for p in data.get("default_ports", []) or []),
            default_credentials=bool(data.get("default_credentials", False)),
            exposure_recommendation=str(data.get("exposure", "proxy-only")),
            risk_note=str(data.get("risk_note", "") or "").strip(),
            references=tuple(str(r) for r in data.get("references", []) or []),
        )
    except (TypeError, ValueError):
        return None  # wrong-typed field in a contributed entry: skip, never crash
