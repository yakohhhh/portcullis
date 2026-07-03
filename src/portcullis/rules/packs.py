"""Community rule packs: data-driven rules loaded from YAML.

Just as the knowledge base lets the community describe applications without
touching Python, a *rule pack* lets them describe simple pattern rules the
same way. A pack is a YAML file with metadata and a list of rules; each rule
is a set of **matchers** (all of which must hold for a service) plus the
finding prose.

    pack:
      name: my-pack
      version: 1.0.0
      maintainer: you <you@example.com>
    rules:
      - id: MYPACK-001
        title: "'{service}' exposes Prometheus without auth"
        severity: medium
        match:
          image: "*/prometheus"
          exposure: LAN            # fires only at this exposure or above
        description: "..."
        risk: "..."
        remediation: "..."
        references: ["https://..."]

Design choices that keep packs safe and low-noise:

* a rule must declare at least one **known** matcher; an empty or typo'd
  ``match`` is rejected at load time, so a broken rule never fires on every
  service;
* rule ids must be unique and must not collide with the built-in ``PC-*``
  ids (which are reserved); duplicates are dropped with a warning;
* packs load in a documented order (see :func:`load_packs`), first definition
  of an id wins.

See ``docs/rule-packs.md`` and ``examples/rule-packs/`` for the full format.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from portcullis.model import Exposure, Finding, Service, Severity

if TYPE_CHECKING:
    from portcullis.rules.base import RuleContext

#: Matcher keys a rule may use. Anything else makes the rule invalid.
_KNOWN_MATCHERS = frozenset({
    "image", "image_untagged", "published_port", "publishes_any_port",
    "env_present", "env_equals", "label_present", "label_equals",
    "privileged", "network_mode", "cap_add", "volume_target", "user",
    "exposure",
})

_RESERVED_PREFIX = "PC-"


@dataclass(frozen=True)
class PackRule:
    """One data-driven rule loaded from a pack."""

    id: str
    title: str
    severity: Severity
    match: dict
    description: str
    risk: str
    remediation: str
    references: tuple[str, ...] = ()
    pack_name: str = ""


def load_packs(directories: list[Path]) -> tuple[list[PackRule], list[str]]:
    """Load every ``*.yaml`` rule pack under the given directories.

    Directories are processed in the given order, files within each sorted by
    name; the first definition of a rule id wins and later duplicates are
    reported. Returns the accepted rules and a list of human-readable warnings
    (invalid rules, duplicate ids) for the caller to surface.
    """
    rules: list[PackRule] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for directory in directories:
        if not directory.is_dir():
            warnings.append(f"rule pack path is not a directory: {directory}")
            continue
        for file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
            pack_rules, pack_warnings = _load_pack_file(file)
            warnings.extend(pack_warnings)
            for pack_rule in pack_rules:
                if pack_rule.id in seen:
                    warnings.append(f"{file.name}: duplicate rule id '{pack_rule.id}' ignored")
                    continue
                seen.add(pack_rule.id)
                rules.append(pack_rule)
    return rules, warnings


def _load_pack_file(file: Path) -> tuple[list[PackRule], list[str]]:
    warnings: list[str] = []
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return [], [f"cannot read rule pack {file.name}: {exc}"]
    if not isinstance(data, dict):
        return [], [f"{file.name}: not a rule pack (top level is not a mapping)"]

    pack_name = str((data.get("pack") or {}).get("name", file.stem))
    rules: list[PackRule] = []
    for raw in data.get("rules") or []:
        rule, error = _parse_rule(raw, pack_name)
        if error is not None:
            warnings.append(f"{file.name}: {error}")
        elif rule is not None:
            rules.append(rule)
    return rules, warnings


def _parse_rule(raw: object, pack_name: str) -> tuple[PackRule | None, str | None]:
    if not isinstance(raw, dict):
        return None, "rule is not a mapping"
    rule_id = str(raw.get("id", "")).strip()
    if not rule_id:
        return None, "rule is missing an id"
    if rule_id.upper().startswith(_RESERVED_PREFIX):
        return None, f"rule id '{rule_id}' uses the reserved PC- prefix"
    try:
        severity = Severity.from_name(str(raw.get("severity", "medium")))
    except KeyError:
        return None, f"rule '{rule_id}' has an invalid severity"

    match = raw.get("match")
    if not isinstance(match, dict) or not match:
        return None, f"rule '{rule_id}' has no match conditions"
    unknown = set(match) - _KNOWN_MATCHERS
    if unknown:
        return None, f"rule '{rule_id}' uses unknown matcher(s): {', '.join(sorted(unknown))}"

    return PackRule(
        id=rule_id,
        title=str(raw.get("title", rule_id)),
        severity=severity,
        match=match,
        description=str(raw.get("description", "")),
        risk=str(raw.get("risk", "")),
        remediation=str(raw.get("remediation", "")),
        references=tuple(str(r) for r in raw.get("references", []) or []),
        pack_name=pack_name,
    ), None


# ---------------------------------------------------------------------------
# Evaluation


def evaluate(rules: list[PackRule], ctx: RuleContext) -> list[Finding]:
    findings: list[Finding] = []
    for name, service in ctx.stack.services.items():
        exposure = ctx.exposure_of(name)
        for rule in rules:
            if _matches(rule.match, service, exposure):
                findings.append(_to_finding(rule, name, service, exposure))
    return findings


def _to_finding(rule: PackRule, name: str, service: Service, exposure: Exposure) -> Finding:
    fields = {"service": name, "image": service.image.raw if service.image else "?"}
    return Finding(
        rule_id=rule.id,
        title=_fmt(rule.title, fields),
        severity=rule.severity,
        service=name,
        exposure=exposure,
        description=_fmt(rule.description, fields),
        risk=_fmt(rule.risk, fields),
        remediation=_fmt(rule.remediation, fields),
        source=f"pack:{rule.pack_name}" if rule.pack_name else "pack",
        references=list(rule.references),
    )


def _fmt(text: str, fields: dict[str, str]) -> str:
    for key, value in fields.items():
        text = text.replace("{" + key + "}", value)
    return text


def _matches(match: dict, service: Service, exposure: Exposure) -> bool:
    return all(_match_one(key, expected, service, exposure) for key, expected in match.items())


def _match_one(key: str, expected: object, service: Service, exposure: Exposure) -> bool:
    if key == "image":
        return _image_matches(service, str(expected))
    if key == "image_untagged":
        untagged = service.image is not None and service.image.digest is None and (
            service.image.tag in (None, "latest")
        )
        return untagged is bool(expected)
    if key == "published_port":
        return any(p.host_port == expected or p.container_port == expected
                   for p in service.ports)
    if key == "publishes_any_port":
        return bool(service.ports) is bool(expected)
    if key == "env_present":
        return all(str(k) in service.environment for k in _as_list(expected))
    if key == "env_equals":
        return isinstance(expected, dict) and all(
            service.environment.get(str(k), "").lower() == str(v).lower()
            for k, v in expected.items()
        )
    if key == "label_present":
        return all(str(k) in service.labels for k in _as_list(expected))
    if key == "label_equals":
        return isinstance(expected, dict) and all(
            service.labels.get(str(k), "").lower() == str(v).lower()
            for k, v in expected.items()
        )
    if key == "privileged":
        return service.privileged is bool(expected)
    if key == "network_mode":
        return service.network_mode == str(expected)
    if key == "cap_add":
        caps = {c.strip().upper().removeprefix("CAP_") for c in service.cap_add}
        return all(str(c).strip().upper().removeprefix("CAP_") in caps
                   for c in _as_list(expected))
    if key == "volume_target":
        return any(str(expected) in mount.target for mount in service.volumes)
    if key == "user":
        return (service.user or "") == str(expected)
    if key == "exposure":
        try:
            threshold = Exposure[str(expected).strip().upper()]
        except KeyError:
            return False
        return exposure >= threshold
    return False


def _image_matches(service: Service, pattern: str) -> bool:
    if service.image is None:
        return False
    pattern = pattern.lower()
    return fnmatch(service.image.repository.lower(), pattern) or fnmatch(
        service.image.name.lower(), pattern
    )


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else [value]
