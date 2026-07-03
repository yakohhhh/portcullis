"""Rule engine plumbing.

A rule is a plain function decorated with :func:`rule` that receives a
:class:`RuleContext` and yields :class:`~portcullis.model.Finding` objects.
Keeping rules as small functions over a shared context makes each one
independently testable and easy to contribute.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from portcullis.model import Exposure, Finding, RoutingTable, Stack

if TYPE_CHECKING:
    from portcullis.kb import KnowledgeBase

RuleFunc = Callable[["RuleContext"], Iterable[Finding]]

_REGISTRY: list[RuleFunc] = []


@dataclass
class RuleContext:
    """Everything a rule can look at."""

    stack: Stack
    exposures: dict[str, Exposure] = field(default_factory=dict)
    kb: KnowledgeBase | None = None
    routing: RoutingTable = field(default_factory=RoutingTable)
    #: Community rule packs (``portcullis.rules.packs.PackRule`` instances)
    #: loaded from ``--rules`` directories. Left untyped to keep this module
    #: free of a (type-only) import cycle with ``packs``.
    packs: list = field(default_factory=list)

    def exposure_of(self, service_name: str) -> Exposure:
        return self.exposures.get(service_name, Exposure.UNKNOWN)


def rule(func: RuleFunc) -> RuleFunc:
    """Register a rule function."""
    _REGISTRY.append(func)
    return func


def all_rules() -> list[RuleFunc]:
    return list(_REGISTRY)


def run_all(context: RuleContext) -> list[Finding]:
    findings: list[Finding] = []
    for check in _REGISTRY:
        findings.extend(check(context))
    if context.packs:
        from portcullis.rules import packs  # local import avoids a cycle

        findings.extend(packs.evaluate(context.packs, context))
    return findings
