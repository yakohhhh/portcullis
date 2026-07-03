"""Optional live reachability probe.

The static scan predicts what *should* be reachable; this confirms what
*actually* answers, by opening a TCP connection to the published ports of the
scanned stack. It is strictly opt-in (its own ``portcullis probe`` command)
and comes with hard safety rails:

* it only ever connects to **ports declared in the scanned compose stack** -
  never an arbitrary host:port, never a range, never a port the stack does
  not publish;
* **local mode** (the default) connects to ``127.0.0.1`` only - a harmless
  loopback check of your own machine;
* **external mode** connects to a host you pass explicitly with ``--host``,
  which must be your own infrastructure - it only tests the ports the stack
  publishes on non-loopback addresses.

A probe is a plain TCP connect (is the port open?), not a scan or an exploit.
The connection function is injectable so the logic is fully testable offline.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass

from portcullis.model import Exposure, Finding, Stack

#: (reachable, detail). ``detail`` is one of open/refused/timeout/error:<Name>.
ConnectFn = Callable[[str, int, float], "tuple[bool, str]"]

LOOPBACK = "127.0.0.1"


@dataclass(frozen=True)
class ProbeTarget:
    """One (service, host, port) the probe is allowed to test."""

    service: str
    host: str
    port: int
    predicted: Exposure
    mode: str  # "local" or "external"


@dataclass(frozen=True)
class ProbeOutcome:
    target: ProbeTarget
    reachable: bool
    detail: str

    @property
    def verdict(self) -> str:
        """A short, human verdict crossing prediction with observation."""
        t = self.target
        if self.reachable and t.mode == "external":
            return "CONFIRMED reachable"
        if self.reachable:
            return "listening on the host"
        if t.predicted >= Exposure.LAN:
            return "predicted reachable, no answer (down or firewalled)"
        return "not answering"


def collect_targets(
    stack: Stack, exposures: dict[str, Exposure], *, external_host: str | None = None
) -> list[ProbeTarget]:
    """Every port the probe may test - derived *only* from the stack.

    In external mode, only ports published on a non-loopback address are
    tested (a loopback-only port is unreachable from outside by definition).
    """
    targets: list[ProbeTarget] = []
    for name, service in stack.services.items():
        predicted = exposures.get(name, Exposure.UNKNOWN)
        for port in service.ports:
            if port.host_port is None:
                continue
            if external_host is not None:
                if port.loopback_only:
                    continue
                targets.append(ProbeTarget(name, external_host, port.host_port,
                                           predicted, "external"))
            else:
                host = port.host_ip if port.loopback_only and port.host_ip else LOOPBACK
                targets.append(ProbeTarget(name, host, port.host_port, predicted, "local"))
    return targets


def run(
    targets: list[ProbeTarget], *, timeout: float = 2.0, connect: ConnectFn | None = None
) -> list[ProbeOutcome]:
    connect = connect or tcp_connect
    outcomes: list[ProbeOutcome] = []
    for target in targets:
        reachable, detail = connect(target.host, target.port, timeout)
        outcomes.append(ProbeOutcome(target=target, reachable=reachable, detail=detail))
    return outcomes


def tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Open and immediately close a TCP connection. True if the port accepts it."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "open"
    except ConnectionRefusedError:
        return False, "refused"
    except TimeoutError:
        return False, "timeout"
    except OSError as exc:
        return False, f"error: {type(exc).__name__}"


def confirmed_services(outcomes: list[ProbeOutcome]) -> set[str]:
    """Services with at least one externally-confirmed reachable port."""
    return {
        o.target.service for o in outcomes
        if o.reachable and o.target.mode == "external"
    }


def annotate_findings(
    findings: list[Finding], outcomes: list[ProbeOutcome]
) -> list[tuple[Finding, str]]:
    """Pair each finding with a probe note (promotion or an unreachable caveat).

    Only findings on a probed service get a note; others are returned unchanged
    with an empty note.
    """
    reachable = confirmed_services(outcomes)
    unreachable: set[str] = set()
    for o in outcomes:
        if not o.reachable and o.target.predicted >= Exposure.LAN:
            unreachable.add(o.target.service)
    unreachable -= reachable

    annotated: list[tuple[Finding, str]] = []
    for finding in findings:
        note = ""
        if finding.service in reachable:
            note = "confirmed reachable by the probe"
        elif finding.service in unreachable:
            note = "probe could not reach this service (down or firewalled)"
        annotated.append((finding, note))
    return annotated
