"""Core domain model for Portcullis.

Everything the scanner produces or consumes is described here: the parsed
stack (services, networks, mounts), the exposure classification, and the
findings that end up in the report. Parsers build these objects, the rule
engine consumes them and reporters render them. Keeping the model free of
parsing and I/O logic makes every other module testable in isolation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Severity(enum.IntEnum):
    """How bad a finding is. Integer values make severities comparable."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.strip().upper()]

    def __str__(self) -> str:
        return self.name


class Exposure(enum.IntEnum):
    """How reachable a service is, from least to most exposed.

    The classification crosses published ports, reverse proxy routing and
    ``internal`` networks (see :mod:`portcullis.exposure`). ``LAN`` means
    "reachable from the local network, and from the Internet if the port is
    forwarded on the router" - without an active probe Portcullis stays on
    the safe side and reports it as local-network reachable.
    """

    UNKNOWN = -1
    INTERNAL = 0  #: only reachable by other containers
    HOST = 1  #: bound to a loopback address, reachable from the host only
    LAN = 2  #: published on all interfaces, reachable from the local network
    INTERNET = 3  #: routed by a reverse proxy, reachable from outside

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class ImageRef:
    """A parsed container image reference (``registry/repo/name:tag@digest``)."""

    raw: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def name(self) -> str:
        """Last path component of the repository (``vaultwarden/server`` -> ``server``)."""
        return self.repository.rsplit("/", 1)[-1]

    @classmethod
    def parse(cls, raw: str) -> ImageRef:
        rest = raw.strip()
        digest: str | None = None
        if "@" in rest:
            rest, digest = rest.split("@", 1)
        tag: str | None = None
        # A colon after the last slash separates the tag; a colon before it
        # belongs to a registry host:port prefix (e.g. localhost:5000/img).
        if rest.rfind(":") > rest.rfind("/"):
            rest, _, tag = rest.rpartition(":")
        return cls(raw=raw.strip(), repository=rest, tag=tag, digest=digest)


@dataclass(frozen=True)
class PortMapping:
    """One entry of a service ``ports:`` section.

    Every entry in ``ports:`` publishes the container port on the host
    (``host_port is None`` means Docker picks an ephemeral port). Ports that
    are merely ``expose``-d between containers are not represented here.
    """

    container_port: int
    host_port: int | None = None
    host_ip: str = ""
    protocol: str = "tcp"
    raw: str = ""

    @property
    def loopback_only(self) -> bool:
        return self.host_ip in ("127.0.0.1", "::1", "localhost")


@dataclass(frozen=True)
class VolumeMount:
    """One entry of a service ``volumes:`` section."""

    source: str
    target: str
    read_only: bool = False
    kind: str = "volume"  #: ``volume`` | ``bind`` | ``tmpfs``
    raw: str = ""


@dataclass
class Service:
    """A service as declared in a compose file, after override merging."""

    name: str
    image: ImageRef | None = None
    build: bool = False
    command: list[str] = field(default_factory=list)
    ports: list[PortMapping] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    network_mode: str | None = None
    volumes: list[VolumeMount] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    #: Resolved paths of the ``env_file:`` entries feeding ``environment``.
    env_files: list[Path] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    privileged: bool = False
    cap_add: list[str] = field(default_factory=list)
    cap_drop: list[str] = field(default_factory=list)
    user: str | None = None
    pid: str | None = None
    restart: str | None = None
    read_only: bool = False
    security_opt: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    #: Compose profiles the service belongs to (empty = always enabled).
    profiles: list[str] = field(default_factory=list)
    #: Names of Docker secrets granted to the service (``secrets:`` section).
    secrets: list[str] = field(default_factory=list)
    source_file: Path | None = None


@dataclass
class Network:
    """A network as declared in a compose file top-level ``networks:`` section."""

    name: str
    internal: bool = False
    external: bool = False
    driver: str | None = None


@dataclass
class Stack:
    """The whole parsed infrastructure: every service of every compose file."""

    root: Path
    services: dict[str, Service] = field(default_factory=dict)
    networks: dict[str, Network] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)
    #: Names declared in top-level ``secrets:`` sections (Docker secrets).
    secret_names: set[str] = field(default_factory=set)
    #: Non-fatal parsing problems (skipped files, ignored sections).
    warnings: list[str] = field(default_factory=list)


@dataclass
class RoutingTable:
    """Which services a reverse proxy routes, discovered from file configuration.

    Complements the label-based detection in :mod:`portcullis.exposure`:
    routing declared in Traefik or Caddy configuration files rather than in
    compose labels. A service reachable through a public entrypoint lands in
    ``internet_routed``; one reachable only through a loopback-bound
    entrypoint lands in ``host_routed`` (reachable from the host, not the
    network). ``proxy_services`` records the compose services identified as
    the reverse proxy itself.
    """

    internet_routed: set[str] = field(default_factory=set)
    host_routed: set[str] = field(default_factory=set)
    proxy_services: set[str] = field(default_factory=set)
    files: list[Path] = field(default_factory=list)

    def routes_to_internet(self, service_name: str) -> bool:
        return service_name in self.internet_routed

    def routes_to_host(self, service_name: str) -> bool:
        return service_name in self.host_routed

    def merge(self, other: RoutingTable) -> None:
        """Fold another table into this one (used to combine proxies)."""
        self.internet_routed |= other.internet_routed
        self.host_routed |= other.host_routed
        self.proxy_services |= other.proxy_services
        self.files.extend(other.files)


@dataclass
class Finding:
    """One issue reported to the user.

    A finding always carries three pieces of prose so the report stays
    understandable by a non-expert: what was found (``description``), why it
    matters (``risk``) and what to do about it (``remediation``).
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    risk: str
    remediation: str
    service: str | None = None
    exposure: Exposure | None = None
    source: str = "portcullis"  #: ``portcullis`` or ``trivy``
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Everything a reporter needs to render the final report."""

    stack: Stack
    exposures: dict[str, Exposure]
    findings: list[Finding]
    score: int
    grade: str
    #: The reverse-proxy routing used for classification (for the graph view).
    routing: RoutingTable = field(default_factory=RoutingTable)
