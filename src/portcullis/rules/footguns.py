"""Foot-gun rules: compose-level misconfigurations that hurt self-hosters.

Every rule follows the same philosophy (see the project's non-functional
requirements): precision over noise, and every finding must explain what was
found, why it is a risk, and how to fix it — in words a non-expert can act on.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from portcullis.model import Exposure, Finding, Severity
from portcullis.rules.base import RuleContext, rule

#: The Docker control socket, under its legacy and modern paths
#: (``/var/run`` is a symlink to ``/run`` on modern distributions).
DOCKER_SOCKET_PATHS = {"/var/run/docker.sock", "/run/docker.sock"}

#: Capabilities that grant near-host-level control (HIGH) or a broad attack
#: surface (MEDIUM). Anything not listed is not reported.
DANGEROUS_CAPS_HIGH = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT"}
DANGEROUS_CAPS_MEDIUM = {"SYS_PTRACE", "NET_ADMIN", "DAC_OVERRIDE", "DAC_READ_SEARCH"}

#: Environment variable names that usually hold a secret.
SECRET_KEY_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)", re.IGNORECASE
)

#: Values that are common defaults or trivially guessable.
WEAK_SECRET_VALUES = {
    "admin", "administrator", "password", "passwd", "changeme", "change_me",
    "changeit", "secret", "default", "root", "toor", "test", "guest", "demo",
    "1234", "12345", "123456", "12345678", "123456789", "qwerty", "azerty",
    "letmein", "password1", "password123", "admin123", "example", "postgres",
    "mysql", "mariadb", "redis",
}


def _cap_normalize(cap: str) -> str:
    return cap.strip().upper().removeprefix("CAP_")


@rule
def docker_socket_mounted(ctx: RuleContext) -> Iterable[Finding]:
    """PC-001 — The Docker socket is mounted into a container."""
    for name, service in ctx.stack.services.items():
        for mount in service.volumes:
            mounted = {mount.source.rstrip("/"), mount.target.rstrip("/")}
            if not (mounted & DOCKER_SOCKET_PATHS):
                continue
            socket_path = (
                mount.source if mount.source.rstrip("/") in DOCKER_SOCKET_PATHS
                else mount.target
            )
            ro_note = ""
            if mount.read_only:
                ro_note = (
                    " Mounting it read-only does not help: the socket is an API "
                    "endpoint, and `:ro` only prevents replacing the socket file, "
                    "not sending commands through it."
                )
            yield Finding(
                rule_id="PC-001",
                title=f"Docker socket mounted into '{name}'",
                severity=Severity.CRITICAL,
                service=name,
                exposure=ctx.exposure_of(name),
                description=(
                    f"The container '{name}' mounts {socket_path}. Whoever controls "
                    "this socket controls the Docker daemon."
                ),
                risk=(
                    "Any code execution inside this container (a vulnerability in the "
                    "app is enough) can start a privileged container and take over the "
                    "whole host — data, other services, everything." + ro_note
                ),
                remediation=(
                    "Remove the mount if the app does not truly need it. If it does "
                    "(reverse proxy auto-discovery, dashboards, updaters), put a socket "
                    "proxy in front (e.g. tecnativa/docker-socket-proxy) and grant only "
                    "the API sections the app requires."
                ),
                references=[
                    "https://docs.docker.com/engine/security/"
                    "#docker-daemon-attack-surface"
                ],
            )


@rule
def privileged_container(ctx: RuleContext) -> Iterable[Finding]:
    """PC-002 — A container runs in privileged mode."""
    for name, service in ctx.stack.services.items():
        if not service.privileged:
            continue
        yield Finding(
            rule_id="PC-002",
            title=f"'{name}' runs in privileged mode",
            severity=Severity.CRITICAL,
            service=name,
            exposure=ctx.exposure_of(name),
            description=(
                f"The container '{name}' sets `privileged: true`, which disables "
                "almost every isolation mechanism Docker provides."
            ),
            risk=(
                "A privileged container has full access to the host's devices and "
                "kernel interfaces. Escaping to the host is trivial: compromising "
                "this container means compromising the machine."
            ),
            remediation=(
                "Remove `privileged: true`. If the app needs specific privileges, "
                "grant them individually: `devices:` for hardware access, `cap_add:` "
                "for a single capability — never the whole set."
            ),
        )


@rule
def host_network_mode(ctx: RuleContext) -> Iterable[Finding]:
    """PC-003 — A container uses the host network."""
    for name, service in ctx.stack.services.items():
        if service.network_mode != "host":
            continue
        yield Finding(
            rule_id="PC-003",
            title=f"'{name}' uses host networking",
            severity=Severity.HIGH,
            service=name,
            exposure=ctx.exposure_of(name),
            description=(
                f"The container '{name}' sets `network_mode: host`: it shares the "
                "host's network stack instead of getting an isolated one."
            ),
            risk=(
                "Every port the application listens on is directly open on every "
                "interface of the host, invisible to the `ports:` section and out of "
                "reach of the reverse proxy. The container can also reach services "
                "bound to 127.0.0.1 on the host."
            ),
            remediation=(
                "Use the default bridge networking and publish only the ports you "
                "need. A few apps genuinely require host networking (e.g. Home "
                "Assistant for device discovery) — for those, firewall the host "
                "ports and document the exception."
            ),
        )


@rule
def dangerous_capabilities(ctx: RuleContext) -> Iterable[Finding]:
    """PC-004 — A container is granted a dangerous Linux capability."""
    for name, service in ctx.stack.services.items():
        for cap in service.cap_add:
            normalized = _cap_normalize(cap)
            if normalized in DANGEROUS_CAPS_HIGH:
                severity = Severity.HIGH
            elif normalized in DANGEROUS_CAPS_MEDIUM:
                severity = Severity.MEDIUM
            else:
                continue
            yield Finding(
                rule_id="PC-004",
                title=f"'{name}' adds the {normalized} capability",
                severity=severity,
                service=name,
                exposure=ctx.exposure_of(name),
                description=(
                    f"The container '{name}' adds the Linux capability {normalized} "
                    "via `cap_add`."
                ),
                risk=(
                    "Capabilities are pieces of root power. "
                    + (
                        "This one is powerful enough to escape the container or load "
                        "code into the kernel."
                        if severity is Severity.HIGH
                        else "This one significantly widens what an attacker inside "
                        "the container can do (traffic manipulation, reading "
                        "protected files, tracing other processes)."
                    )
                ),
                remediation=(
                    f"Remove `{cap}` from `cap_add` unless the application documents "
                    "why it is required. Prefer narrower alternatives (specific "
                    "`devices:`, sysctls, or a sidecar handling the privileged part)."
                ),
            )


@rule
def mutable_image_tag(ctx: RuleContext) -> Iterable[Finding]:
    """PC-005 — An image has no tag or uses ``latest``."""
    for name, service in ctx.stack.services.items():
        image = service.image
        if image is None or image.digest:
            continue
        if image.tag not in (None, "latest"):
            continue
        shown = image.raw
        yield Finding(
            rule_id="PC-005",
            title=f"'{name}' uses a mutable image tag ({shown})",
            severity=Severity.LOW,
            service=name,
            exposure=ctx.exposure_of(name),
            description=(
                f"The service '{name}' uses the image `{shown}`"
                + (" without a tag, which implicitly means `latest`."
                   if image.tag is None else " with the `latest` tag.")
            ),
            risk=(
                "`latest` changes without notice: a `docker compose pull` can silently "
                "deploy a different major version, breaking the service or reopening "
                "a patched vulnerability. It also makes rollbacks guesswork."
            ),
            remediation=(
                "Pin a version tag (e.g. `:1.32`) and upgrade deliberately. Tools "
                "like Renovate or Diun can notify you when a new version is available."
            ),
        )


@rule
def explicit_root_user(ctx: RuleContext) -> Iterable[Finding]:
    """PC-006 — A container explicitly runs as root."""
    for name, service in ctx.stack.services.items():
        user = (service.user or "").strip()
        if user.split(":")[0] not in ("root", "0"):
            continue
        yield Finding(
            rule_id="PC-006",
            title=f"'{name}' explicitly runs as root",
            severity=Severity.LOW,
            service=name,
            exposure=ctx.exposure_of(name),
            description=f"The service '{name}' sets `user: {service.user}`.",
            risk=(
                "Processes running as root inside a container have more power if "
                "they escape (kernel vulnerability, misconfigured mount) and full "
                "write access to everything mounted into the container."
            ),
            remediation=(
                "Run as an unprivileged user (`user: \"1000:1000\"`), or use the "
                "image's PUID/PGID environment variables when it supports them."
            ),
        )


@rule
def host_pid_namespace(ctx: RuleContext) -> Iterable[Finding]:
    """PC-007 — A container shares the host PID namespace."""
    for name, service in ctx.stack.services.items():
        if service.pid != "host":
            continue
        yield Finding(
            rule_id="PC-007",
            title=f"'{name}' shares the host PID namespace",
            severity=Severity.HIGH,
            service=name,
            exposure=ctx.exposure_of(name),
            description=f"The service '{name}' sets `pid: host`.",
            risk=(
                "The container sees and can signal every process on the host, and "
                "combined with SYS_PTRACE can read their memory — including secrets "
                "held by other services."
            ),
            remediation=(
                "Remove `pid: host`. Monitoring agents that need it should be "
                "trusted, minimal images — never Internet-facing applications."
            ),
        )


@rule
def weak_or_default_secrets(ctx: RuleContext) -> Iterable[Finding]:
    """PC-008 — An environment variable holds a weak or default secret."""
    for name, service in ctx.stack.services.items():
        for key, value in service.environment.items():
            if not SECRET_KEY_PATTERN.search(key):
                continue
            stripped = value.strip()
            if "${" in stripped:  # provided externally at deploy time — unknown here
                continue
            is_empty = stripped == ""
            if not is_empty and stripped.lower() not in WEAK_SECRET_VALUES:
                continue
            exposure = ctx.exposure_of(name)
            severity = Severity.CRITICAL if exposure >= Exposure.LAN else Severity.HIGH
            yield Finding(
                rule_id="PC-008",
                title=f"Weak or default secret in '{name}' ({key})",
                severity=severity,
                service=name,
                exposure=exposure,
                description=(
                    f"The environment variable `{key}` of service '{name}' is "
                    + ("empty." if is_empty else "set to a well-known default value.")
                ),
                risk=(
                    "Default and trivial credentials are the first thing attackers "
                    "and scanning bots try. On a reachable service this is an open "
                    "door, no vulnerability required."
                ),
                remediation=(
                    "Set a long random value (e.g. `openssl rand -base64 32`), store "
                    "it in an `.env` file excluded from Git or in Docker secrets, and "
                    "rotate the credential if the service was ever exposed."
                ),
            )


@rule
def sensitive_service_exposed(ctx: RuleContext) -> Iterable[Finding]:
    """PC-009 — A sensitive application is more exposed than recommended."""
    if ctx.kb is None:
        return
    for name, service in ctx.stack.services.items():
        if service.image is None:
            continue
        app = ctx.kb.match(service.image)
        if app is None:
            continue
        exposure = ctx.exposure_of(name)
        if exposure < Exposure.LAN:
            continue
        if not app.exposed_beyond_recommendation(exposure):
            continue
        severity = (
            Severity.CRITICAL
            if app.sensitivity == "critical" and exposure >= Exposure.LAN
            else Severity.HIGH
        )
        where = "the Internet" if exposure == Exposure.INTERNET else "your local network"
        yield Finding(
            rule_id="PC-009",
            title=f"{app.name} ('{name}') is reachable from {where}",
            severity=severity,
            service=name,
            exposure=exposure,
            description=(
                f"'{name}' runs {app.name} ({app.category}), a {app.sensitivity}-"
                f"sensitivity application, and it is reachable from {where}. "
                f"Recommended exposure for this app: {app.exposure_recommendation}."
            ),
            risk=app.risk_note or (
                "This application guards data or capabilities that are valuable to "
                "an attacker; exposing it widens your attack surface far more than "
                "an ordinary web app."
            ),
            remediation=(
                "Put it behind your reverse proxy with authentication (SSO/forward "
                "auth), restrict it to VPN/LAN access, or remove the published port "
                "if it does not need to be reachable at all."
            ),
            references=list(app.references),
        )


@rule
def database_published(ctx: RuleContext) -> Iterable[Finding]:
    """PC-010 — A database port is published on the host."""
    for name, service in ctx.stack.services.items():
        if service.image is None or not service.ports:
            continue
        app = ctx.kb.match(service.image) if ctx.kb else None
        if app is None or app.category != "database":
            continue
        published = [p for p in service.ports if not p.loopback_only]
        if not published:
            continue
        ports = ", ".join(str(p.host_port or p.container_port) for p in published)
        yield Finding(
            rule_id="PC-010",
            title=f"Database '{name}' ({app.name}) is published on the host (port {ports})",
            severity=Severity.HIGH,
            service=name,
            exposure=ctx.exposure_of(name),
            description=(
                f"The database service '{name}' publishes port(s) {ports} on the "
                "host, making it reachable from outside the container network."
            ),
            risk=(
                "Databases are designed to be reached by your applications, not by "
                "the network at large. Exposed database ports are continuously "
                "scanned, brute-forced, and hit by authentication-bypass CVEs."
            ),
            remediation=(
                "Remove the `ports:` entry — containers on the same compose network "
                "reach the database by service name without any published port. For "
                "occasional admin access, bind to loopback (`127.0.0.1:5432:5432`) "
                "and connect through an SSH tunnel or VPN."
            ),
        )


@rule
def service_bypasses_proxy(ctx: RuleContext) -> Iterable[Finding]:
    """PC-011 — A proxied service also publishes ports directly."""
    from portcullis.exposure import bypasses_proxy  # local import to avoid a cycle

    for name, service in ctx.stack.services.items():
        if not bypasses_proxy(service):
            continue
        direct = ", ".join(
            f"{p.host_ip + ':' if p.host_ip else ''}{p.host_port or '?'}" for p in service.ports
            if not p.loopback_only
        )
        yield Finding(
            rule_id="PC-011",
            title=f"'{name}' bypasses the reverse proxy via published port(s) {direct}",
            severity=Severity.MEDIUM,
            service=name,
            exposure=ctx.exposure_of(name),
            description=(
                f"The service '{name}' is routed through your reverse proxy but "
                f"also publishes port(s) {direct} directly on the host."
            ),
            risk=(
                "The direct port skips everything the proxy adds: TLS, access "
                "logs, rate limiting, and any authentication middleware. Anyone on "
                "the network can talk to the app directly."
            ),
            remediation=(
                "Remove the `ports:` entry and let the proxy reach the service over "
                "the shared Docker network. Keep a loopback binding "
                "(`127.0.0.1:PORT:PORT`) only if you need local debugging."
            ),
        )
