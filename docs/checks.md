# Checks reference

Portcullis ships 12 compose-level foot-gun rules, implemented in
`src/portcullis/rules/footguns.py`. Every finding carries three pieces of prose - what was found,
why it is a risk, and how to fix it - so this page is a condensed reference, not a replacement for
the report itself.

Severities: findings are ranked CRITICAL > HIGH > MEDIUM > LOW > INFO, and at equal severity the
most exposed service comes first.

## PC-001 - Docker socket mounted into a container (CRITICAL)

**Detects:** a service whose `volumes:` mount `/var/run/docker.sock` (as source or target).

**Why it matters:** whoever controls the socket controls the Docker daemon. Any code execution
inside the container - a vulnerability in the app is enough - can start a privileged container and
take over the whole host: data, other services, everything. Mounting it `:ro` does not help: the
socket is an API endpoint, and read-only only prevents replacing the socket file, not sending
commands through it.

**Fix:** remove the mount if the app does not truly need it. If it does (reverse proxy
auto-discovery, dashboards, updaters), put a socket proxy in front (e.g.
`tecnativa/docker-socket-proxy`) and grant only the API sections the app requires.

## PC-002 - Privileged container (CRITICAL)

**Detects:** `privileged: true` on a service.

**Why it matters:** privileged mode disables almost every isolation mechanism Docker provides. The
container gets full access to the host's devices and kernel interfaces; escaping to the host is
trivial, so compromising the container means compromising the machine.

**Fix:** remove `privileged: true`. If the app needs specific privileges, grant them individually:
`devices:` for hardware access, `cap_add:` for a single capability - never the whole set.

## PC-003 - Host networking (HIGH)

**Detects:** `network_mode: host` on a service.

**Why it matters:** the container shares the host's network stack. Every port the application
listens on is directly open on every interface of the host - invisible to the `ports:` section and
out of reach of the reverse proxy. The container can also reach services bound to `127.0.0.1` on
the host.

**Fix:** use the default bridge networking and publish only the ports you need. A few apps
genuinely require host networking (e.g. Home Assistant for device discovery) - for those, firewall
the host ports and document the exception.

## PC-004 - Dangerous Linux capability (HIGH or MEDIUM)

**Detects:** `cap_add` entries granting a dangerous capability. HIGH for near-host-level control:
`ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_BOOT`. MEDIUM for a broad attack surface:
`SYS_PTRACE`, `NET_ADMIN`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`. Other capabilities are not reported.

**Why it matters:** capabilities are pieces of root power. The HIGH set is powerful enough to
escape the container or load code into the kernel; the MEDIUM set significantly widens what an
attacker inside the container can do (traffic manipulation, reading protected files, tracing other
processes).

**Fix:** remove the capability from `cap_add` unless the application documents why it is required.
Prefer narrower alternatives: specific `devices:`, sysctls, or a sidecar handling the privileged
part.

## PC-005 - Mutable image tag (LOW)

**Detects:** an image with no tag or the `latest` tag (images pinned by digest are exempt).

**Why it matters:** `latest` changes without notice: a `docker compose pull` can silently deploy a
different major version, breaking the service or reopening a patched vulnerability. It also makes
rollbacks guesswork.

**Fix:** pin a version tag (e.g. `:1.32`) and upgrade deliberately. Tools like Renovate or Diun
can notify you when a new version is available.

## PC-006 - Explicit root user (LOW)

**Detects:** `user: root` or `user: "0"` (including `0:0` forms) on a service.

**Why it matters:** processes running as root inside a container have more power if they escape
(kernel vulnerability, misconfigured mount) and full write access to everything mounted into the
container.

**Fix:** run as an unprivileged user (`user: "1000:1000"`), or use the image's PUID/PGID
environment variables when it supports them.

## PC-007 - Host PID namespace (HIGH)

**Detects:** `pid: host` on a service.

**Why it matters:** the container sees and can signal every process on the host, and combined with
`SYS_PTRACE` can read their memory - including secrets held by other services.

**Fix:** remove `pid: host`. Monitoring agents that need it should be trusted, minimal images -
never Internet-facing applications.

## PC-008 - Weak or default secret (CRITICAL when LAN/Internet-reachable, HIGH otherwise)

**Detects:** an environment variable whose name looks secret-bearing (PASSWORD, SECRET, TOKEN,
API_KEY, ...) set to an empty value or a well-known default (`admin`, `changeme`, `123456`,
`postgres`, ...). Values referencing deploy-time variables (`${...}`) are skipped: they are
provided externally and unknown to static analysis.

**Why it matters:** default and trivial credentials are the first thing attackers and scanning
bots try. On a reachable service this is an open door, no vulnerability required - which is why
the severity escalates to CRITICAL when the service is reachable from the LAN or beyond.

**Fix:** set a long random value (e.g. `openssl rand -base64 32`), store it in an `.env` file
excluded from Git or in Docker secrets, and rotate the credential if the service was ever exposed.

## PC-009 - Sensitive application over-exposed (CRITICAL or HIGH)

**Detects:** a service whose image matches a knowledge base entry and whose exposure exceeds the
entry's recommendation (`never`, `proxy-only`, `lan`, `public-ok`). CRITICAL when a
critical-sensitivity app (password manager, SSO, ...) is LAN-reachable or worse; HIGH otherwise.

**Why it matters:** some applications guard data or capabilities that are valuable to an attacker;
exposing them widens your attack surface far more than an ordinary web app. The finding includes
the app's own risk note and the recommended exposure.

**Fix:** put the app behind your reverse proxy with authentication (SSO/forward auth), restrict it
to VPN/LAN access, or remove the published port if it does not need to be reachable at all.

## PC-010 - Database port published on the host (HIGH)

**Detects:** a service matching a knowledge base entry of category `database` that publishes a
non-loopback port.

**Why it matters:** databases are designed to be reached by your applications, not by the network
at large. Exposed database ports are continuously scanned, brute-forced, and hit by
authentication-bypass CVEs.

**Fix:** remove the `ports:` entry - containers on the same compose network reach the database by
service name without any published port. For occasional admin access, bind to loopback
(`127.0.0.1:5432:5432`) and connect through an SSH tunnel or VPN.

## PC-011 - Reverse proxy bypass (MEDIUM)

**Detects:** a service that is routed through the reverse proxy (Traefik, caddy-docker-proxy or
nginx-proxy conventions) *and* also publishes a non-loopback port directly on the host.

**Why it matters:** the direct port skips everything the proxy adds: TLS, access logs, rate
limiting, and any authentication middleware. Anyone on the network can talk to the app directly.

**Fix:** remove the `ports:` entry and let the proxy reach the service over the shared Docker
network. Keep a loopback binding (`127.0.0.1:PORT:PORT`) only if you need local debugging.

## PC-012 - Secret in environment despite a `secrets:` section (LOW)

**Detects:** a service that passes a concrete secret through `environment:` while the stack already
declares top-level Docker `secrets:`. Weak or default values are left to PC-008; externally
provided values (`${VAR}`) are ignored.

**Why it matters:** environment variables are readable by anyone who can inspect the container
(`docker inspect`, `/proc`, crash dumps, logs) and easily leak into a committed compose file.
Docker secrets are mounted as files with tighter access and stay out of the process environment.

**Fix:** move the value into the existing `secrets:` mechanism and read it from
`/run/secrets/<name>` in the service, instead of passing it through `environment:`.
