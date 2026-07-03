# Portcullis

> See what your self-hosted stack really exposes to the Internet - and how to fix it.

[![CI](https://github.com/yakohhhh/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/yakohhhh/portcullis/actions/workflows/ci.yml)
[![CodeQL](https://github.com/yakohhhh/portcullis/actions/workflows/codeql.yml/badge.svg)](https://github.com/yakohhhh/portcullis/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/yakohhhh/portcullis/badge)](https://scorecard.dev/viewer/?uri=github.com/yakohhhh/portcullis)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)

Portcullis is a security auditor for self-hosted infrastructures. It statically analyses your
docker-compose files, figures out what each service actually exposes, runs foot-gun checks, and
renders a prioritised report with an A-F grade. 100% local: nothing leaves your machine.

## Why

Homelabs routinely run dozens of compose services behind Traefik or Caddy, with no security team
reviewing any of it. The failure modes are brutal and quiet: one published database port, one
mounted Docker socket, one default password on a LAN-reachable service - and an attacker owns the
host, not just the container.

Existing scanners don't help much here. They look at files one by one, are built for cloud and
Kubernetes estates, and drown the one finding that matters under hundreds that don't. Portcullis
treats the compose stack as the unit of analysis and asks the question a self-hoster actually
cares about: *what can reach this service, and what happens if it is compromised?*

## What it does

- **Exposure engine** - classifies every service as INTERNAL / HOST / LAN / INTERNET by crossing
  three signals: published ports × reverse-proxy routing × `internal: true` networks. Routing is
  read from compose labels (Traefik, caddy-docker-proxy, nginx-proxy) **and** from reverse-proxy
  file configuration - Traefik (`traefik.yml`/`.toml`, `command:` flags, dynamic file provider,
  `exposedByDefault`, entrypoint bind addresses), a plain Caddyfile (site addresses and
  `reverse_proxy` upstreams, including snippet imports), raw nginx `server` blocks, and Nginx Proxy
  Manager (its `database.sqlite` or generated configs).
- **Application knowledge base** - YAML entries map container images to what the app is (category,
  sensitivity, recommended exposure), so exposing a password manager is treated differently from
  exposing a blog.
- **Foot-gun rules** - 12 compose-level checks (PC-001..PC-012) for the misconfigurations that
  actually hand over homelabs. Every finding explains what was found, why it matters, and how to
  fix it.
- **A-F grade** - a simple, documented score (start at 100, subtract per finding by severity) you
  can track over time or gate CI on.
- **Optional Trivy delegation** - when the `trivy` binary is installed, image CVEs are merged into
  the report, aggregated to one finding per image.

### The checks

| ID | Check | Severity |
| --- | --- | --- |
| PC-001 | Docker socket mounted into a container | CRITICAL |
| PC-002 | Container runs in privileged mode | CRITICAL |
| PC-003 | Container uses host networking | HIGH |
| PC-004 | Dangerous Linux capability granted (`cap_add`) | HIGH or MEDIUM (by capability) |
| PC-005 | Image has no tag or uses `latest` | LOW |
| PC-006 | Container explicitly runs as root | LOW |
| PC-007 | Container shares the host PID namespace | HIGH |
| PC-008 | Weak, default or empty secret in an environment variable | CRITICAL or HIGH (by exposure) |
| PC-009 | Sensitive application more exposed than recommended | CRITICAL or HIGH (by sensitivity) |
| PC-010 | Database port published on the host | HIGH |
| PC-011 | Proxied service also publishes ports directly (proxy bypass) | MEDIUM |
| PC-012 | Secret passed via `environment:` while the stack uses Docker `secrets:` | LOW |

Full details in [docs/checks.md](docs/checks.md).

## How exposure is classified

- **INTERNAL** - reachable only by other containers on the same Docker network.
- **HOST** - published, but bound to a loopback address: reachable from the host machine only.
- **LAN** - published on all interfaces: reachable from the local network.
- **INTERNET** - routed by the reverse proxy, which is typically the Internet entry point.

Honest note: static analysis cannot know whether your router forwards a port, so a service
published on all interfaces is classified LAN - the safe, defensible answer. If the port *is*
forwarded, it is Internet-facing and the findings only get more urgent. Details and limits in
[docs/exposure-model.md](docs/exposure-model.md).

## Quickstart

```sh
# from PyPI (once released)
pipx install portcullis

# the latest from git
pipx install git+https://github.com/yakohhhh/portcullis

# or with pip, from source
git clone https://github.com/yakohhhh/portcullis
cd portcullis && pip install .
```

Then point it at a compose file or a directory tree (e.g. your homelab Git repository):

```sh
portcullis scan .
```

Requires Python 3.10+. Runs on Linux (the primary target), macOS and Windows - the test suite runs
on all three in CI.

| Option | Default | Description |
| --- | --- | --- |
| `PATH` | `.` | A compose file, or a directory walked recursively. |
| `--format terminal\|markdown\|html\|json` | `terminal` | Report format. |
| `-o, --output FILE` | stdout | Write the markdown/html/json report to a file. |
| `--min-severity LEVEL` | `info` | Hide findings below `info`/`low`/`medium`/`high`/`critical`. |
| `--fail-on LEVEL` | `never` | Exit with code 1 if any finding is at or above LEVEL (CI gate). |
| `--trivy` / `--no-trivy` | auto | Force or disable Trivy (default: used when the binary is found). |
| `--rules DIR` | - | Load a community rule pack directory (repeatable). See [docs/rule-packs.md](docs/rule-packs.md). |

### Sample output

Real output for a three-service stack - vaultwarden proxied by Traefik but also publishing a
port, postgres bound to loopback with a default password, watchtower with the Docker socket:

```text
╭────────────────────────────────────────────────────────────────╮
│ Portcullis - security report for /home/user/homelab            │
│ Grade:  C   (score 60/100, 3 services, 4 findings)             │
╰────────────────────────────────────────────────────────────────╯
                    Service exposure
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Service     ┃ Image                       ┃ Exposure ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ db          │ postgres:16                 │ HOST     │
│ vaultwarden │ vaultwarden/server:latest   │ INTERNET │
│ watchtower  │ containrrr/watchtower:1.7.1 │ INTERNAL │
└─────────────┴─────────────────────────────┴──────────┘
╭──────────  CRITICAL  Docker socket mounted into 'watchtower' ──────────╮
│ The container 'watchtower' mounts /var/run/docker.sock. Whoever        │
│ controls this socket controls the Docker daemon.                       │
│                                                                        │
│ Why it matters: Any code execution inside this container (a            │
│ vulnerability in the app is enough) can start a privileged container   │
│ and take over the whole host - data, other services, everything.       │
│                                                                        │
│ Fix: Remove the mount if the app does not truly need it. If it does    │
│ (reverse proxy auto-discovery, dashboards, updaters), put a socket     │
│ proxy in front (e.g. tecnativa/docker-socket-proxy) and grant only     │
│ the API sections the app requires.                                     │
╰──────────────────────────────────────── PC-001 · exposure: INTERNAL ───╯
… followed by the 3 remaining findings in the same format:
HIGH PC-008 (default POSTGRES_PASSWORD), MEDIUM PC-011 (vaultwarden
bypasses the proxy via port 8081), LOW PC-005 (mutable `latest` tag).
```

Use it as a CI gate, or produce a shareable report:

```sh
portcullis scan . --format markdown -o report.md --fail-on high
portcullis scan . --format html -o report.html   # self-contained, no external requests
```

## GitHub Action

Run Portcullis on every push and pull request. The action writes the report to the job summary,
optionally comments it on the PR, and fails the job above a severity threshold.

```yaml
# .github/workflows/portcullis.yml
name: Portcullis
on: [push, pull_request]
permissions:
  contents: read
  pull-requests: write   # only needed for comment-on-pr
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yakohhhh/portcullis@v1
        with:
          path: .            # a compose file or a directory tree
          fail-on: high      # critical | high | medium | low | info | never
          comment-on-pr: true
```

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Compose file or directory to scan. |
| `fail-on` | `high` | Fail the job at or above this severity (`never` to never fail). |
| `min-severity` | `info` | Hide findings below this severity in the report. |
| `trivy` | `false` | Also run Trivy when available. |
| `comment-on-pr` | `false` | Post the report as a PR comment. |

Outputs: `grade` (A-F) and `score` (0-100).

## Trivy integration

Portcullis deliberately does not reimplement what [Trivy](https://github.com/aquasecurity/trivy)
already does well. The split:

| Trivy's job | Portcullis's job |
| --- | --- |
| Image CVE scanning | Compose stack as a first-class target |
| Secrets committed in files | Exposure engine (ports × proxy × networks) |
| Dockerfile analysis | Application knowledge base |
| | Compose foot-gun rules (PC-001..PC-012) |
| | Pedagogical, prioritised report with a grade |

When `trivy` is on your PATH, Portcullis runs its three relevant scanners and merges the results as
regular findings:

- `trivy image` - known image vulnerabilities (CVEs), one finding per image;
- `trivy fs --scanners secret` - secrets committed in the tree, one finding per file;
- `trivy config` - Dockerfile misconfigurations, one finding per Dockerfile.

Results are aggregated (per image / file / Dockerfile, never one finding per occurrence) so the
report stays readable, and a secret that Portcullis's own PC-008 rule already flagged is not
reported twice. Everything else works exactly the same without Trivy installed: degraded, never
broken.

## Privacy

Portcullis is 100% local. It reads your configuration files, prints a report, and that's it: no
network calls, no telemetry, no account. (The optional Trivy integration is a separate binary with
its own behaviour, and is entirely opt-out with `--no-trivy`.)

## Roadmap

- **M1 - Core scan** (done, v0.1): compose discovery and parsing, exposure engine, rules
  PC-001..PC-011, app knowledge base, A-F grade, terminal and markdown reports, Trivy merge,
  `--fail-on` CI gate.
- **M2 - Reverse proxy configuration files** (done): Traefik (static `traefik.yml`/`.toml`,
  `command:` flags, dynamic file provider) and Caddyfile parsing, plus a knowledge base grown to
  90+ applications.
- **M3 - Reports and enrichment** (done): self-contained HTML report (`--format html`) and a
  richer Trivy merge (image CVEs, committed secrets, Dockerfile misconfigurations).
- **M4 - Industrialisation** (done): machine-readable JSON output (`--format json`), a GitHub
  Action, macOS/Windows CI, and automated PyPI releases via trusted publishing (see
  [RELEASING.md](RELEASING.md)).

- **v2** (in progress): nginx and Nginx Proxy Manager routing and community rule packs (`--rules`)
  are done; still ahead - a live reachability probe to confirm exposure from the outside, a web
  report, and patch suggestions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The easiest and highest-impact contribution is a
**knowledge base entry**: one small YAML file describing a self-hosted app you know well - no
Python required.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) - **free for individuals** (homelabs, hobby projects,
research, study) **and for noncommercial organizations** (charities, schools, public
institutions). **Companies and any other commercial use need a paid commercial license**: see
[COMMERCIAL.md](COMMERCIAL.md).

To be precise about the words: the source is public and contributions are welcome, but this is a
*source-available* license, not an OSI-approved open source one. Versions published before the
license switch remain MIT (see the git history).
