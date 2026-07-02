# Contributing to Portcullis

Thanks for considering a contribution. Portcullis is young and small on purpose — most
contributions are a single YAML file or a single rule function.

## Development setup

```sh
git clone https://github.com/yakohhhh/portcullis
cd portcullis
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the checks before pushing:

```sh
pytest
ruff check src tests
```

Ruff is configured in `pyproject.toml` (line length 100, `E F W I UP B SIM`). CI runs the same two
commands.

## Project layout

```
src/portcullis/
├── cli.py            # click entry point: `portcullis scan`
├── scanner.py        # orchestration: discover → parse → classify → rules → score
├── discovery.py      # find compose files and group them with their overrides
├── model.py          # domain model: Stack, Service, Finding, Severity, Exposure
├── exposure.py       # exposure engine (ports × proxy labels × internal networks)
├── scoring.py        # severity weights, 0–100 score, A–F grade
├── trivy.py          # optional Trivy integration (one aggregated finding per image)
├── parsers/
│   ├── compose.py    # docker-compose parsing (yaml.safe_load only)
│   ├── traefik.py    # milestone 2 — Traefik static/dynamic file config (stub)
│   └── caddy.py      # milestone 2 — Caddyfile parsing (stub)
├── rules/
│   ├── base.py       # @rule decorator, RuleContext, registry
│   └── footguns.py   # PC-001..PC-011
├── kb/
│   ├── __init__.py   # KnowledgeBase loader and image matching
│   └── data/apps/    # one YAML file per known application
└── report/
    ├── terminal.py   # rich terminal report
    └── markdown.py   # markdown report (CI artifacts, PR comments)
```

## Add an app to the knowledge base

This is the best first contribution: no Python, immediate user value. Each app is one YAML file in
`src/portcullis/kb/data/apps/`. Copy an existing entry (e.g. `vaultwarden.yaml`) and adapt it:

```yaml
id: vaultwarden                # unique slug, matches the file name
name: Vaultwarden              # display name used in findings
category: passwords            # passwords | database | media | ... (PC-010 keys on "database")
sensitivity: critical          # critical | high | medium | low
images:                        # fnmatch patterns, matched (case-insensitively) against the
  - vaultwarden/server         #   image repository AND its last path component
  - "*/vaultwarden"
default_ports: [80]            # ports the app listens on by default
default_credentials: false     # does the app ship with a default login?
exposure: proxy-only           # never | proxy-only | lan | public-ok
risk_note: >                   # optional — shown in PC-009 findings; write for a non-expert
  Vaultwarden holds every credential you own...
references:
  - https://github.com/dani-garcia/vaultwarden
```

Field notes:

- **`id` / `name`** — `id` is a stable slug; `name` is what users see in the report.
- **`category`** — free-form, but reuse existing values when one fits. `database` has behaviour
  attached: it triggers PC-010 when a port is published.
- **`sensitivity`** — how bad a compromise of this app is. `critical` means "game over for the
  user" (password manager, SSO); it upgrades PC-009 to CRITICAL when the app is LAN-reachable or
  worse.
- **`images`** — the matching contract. Patterns are `fnmatch` globs tested against both the full
  repository (`vaultwarden/server`) and its last component (`server`), lowercased.
- **`exposure`** — the recommended maximum: `never` (not beyond the host), `proxy-only` (fine on
  the Internet, but only through the reverse proxy), `lan`, or `public-ok`.

**Image-pattern precision matters more than coverage.** A pattern like `"*server*"` would match
half of Docker Hub and produce false findings on unrelated services — an entry like that will be
rejected. Prefer the exact official repository plus a namespace wildcard for known mirrors
(`"*/vaultwarden"`), and test against the images you actually see in the wild. The first matching
entry wins, so broad patterns also shadow more precise ones.

A malformed KB file is silently skipped at load time (a broken entry must never break a scan), so
add a test asserting your entry matches the intended images — and does not match near-misses.

## Add a rule

Rules live in `src/portcullis/rules/` and are plain functions decorated with `@rule` that receive
a `RuleContext` and yield `Finding` objects:

```python
from collections.abc import Iterable

from portcullis.model import Finding, Severity
from portcullis.rules.base import RuleContext, rule


@rule
def my_check(ctx: RuleContext) -> Iterable[Finding]:
    """PC-0XX — One-line summary of what this detects."""
    for name, service in ctx.stack.services.items():
        if not looks_bad(service):
            continue
        yield Finding(
            rule_id="PC-0XX",
            title=f"'{name}' does the bad thing",
            severity=Severity.HIGH,
            service=name,
            exposure=ctx.exposure_of(name),
            description="What was found, factually.",
            risk="Why it matters, in words a non-expert can understand.",
            remediation="A concrete action the user can take today.",
        )
```

Ground rules:

- **Always fill `description`, `risk` and `remediation`.** A finding that says *what* without
  *why* and *how to fix* is not acceptable — the report is pedagogical by design.
- **Take the next `PC-` id** and mention it in the function docstring, like the existing rules.
- **Use `ctx.exposure_of(name)`** so the finding is prioritised correctly, and scale severity with
  exposure when it makes sense (see PC-008 for an example).
- **Precision over noise.** This is the project's core principle: a rule must be right nearly
  every time it fires. When a case is ambiguous, stay silent or downgrade to INFO. A rule that
  cries wolf gets removed — users who learn to ignore findings are worse off than users who see
  fewer of them.

## Tests

- Tests live in `tests/` and run with plain `pytest` (configured in `pyproject.toml`).
- Every rule needs at least two tests: a stack where it fires (assert rule id, severity, service)
  and a close-but-legitimate stack where it stays silent — that second test is what enforces
  precision over noise.
- Every KB entry needs a matching test (intended images match, near-misses do not).
- Parser changes need a test with a realistic compose snippet; parsers must never crash on
  malformed input (see SECURITY.md — parser bugs are security bugs).

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat: ...`, `fix: ...`, `docs: ...`, `test: ...`, `refactor: ...`, `chore: ...` — with an
  optional scope, e.g. `feat(kb): add immich entry` or `fix(exposure): loopback IPv6 binding`.
- Keep PRs focused: one rule, one KB entry, or one fix per PR.
- Make sure `pytest` and `ruff check src tests` pass; describe *why* the change is right, not just
  what it does.
