# CI/CD pipeline

Portcullis is a public security tool, so its own pipeline is held to the bar
it preaches. This page is the map; the workflows in
[`.github/workflows/`](../.github/workflows/) are the source of truth.

## Workflows

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | push to `main`, every PR | lint (ruff), tests on Linux 3.10-3.12 + macOS + Windows, coverage gate (>= 88%), zizmor audit of our own workflows, dogfood scan of the demo stack through the composite action, and the `ci-ok` aggregate gate |
| `codeql.yml` | push/PR to `main`, weekly | CodeQL static analysis of the Python sources **and** of the workflows themselves (`actions` language) |
| `scorecard.yml` | push to `main`, weekly | OpenSSF Scorecard supply-chain rating, published (README badge) and uploaded to the Security tab |
| `dependency-review.yml` | every PR | blocks dependency changes that introduce known-vulnerable packages |
| `release.yml` | `v*` tags | build, `twine check`, install smoke test, signed build provenance, PyPI trusted publishing, GitHub release (see [RELEASING.md](../RELEASING.md)) |

## Security posture

- **Least privilege** - every workflow declares `permissions:` explicitly,
  `contents: read` by default; jobs elevate only what they need
  (`security-events: write` for SARIF uploads, `id-token: write` for OIDC).
  One documented exception: `scorecard.yml` uses the upstream-recommended
  `permissions: read-all` from the OpenSSF template.
- **Pinned actions** - every third-party action is pinned to a full commit
  SHA with a version comment. Dependabot (weekly, grouped) bumps the pins.
- **No persisted credentials** - every `actions/checkout` sets
  `persist-credentials: false`; the release notes step uses the ephemeral
  `github.token` through `gh`, never a stored secret.
- **No template injection** - expression values (`${{ ... }}`) never reach a
  `run:` script directly; they pass through `env:` indirection. `zizmor`
  enforces this class of issue on every PR, and CodeQL's `actions` language
  double-checks it.
- **Trusted publishing** - PyPI releases use OIDC; there is no long-lived
  PyPI token anywhere in the repository or its secrets.
- **Build provenance** - release artifacts carry a signed provenance
  attestation (`actions/attest-build-provenance`), verifiable with
  `gh attestation verify`.
- **Fork safety** - no `pull_request_target`, no secrets exposed to jobs
  that run on PR code.

## Branch protection

`main` only moves through pull requests, enforced by the repository's
branch-protection settings. The single required status check is the
**`ci-ok`** aggregate job, which succeeds only when lint, the whole test
matrix, coverage, the workflow audit and the demo scan all pass - so the
protection rule never needs editing when the matrix changes. Force pushes and
deletions of `main` are disabled.

## Running the same checks locally

```sh
pip install -e ".[dev]"
ruff check src tests
pytest --cov=portcullis --cov-fail-under=88
# Workflow security audit, same gate as CI. CI also sets GH_TOKEN so zizmor's
# online audits run; export GH_TOKEN=$(gh auth token) locally for full parity.
pipx run zizmor --min-severity medium .github/workflows action.yml
```

Optionally, install the pre-commit hooks (`pipx install pre-commit`,
`pre-commit install`): ruff, whitespace/YAML hygiene, and a hook that rejects
typographic dashes.
