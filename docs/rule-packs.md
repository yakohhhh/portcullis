# Community rule packs

Beyond the built-in `PC-*` foot-gun rules, you can load extra rules from
**rule packs**: YAML files that describe simple pattern rules, the same way
the [knowledge base](../src/portcullis/kb/) describes applications. No Python,
no plugin API - just data.

```sh
portcullis scan . --rules ./my-pack --rules ./another-pack
```

`--rules` takes a directory (repeatable) and loads every `*.yaml` / `*.yml`
file in it. A ready-to-copy example lives in
[`examples/rule-packs/homelab-extras/`](../examples/rule-packs/homelab-extras/).

## Pack format

```yaml
pack:
  name: my-pack          # shown as the finding source (pack:my-pack)
  version: 1.0.0
  maintainer: You <you@example.com>

rules:
  - id: MYPACK-001       # unique; must NOT start with the reserved "PC-"
    title: "'{service}' exposes Prometheus"
    severity: medium     # critical | high | medium | low | info
    match:               # ALL conditions must hold (see matchers below)
      image: "*/prometheus"
      exposure: LAN
    description: "'{service}' runs Prometheus and is reachable from the LAN."
    risk: "Metrics endpoints leak internal detail and are rarely authed."
    remediation: "Keep it internal or bind to loopback."
    references:
      - https://example.com/hardening
```

The placeholders `{service}` and `{image}` are substituted in the title,
description, risk and remediation.

## Matchers

A rule fires for a service only when **every** matcher holds. A rule with no
matcher, or with an unknown matcher key, is rejected at load time (with a
warning) - so a typo can never turn into a rule that matches every service.

| Matcher | Type | Matches when |
| --- | --- | --- |
| `image` | glob | the service image repository or name matches (e.g. `*/prometheus`) |
| `image_untagged` | bool | the image has no tag or uses `latest` |
| `published_port` | int | the service publishes this host or container port |
| `publishes_any_port` | bool | the service publishes (or not) any port |
| `env_present` | list | all listed environment variables are set |
| `env_equals` | map | each `KEY: value` matches (case-insensitive) |
| `label_present` | list | all listed labels are set |
| `label_equals` | map | each `label: value` matches (case-insensitive) |
| `privileged` | bool | `privileged:` equals this |
| `network_mode` | string | `network_mode:` equals this (e.g. `host`) |
| `cap_add` | list | all listed capabilities are added (`CAP_` prefix optional) |
| `volume_target` | string | any mount target contains this substring |
| `user` | string | `user:` equals this |
| `exposure` | level | the service exposure is at least this (`INTERNAL`/`HOST`/`LAN`/`INTERNET`) |

## Precedence and conflicts

- **Built-in rules always run.** Packs add to them; they cannot disable a
  `PC-*` rule (the `PC-` prefix is reserved and rejected in packs).
- Directories load in the order given on the command line; within a
  directory, files load sorted by name.
- **Rule ids must be unique.** The first definition of an id wins; a later
  duplicate is dropped with a warning printed to stderr.
- A finding from a pack shows its origin as the source `pack:<name>`, so it is
  always distinguishable from the built-in checks in the report.

## Sharing a pack

A rule pack is just a directory of YAML files, so a pack repository is a
GitHub repo containing that directory (plus a README and, ideally, a small
demo compose stack and a CI check that runs `portcullis scan demo --rules .`).
Copy [`examples/rule-packs/homelab-extras/`](../examples/rule-packs/homelab-extras/)
as a starting point.
