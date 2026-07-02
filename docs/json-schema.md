# JSON report schema

`portcullis scan --format json` prints a machine-readable report. It is a
stable contract for integrations (the GitHub Action, dashboards, scripts):
additive changes keep `schema_version` at the same major, breaking changes
bump it.

Enums are serialised **by name**, never by their internal integer value:

- `severity`: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`
- `exposure`: `INTERNET` | `LAN` | `HOST` | `INTERNAL` | `UNKNOWN`

## Shape

```json
{
  "schema_version": "1.0",
  "tool": "portcullis",
  "tool_version": "0.1.0.dev0",
  "scanned_path": "/home/user/homelab",
  "score": 60,
  "grade": "C",
  "summary": {
    "services": 3,
    "findings": 2,
    "by_severity": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0 }
  },
  "services": [
    {
      "name": "db",
      "image": "postgres:16",
      "build": false,
      "exposure": "HOST"
    }
  ],
  "findings": [
    {
      "rule_id": "PC-008",
      "title": "Weak or default secret in 'db' (POSTGRES_PASSWORD)",
      "severity": "HIGH",
      "service": "db",
      "exposure": "HOST",
      "source": "portcullis",
      "description": "The environment variable POSTGRES_PASSWORD ... is set to a well-known default value.",
      "risk": "Default and trivial credentials are the first thing attackers and scanning bots try. ...",
      "remediation": "Set a long random value (e.g. openssl rand -base64 32) ...",
      "references": []
    }
  ]
}
```

## Fields

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | `MAJOR.MINOR`. Consumers should accept any matching major. |
| `tool` | string | Always `portcullis`. |
| `tool_version` | string | The Portcullis version that produced the report. |
| `scanned_path` | string | The path that was scanned. |
| `score` | integer | 0-100. |
| `grade` | string | `A`-`F`. |
| `summary.services` | integer | Number of services in the stack. |
| `summary.findings` | integer | Number of findings **after** the `--min-severity` filter. |
| `summary.by_severity` | object | Count per severity name, for the reported findings. |
| `services[]` | array | One entry per service, sorted by name. |
| `services[].name` | string | Compose service name (may be namespaced with its directory). |
| `services[].image` | string \| null | Image reference, or `null` when the service only `build`s. |
| `services[].build` | boolean | Whether the service has a `build:` section. |
| `services[].exposure` | string | Exposure level name. |
| `findings[]` | array | Sorted most-severe first, then by exposure. |
| `findings[].rule_id` | string | e.g. `PC-008`, `TRIVY-CVE`. |
| `findings[].severity` | string | Severity name. |
| `findings[].service` | string \| null | Owning service, or `null` when not service-specific. |
| `findings[].exposure` | string \| null | Exposure of the owning service, if known. |
| `findings[].source` | string | `portcullis` or `trivy`. |
| `findings[].description` / `risk` / `remediation` | string | Plain-language what / why / how-to-fix. |
| `findings[].references` | array of string | Zero or more URLs. |

## Stability

- `schema_version` starts at `1.0`. New optional fields bump the minor.
- Renaming or removing a field, or changing an enum's string values, bumps the
  major.
- The `--min-severity` filter applies to `findings` and `summary`, but `score`
  and `grade` are always computed from **all** findings.
