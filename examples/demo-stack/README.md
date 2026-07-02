# Demo stack — a deliberately vulnerable homelab

This directory contains a realistic but **deliberately misconfigured** homelab
compose file. It is used by the documentation and by CI to exercise Portcullis
against known, stable findings.

> **DO NOT deploy this stack.** Every mistake in it is intentional and marked
> with a `# DELIBERATE (PC-0xx)` comment in `docker-compose.yml`.

Reproduce the scan from the repository root:

```console
portcullis scan examples/demo-stack --no-trivy
```

## What Portcullis finds

| Deliberate issue                                          | Rule   | Service(s)                          | Severity |
| --------------------------------------------------------- | ------ | ----------------------------------- | -------- |
| Docker socket mounted (read-only — `:ro` does not help)   | PC-001 | `traefik`                           | CRITICAL |
| Docker socket mounted read-write                           | PC-001 | `portainer`                         | CRITICAL |
| Host networking (`network_mode: host`)                     | PC-003 | `homeassistant`                     | HIGH     |
| `SYS_ADMIN` capability added                               | PC-004 | `duplicati`                         | HIGH     |
| Image without a tag (implicit `latest`)                    | PC-005 | `portainer`                         | LOW      |
| Default credential (`POSTGRES_PASSWORD: postgres`)         | PC-008 | `postgres`                          | CRITICAL |
| Sensitive app more exposed than its recommendation         | PC-009 | `jellyfin`, `homeassistant`         | HIGH     |
| Sensitive app more exposed than its recommendation         | PC-009 | `postgres`                          | CRITICAL |
| Database port published on the host (`5432:5432`)          | PC-010 | `postgres`                          | HIGH     |
| Published port bypasses the reverse proxy (`8081:80`)      | PC-011 | `vaultwarden`                       | MEDIUM   |

Eleven findings in total: with 4 CRITICAL and 5 HIGH the score bottoms out at
**0/100, grade F** — exactly what a stack this careless deserves.

## Exposure classification

The stack also demonstrates every exposure level of the engine:

| Service                            | Exposure   | Why                                                    |
| ---------------------------------- | ---------- | ------------------------------------------------------ |
| `vaultwarden`                      | INTERNET   | routed by Traefik (`traefik.enable=true`)              |
| `traefik`, `jellyfin`, `postgres`, | LAN        | ports published on all interfaces (or host networking  |
| `homeassistant`                    |            | for `homeassistant`)                                   |
| `duplicati`                        | HOST       | port bound to `127.0.0.1`: reachable from the host only |
| `portainer`                        | INTERNAL   | no published port, not proxied                         |
| `redis`                            | INTERNAL   | attached only to the `internal: true` backend network  |

`redis` is the clean counter-example: pinned tag, no published port, internal
network only — zero findings.

## A note on PC-009 vs PC-011

A `proxy-only` application that is *proxied and also published directly*
(like `vaultwarden` here) is reported as a proxy bypass (PC-011), not as
over-exposure (PC-009): reaching the Internet *through* the proxy is what the
recommendation describes. PC-009 fires for services that reach the LAN
directly, without the proxy — `jellyfin`, `homeassistant` (via host
networking) and `postgres` in this stack.

## Files

- `docker-compose.yml` — the stack itself, with every mistake annotated.
- `.env.example` — an example of the weak secrets rule PC-008 flags. It is not
  referenced by the compose file, so it does not affect the scan; it only
  illustrates what **not** to put in an `.env` file.
