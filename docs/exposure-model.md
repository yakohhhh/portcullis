# The exposure model

The exposure engine (`src/portcullis/exposure.py`) answers one question for every service: *who
can reach this?* Findings are then prioritised by that answer - the same misconfiguration matters
far more on an Internet-facing service than on an internal one.

## The four levels

From least to most exposed:

| Level | Meaning |
| --- | --- |
| `INTERNAL` | Reachable only by other containers on the same Docker network. |
| `HOST` | Published, but bound to a loopback address (`127.0.0.1`, `::1`): reachable from the host machine only. |
| `LAN` | Published on all interfaces: reachable from the local network - and from the Internet if the router forwards the port. |
| `INTERNET` | Routed by the reverse proxy, which is typically the Internet entry point. |

(A fifth value, `UNKNOWN`, exists as a fallback when a service cannot be classified.)

## The three signals

The classification crosses three signals read from the compose files:

1. **Published ports** - every `ports:` entry binds a host port. A loopback binding
   (`127.0.0.1:5432:5432`) limits reachability to the host itself (`HOST`); any other binding is
   reachable from the local network (`LAN`). Ports merely `expose`d between containers do not
   publish anything and are ignored.
2. **Reverse-proxy routing** - a service routed by the reverse proxy is classified `INTERNET`,
   since the proxy is typically the Internet entry point. In v0.1 this is detected from compose
   conventions: the Traefik `traefik.enable=true` label, caddy-docker-proxy labels (`caddy`,
   `caddy.*`), and the nginx-proxy `VIRTUAL_HOST` environment variable.
3. **Internal networks** - a service attached only to `internal: true` networks has no gateway:
   Docker cannot NAT published ports for it, so even a `ports:` entry is unreachable and the
   service stays `INTERNAL`.

Two special cases:

- **Host networking** (`network_mode: host`): every port the app listens on is bound on every host
  interface, invisible to `ports:`. The service is classified at least `LAN` (`INTERNET` if it is
  also proxied).
- **Proxy bypass**: a service that is proxied *and* publishes a non-loopback port defeats whatever
  the proxy adds (TLS, auth, logging). The engine flags this and rule PC-011 reports it.

## Current limits - read this

Portcullis is static analysis over declared configuration. Being honest about what that can and
cannot know:

- **Proxy detection is label-based only (v0.1).** Traefik configured through `traefik.yml` or a
  dynamic file provider, and Caddy configured through a plain Caddyfile, are not parsed yet - a
  service routed only there will not be classified `INTERNET`. The stubs in
  `src/portcullis/parsers/traefik.py` and `parsers/caddy.py` mark where this lands.
- **No router knowledge.** Static analysis cannot see whether your router forwards a port, so a
  port published on all interfaces is reported as `LAN` - the safe classification. If the port is
  forwarded, the real exposure is `INTERNET` and every finding on that service is more urgent than
  reported, never less.
- **No runtime probe.** Portcullis reads files; it does not connect to anything. Firewall rules on
  the host, VPN-only interfaces, or a service that is declared but not running are all outside
  what it can observe.

## How milestone 2 extends this

Milestone 2 adds parsing of reverse-proxy configuration files: Traefik static configuration
(`traefik.yml`: entrypoints, `exposedByDefault`) and dynamic file providers, plus Caddyfiles. That
feeds the same engine a second source of routing truth, so services routed outside compose labels
are correctly classified `INTERNET`, and label detection can be cross-checked against what the
proxy actually loads. Further out (v2), a live reachability probe is planned to confirm exposure
from the outside instead of inferring it - see the roadmap in the README.
