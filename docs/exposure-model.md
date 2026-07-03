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
   since the proxy is typically the Internet entry point. Routing is detected from two sources:
   - **compose conventions**: the Traefik `traefik.enable=true` label, caddy-docker-proxy labels
     (`caddy`, `caddy.*`), and the nginx-proxy `VIRTUAL_HOST` environment variable;
   - **Traefik file configuration** (`src/portcullis/parsers/traefik.py`): the static
     configuration (`traefik.yml`/`.toml` or the service's `command:` flags) for entrypoints and
     the docker provider's `exposedByDefault`, and the dynamic file provider for routers and their
     target services. The load-balancer server URLs (`http://<service>:<port>`) name the compose
     services that Traefik routes. See [The Traefik file parser](#the-traefik-file-parser) below.
   - **Caddyfile** (`src/portcullis/parsers/caddy.py`): each site block's addresses decide whether
     it is public or loopback-bound, and its `reverse_proxy` upstreams (inline, matcher-prefixed,
     `to` block form, or pulled in via `import` of a snippet) name the routed compose services. See
     [The Caddyfile parser](#the-caddyfile-parser) below.
   - **nginx and Nginx Proxy Manager** (`src/portcullis/parsers/nginx.py`): `server` blocks in
     mounted `.conf` files, where a `proxy_pass http://<service>:<port>` names the routed compose
     service and the `listen` address decides public vs loopback. For Nginx Proxy Manager, the
     same is read from its `database.sqlite` (`proxy_host` table: forward host and domain names).
3. **Internal networks** - a service attached only to `internal: true` networks has no gateway:
   Docker cannot NAT published ports for it, so even a `ports:` entry is unreachable and the
   service stays `INTERNAL`.

Two special cases:

- **Host networking** (`network_mode: host`): every port the app listens on is bound on every host
  interface, invisible to `ports:`. The service is classified at least `LAN` (`INTERNET` if it is
  also proxied).
- **Proxy bypass**: a service that is proxied *and* publishes a non-loopback port defeats whatever
  the proxy adds (TLS, auth, logging). The engine flags this and rule PC-011 reports it.

## The Traefik file parser

When a service routes through Traefik without a `traefik.enable` label - the router lives in a
`traefik.yml` or in a dynamic file provider - the parser recovers it:

- **Entrypoints** are read from the static config or the `command:` flags
  (`--entrypoints.web.address=:80`). An entrypoint bound to a loopback address
  (`127.0.0.1:8081`) is treated as host-only. A router reachable *only* through such an entrypoint
  routes its target to `HOST`, not `INTERNET`, so an admin dashboard on an internal entrypoint is
  not overcounted as Internet-facing.
- **Routers and services** map a router to its target service, and the service's load-balancer
  server URL (`http://vaultwarden:80`) back to the compose service `vaultwarden`.
- **`exposedByDefault`** is honoured: Traefik's docker provider defaults it to `true`, meaning
  *every* container on a Traefik network is routed unless it sets `traefik.enable=false`.
  Portcullis mirrors this only when it can confirm the docker provider is enabled and the flag was
  not turned off - which surfaces the common, dangerous default of exposing the whole stack.
- **Dynamic file paths** declared as container paths (`--providers.file.directory=/etc/traefik/dynamic`)
  are translated to host paths through the Traefik service's bind mounts, then parsed too.

Everything here is defensive: reverse-proxy configuration is untrusted, hand-written input, so a
malformed file degrades the routing analysis instead of failing the scan.

## The Caddyfile parser

A plain `Caddyfile` (not caddy-docker-proxy labels) is parsed the same way:

- The parser tokenises with brace, quote and comment awareness, then isolates **site blocks** from
  the global options block and named **snippets**.
- Each **site address** decides exposure: `vault.example.com`, `http://app…`, `:8080` and
  `*.example.com` are public (`INTERNET`); `localhost` and `127.0.0.1` sites are loopback-bound, so
  their upstreams are routed to `HOST` instead.
- Every **`reverse_proxy` upstream** is collected - inline (`reverse_proxy app:80`),
  matcher-prefixed (`reverse_proxy /api/* app:80`), the block form with `to` directives, upstreams
  reached inside `handle`/`route` blocks, and those pulled in through `import` of a snippet. The
  upstream host (`app` in `app:80` or `http://app:80`) maps back to the compose service `app`.

Unknown directives are ignored; the Caddyfile grammar is large and only routing matters here.

## Current limits - read this

Portcullis is static analysis over declared configuration. Being honest about what that can and
cannot know:

- **No router knowledge.** Static analysis cannot see whether your router forwards a port, so a
  port published on all interfaces is reported as `LAN` - the safe classification. If the port is
  forwarded, the real exposure is `INTERNET` and every finding on that service is more urgent than
  reported, never less.
- **No runtime probe.** Portcullis reads files; it does not connect to anything. Firewall rules on
  the host, VPN-only interfaces, or a service that is declared but not running are all outside
  what it can observe.
