# Changelog

All notable changes to Portcullis are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is in its `0.x` (alpha) line, minor versions may include
breaking changes; the JSON report carries its own `schema_version` (see
[docs/json-schema.md](docs/json-schema.md)).

## [Unreleased]

### Changed

- **License**: switched from MIT to the
  [PolyForm Noncommercial License 1.0.0](LICENSE). Portcullis stays free for
  individuals and noncommercial organizations; commercial use now requires a
  paid license (see [COMMERCIAL.md](COMMERCIAL.md)). Versions before this
  change remain MIT. Contributions are accepted under the grant described in
  [CONTRIBUTING.md](CONTRIBUTING.md).

## [0.1.0] - Unreleased

First public release.

### Added

- Compose discovery and parsing, treating docker-compose as a first-class,
  untrusted input. Resolves `include:`, `extends:` (same and cross file),
  project `.env` interpolation, `profiles:`, and top-level `secrets:`/`configs:`.
- Exposure engine classifying every service INTERNAL / HOST / LAN / INTERNET by
  crossing published ports, reverse-proxy routing and `internal:` networks.
- Reverse-proxy routing from compose labels and from file configuration:
  Traefik (`traefik.yml`/`.toml`, `command:` flags, dynamic file provider,
  `exposedByDefault`, entrypoint bind addresses) and plain Caddyfiles.
- Foot-gun rules PC-001 through PC-012.
- Knowledge base of 90+ self-hosted applications (YAML, community-contributable).
- A-F grade with a documented scoring model.
- Reports: colour terminal, Markdown, self-contained HTML, and machine-readable
  JSON (`--format json`, a stable schema).
- Optional Trivy integration: image CVEs, committed secrets (`trivy fs`), and
  Dockerfile misconfigurations (`trivy config`), aggregated and deduplicated
  against PC-008.
- `--fail-on` CI gate and a composite GitHub Action.
- Runs on Linux, macOS and Windows (Python 3.10+), tested on all three in CI.

[Unreleased]: https://github.com/yakohhhh/portcullis/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yakohhhh/portcullis/releases/tag/v0.1.0
