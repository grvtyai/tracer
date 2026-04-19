<p align="center">
  <img src="assets/pictures/logo.png" alt="Startrace logo" width="220">
</p>

# Startrace

Startrace is a self-hosted operator suite for network reconnaissance and asset intelligence.

It currently follows a Nexus + Satellite model:

- `startrace` is the Nexus controller with the web UI
- `startrace-satellite` is the Linux runner that executes scanner tools
- `st-radar` still exists as a legacy path during the migration

The Nexus is cross-platform (`Linux`, `Windows`, `macOS`). The Satellite is `Linux` only because the scanner toolchain depends on Linux tooling and privileges.

## Repository Notes

- The Go code lives in [`scanner-core/`](scanner-core/)
- The root `docs/` folder is the current source of truth for architecture, setup, API, and security
- The project is mid-migration from the legacy subprocess runner to the new Satellite daemon model

## Quick Start

Build from `scanner-core`:

```bash
cd scanner-core
go build -o startrace ./cmd/startrace
go build -o startrace-satellite ./cmd/startrace-satellite
```

Then follow one of these setup guides:

- Standalone Linux setup: [docs/installation/standalone-quickstart.md](docs/installation/standalone-quickstart.md)
- Distributed Nexus + Satellite setup: [docs/installation/distributed-setup.md](docs/installation/distributed-setup.md)
- Required Linux scanner tools: [docs/installation/satellite-tools.md](docs/installation/satellite-tools.md)

## Documentation

Start here:

- Documentation index: [docs/index.md](docs/index.md)
- Architecture overview: [docs/architecture/overview.md](docs/architecture/overview.md)
- Scan data flow: [docs/architecture/data-flow.md](docs/architecture/data-flow.md)

API and runtime:

- Satellite REST API: [docs/api/satellite-rest-api.md](docs/api/satellite-rest-api.md)
- Authentication and Bearer token model: [docs/api/authentication.md](docs/api/authentication.md)
- SSE event stream: [docs/api/sse-events.md](docs/api/sse-events.md)
- API contract packages: [docs/packages/api-contract.md](docs/packages/api-contract.md)
- Runner client: [docs/packages/runnerclient.md](docs/packages/runnerclient.md)
- Runner service: [docs/packages/runner-service.md](docs/packages/runner-service.md)
- Runner API server: [docs/packages/runner-apiserver.md](docs/packages/runner-apiserver.md)

Storage and security:

- Storage model: [docs/packages/storage.md](docs/packages/storage.md)
- Evidence model: [docs/packages/evidence.md](docs/packages/evidence.md)
- Engine plugins: [docs/packages/engine-plugins.md](docs/packages/engine-plugins.md)
- TLS cert pinning: [docs/security/tls-cert-pinning.md](docs/security/tls-cert-pinning.md)
- Token handling: [docs/security/token-model.md](docs/security/token-model.md)
- Config reference: [docs/ops/config-reference.md](docs/ops/config-reference.md)

## Status

The new Nexus <-> Satellite path, registration flow, REST API, SSE streaming, and TLS fingerprint pinning are already in place.

The next major work items are cross-platform release builds, decomposition of the large Nexus server package, and eventual removal of the legacy `st-radar` path.
