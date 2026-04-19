# Startrace Documentation

## What is Startrace

Startrace is a modular local operator suite for network reconnaissance and asset intelligence.
It is designed for small infrastructure operators, home lab users, and security practitioners.
It is self-hosted — no cloud, no telemetry, no external dependencies at runtime.

## Core Concepts

**Nexus** — the controller. Runs the web UI, stores data, coordinates scan runs. Binary: `startrace`.

**Satellite** — the runner. Executes the actual scans using Linux scanner tools. Binary: `startrace-satellite`.

The two components communicate over a typed HTTP+SSE API. The Nexus issues run requests; the Satellite executes them and streams events back.

## Platform Support

- Nexus: Linux, Windows, macOS (pure Go, no platform-specific code)
- Satellite: Linux only (scanner tools like arp-scan, nmap, scamper, zeek only exist on Linux)

## Deployment Modes

1. **Standalone** — Nexus and Satellite on the same Linux machine, talking over localhost.
2. **Distributed (Linux operator)** — Nexus on a Linux workstation, Satellite on a separate Linux host.
3. **Distributed (Windows operator)** — Nexus on Windows, Satellite on a Linux VM (Hyper-V / WSL2 / remote host).

## Documentation Map

- `architecture/overview.md` — System components, communication paths, current migration state
- `architecture/data-flow.md` — How a scan flows from request to stored evidence
- `api/satellite-rest-api.md` — Full Satellite HTTP API reference
- `api/authentication.md` — Bearer token auth, TLS, TOFU fingerprint pinning
- `api/sse-events.md` — Server-Sent Events stream format and event types
- `installation/standalone-quickstart.md` — Run Nexus + Satellite on one machine
- `installation/distributed-setup.md` — Separate Nexus and Satellite
- `installation/satellite-tools.md` — Required Linux scanner tools
- `packages/api-contract.md` — Wire types in internal/api
- `packages/runner-service.md` — Service interface (internal/runner/service)
- `packages/runner-apiserver.md` — Satellite-side HTTP server
- `packages/runnerclient.md` — Nexus-side HTTP client
- `packages/storage.md` — SQLite schema (Nexus DB)
- `packages/evidence.md` — Evidence record model
- `packages/engine-plugins.md` — Scanner plugin interface and integrations
- `security/tls-cert-pinning.md` — Self-signed cert + TOFU pinning model
- `security/token-model.md` — Auth token generation, storage, comparison
- `ops/config-reference.md` — All CLI flags and environment variables
