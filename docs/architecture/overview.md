# Architecture Overview

## Components

### Nexus (controller)
- Go web application, cross-platform
- Serves the operator-facing HTML UI
- Owns a local SQLite database (projects, runs, evidence, satellites, schedules)
- Issues scan requests to registered Satellites over HTTP
- Binary: `startrace` (`cmd/startrace/`)

### Satellite (runner)
- Go daemon, Linux only
- Exposes the typed HTTP API (`internal/api`)
- Executes scan jobs using plugged-in scanner tools
- Streams events back to the Nexus via SSE
- Has its own local SQLite (run state, evidence local to that satellite)
- Binary: `startrace-satellite` (`cmd/startrace-satellite/`)

### Legacy Runner (transitional)
- `st-radar` — a CLI subprocess spawned by the old Nexus code path
- Still present, being replaced by the new Satellite daemon model
- Will be removed once the new path is fully wired

## Communication

```
Nexus (HTTP server + UI)
  |
  | HTTPS + Bearer token
  |
Satellite (HTTP API)
  |
  | internal method calls
  |
Scanner tools (arp-scan, nmap, httpx, zeek, ...)
```

The Nexus connects to one or more registered Satellites. Each Satellite exposes a fixed REST+SSE API. The Nexus is the only client; there is no peer-to-peer communication between Satellites.

## Current Migration State

The system is mid-migration from a subprocess runner model to a daemon runner model.

### Legacy path (still in use for some flows)
```
startrace (Nexus) — spawns → st-radar (subprocess CLI) — writes → SQLite
```

### New path (primary going forward)
```
startrace (Nexus) — HTTPS API → startrace-satellite (daemon) — runner/service → scanner tools
```

Migration steps done:
- Wire contract defined (`internal/api`)
- Satellite daemon running with real Radar backend
- Nexus-side HTTP client (`runnerclient`)
- Satellite registration UI with TOFU cert pinning
- Nexus web handlers wired to use runnerclient
- TLS + cert pinning

Next:
- Cross-platform release builds (Linux + Windows Nexus, Linux Satellite)
- Decompose `internal/suite/server.go` (~3800 LOC)
- Deprecate and remove `cmd/st-radar`

## Key Package Boundaries

| Package | Side | Role |
|---|---|---|
| `internal/api` | shared | Wire types only — no logic |
| `internal/runner/service` | Satellite | Service interface + error sentinels |
| `internal/runner/apiserver` | Satellite | HTTP handlers, auth middleware, SSE |
| `internal/controller/runnerclient` | Nexus | Typed HTTP client for Satellite API |
| `internal/shared/storage` | Nexus | SQLite persistence |
| `internal/modules/radar/runtime` | Satellite | Plan building + job orchestration |
| `internal/modules/radar/integrations` | Satellite | 13 scanner plugins |
| `internal/suite` | Nexus | Web UI server + handlers |
| `internal/evidence` | shared | Canonical evidence.Record model |
| `internal/engine` | Satellite | Job dispatch + Plugin interface |
