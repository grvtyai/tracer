# Startrace

`Startrace` is moving from a scanner-centric project toward a browser-first operator suite for local infrastructure, lab networks and small environments.

The current codebase already combines:

- a Go runtime for discovery and scanner orchestration
- a local web UI for projects, runs, inventory and operator workflows
- shared `SQLite` persistence for projects, runs, evidence and assets

The scanner is no longer the product surface by itself. It is the first major module inside the wider `Startrace` suite.

## Product Direction

The suite shell is now the main product layer.

Current top-level areas in the UI:

- `Dashboard`
- `Inventory`
- `Discovery`
- `Security`
- `Workbench`
- `Automation`
- `Settings`

Right now, `Discovery` and `Inventory` are the most developed areas.
`Security`, `Workbench` and `Automation` already exist as suite-level module spaces so future tools can be built directly inside the real product shell instead of being bolted on later.

## Current State

### Discovery module

`Discovery` is the first live module and currently provides:

- scope preparation for targets and CIDR ranges
- active discovery with `naabu`
- route probing with `scamper`
- service and OS fingerprinting with `nmap`
- web verification with `httpx`
- layer-7 grabbing with `zgrab2`
- optional local-segment discovery with layer-2 tooling
- passive ingest through `Zeek`
- browser-launched scans
- run history and run detail views
- reevaluation scheduling records
- run acknowledgement workflows

### Shared inventory

The suite already maintains a shared inventory model above individual runs:

- persistent assets
- observed ports and host metadata
- manual overrides for display name, type, tags and notes
- historical asset observations per run

This is important because future modules such as `Security` or `Workbench` should reuse the same assets and project context instead of creating isolated data silos.

### Suite shell

The web UI now has:

- a persistent project selector
- a global readiness / preflight indicator
- suite-level left navigation
- module-level horizontal navigation
- discovery-specific pages under the `Discovery` module

## Linux / Ubuntu Runtime Model

On Linux, `Startrace` should be started with `sudo` / as `root`.

That is now an explicit runtime rule, not just a best-effort suggestion.
The reason is simple: several current and planned plugins rely on scanners, sensors or processes that need elevated privileges.

This applies to:

- `startrace`
- `tracer`

The web UI no longer tries to silently escalate in the background for discovery runs. Instead, the suite itself should already be running with the required privileges.

## Ubuntu Quick Start

Install dependencies:

```bash
bash scripts/install-ubuntu-tools.sh
```

Build the binaries:

```bash
cd scanner-core
go build -o ./bin/tracer ./cmd/tracer
go build -o ./bin/startrace ./cmd/startrace
```

Start the suite UI as `root` / via `sudo`:

```bash
sudo env "PATH=/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:/opt/zeek/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" ./bin/startrace --db-path /home/$USER/.local/share/tracer/tracer.db --listen 0.0.0.0:8080
```

Open:

```text
http://<ubuntu-ip>:8080
```

Typical flow:

1. Open the browser UI
2. Create or select a project
3. Enter `Discovery`
4. Start a run from `Discovery -> Start Run`
5. Review `Discovery -> Runs`
6. Review the shared `Inventory`

## CLI Usage

The CLI still writes into the same persistence model and should also be started with `sudo` / as `root` on Linux.

Examples:

```bash
sudo ./bin/tracer -mode run -template examples/tracer-home-lab.json
sudo ./bin/tracer -mode projects
sudo ./bin/tracer -mode runs --project "Heimnetz"
sudo ./bin/tracer -mode show-run --run-id <run-id>
sudo ./bin/tracer -mode diff --baseline-run <run-a> --candidate-run <run-b>
```

## Repository Layout

- `scanner-core/cmd/tracer`: CLI entrypoint
- `scanner-core/cmd/startrace`: suite web server entrypoint
- `scanner-core/internal/web`: suite routes, templates and static assets
- `scanner-core/internal/platform`: shared runtime/platform helpers such as privilege checks
- `scanner-core/internal/storage`: SQLite persistence, projects, runs, assets and schedules
- `scanner-core/plugins`: scanner and sensor integrations
- `docs`: supporting documentation
- `scripts`: install and verification helpers
- `BackUps`: manual repository snapshots with changelogs

## Near-Term Plan

The current focus is not "more random features" but better suite foundations.

Priority order:

1. keep `Discovery` improving without letting it dominate the whole product structure
2. strengthen the shared suite shell and shared data model
3. turn scheduled discovery records into a generic automation runner
4. make `Security`, `Workbench` and `Automation` real module homes
5. introduce the next concrete module inside the suite, likely a focused workbench-style tool

## Planned Module Direction

### Discovery

- continue improving the scanner
- improve repeatable run setup
- later execute scheduled discovery tasks automatically

### Inventory

- remain the shared cross-module asset model
- become the place where all modules enrich the same hosts and devices

### Security

- findings and security-centric checks
- later correlation above raw scan evidence

### Workbench

- hands-on operator tools
- likely a focused HTTP repeater / request lab style tool first

### Automation

- generic scheduler and task execution
- not discovery-only logic

## More Documentation

- [scanner-core README](scanner-core/README.md)
- [Ubuntu install notes](docs/INSTALL-UBUNTU.md)
