# Startrace

`Startrace` is moving from a scanner-centric project toward a browser-first operator suite for local infrastructure, lab networks and small environments.

The current codebase already combines:

- a Go runtime for discovery and scanner orchestration
- a local web UI for projects, runs, inventory and operator workflows
- shared `SQLite` persistence for projects, runs, evidence and assets

The scanner is no longer the product surface by itself. It is the first major module inside the wider `Startrace` suite.

## Code Structure Direction

`Startrace` now follows a suite-first structure inside this repository:

- `internal/suite`: the browser-facing Startrace shell, routing, layout, templates, components and global styling
- `internal/shared`: shared persistence, platform/runtime helpers and cross-module data foundations
- `internal/modules/*`: module capabilities, workflows, runtime logic and integrations

This keeps the GUI as the product shell instead of treating it as part of Radar, while still letting Radar remain the first major live module inside the suite.

The important boundary is:

- `suite` owns the GUI
- `shared` owns canonical data and shared infrastructure
- `modules` own capabilities, workflows and data production

That means modules are not intended to become separate mini frontends by default. The suite renders the product UI and consumes data or workflow output from the modules.

## Product Direction

The suite shell is now the main product layer.

Current top-level areas in the UI:

- `Dashboard`
- `Inventory`
- `Discovery`
- `Security`
- `Workbench`
- `Automation`
- `Help`
- `Settings`

Right now, `Discovery` and `Inventory` are the most developed areas.
`Security`, `Workbench` and `Automation` already exist as suite-level module spaces so future tools can be built directly inside the real product shell instead of being bolted on later. `Help` is now a dedicated module space instead of being buried under settings.

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
- run comparison (`Discovery -> Compare`)
- reevaluation scheduling records
- run acknowledgement workflows

### Shared inventory

The suite already maintains a shared inventory model above individual runs:

- persistent assets
- observed ports and host metadata
- manual overrides for display name, type, tags and notes
- historical asset observations per run
- subnet-first inventory grouping with collapsible sections
- compact port and service summaries per host
- a network view with graph-based topology rendering

This is important because future modules such as `Security` or `Workbench` should reuse the same assets and project context instead of creating isolated data silos.

### Device classification

Asset grouping is no longer only simple keyword matching.

`Startrace` now uses a small scoring-based classification pass that weighs:

- operating system fingerprints
- service and port patterns
- vendor / product clues
- hostname hints

This helps reduce bad guesses such as treating a workstation as a router just because its hostname contains `fritz` or another misleading label.

### Inventory network view

`Inventory -> Netzwerkansicht` now renders the shared topology with role-aware graph nodes:

- origin / scan host as a red satellite node
- subnets as blue rounded rectangles
- routers, switches and gateways as yellow triangles
- firewalls as green triangles
- DNS servers as purple triangles
- domain controllers as white rectangles
- regular hosts as larger blue host nodes

The graph also exposes route context, gateway inference and per-host port/service detail cards so the view is useful as an operator surface instead of just a picture.

### Help center

`Help` is now a first-class suite area and currently provides:

- a searchable help start page
- links to the main repository and local workspace
- latest help entries
- starter sections for installation, basics, plugins, runs, reevaluation, troubleshooting, inventory and best practices

The intent is to grow these pages alongside the suite instead of leaving knowledge trapped in commits and chat history.

### Suite shell

The web UI now has:

- a persistent project selector
- a global readiness / preflight indicator
- suite-level left navigation
- module-level horizontal navigation
- discovery-specific pages under the `Discovery` module
- dashboard charts for shared inventory and port state
- a stronger sci-fi / glass / glow visual language across navigation and primary views

## Linux / Ubuntu Runtime Model

On Linux, `Startrace` should be started with `sudo` / as `root`.

That is now an explicit runtime rule, not just a best-effort suggestion.
The reason is simple: several current and planned plugins rely on scanners, sensors or processes that need elevated privileges.

This applies to:

- `startrace`
- `tracer`

The web UI no longer tries to silently escalate in the background for discovery runs. Instead, the suite itself should already be running with the required privileges.

The runtime also resolves tools more defensively across common root and user install locations, including paths such as:

- `/usr/bin`
- `/usr/local/bin`
- `/opt/zeek/bin`
- `~/.local/bin`
- `~/go/bin`

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
3. Review the `Dashboard`
4. Enter `Discovery`
5. Start a run from `Discovery -> Start Run`
6. Review `Discovery -> Runs` or `Discovery -> Compare`
7. Review the shared `Inventory`
8. Open `Inventory -> Netzwerkansicht`
9. Use `Help` for setup notes, plugin references and troubleshooting

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

- `scanner-core/cmd/tracer`: CLI entrypoint for Radar/discovery execution
- `scanner-core/cmd/startrace`: suite web server entrypoint
- `scanner-core/internal/suite`: suite shell routes, templates, components and global static assets
- `scanner-core/internal/shared/platform`: shared runtime/platform helpers such as privilege checks
- `scanner-core/internal/shared/storage`: SQLite persistence, projects, runs, assets and schedules
- `scanner-core/internal/modules/radar/runtime`: Radar run planning and execution logic
- `scanner-core/internal/modules/radar/integrations`: scanner and sensor integrations currently owned by Radar
- `docs`: supporting documentation
- `scripts`: install and verification helpers
- `BackUps`: manual repository snapshots with changelogs

## Near-Term Plan

The current focus is not "more random features" but better suite foundations.

Priority order:

1. keep `Discovery` improving without letting it dominate the whole product structure
2. strengthen the shared suite shell and shared data model
3. turn scheduled discovery records into a generic automation runner
4. continue improving classification, topology and shared inventory quality
5. make `Security`, `Workbench` and `Automation` real module homes
6. introduce the next concrete module inside the suite, likely a focused workbench-style tool

## Planned Module Direction

### Discovery

- continue improving the scanner
- improve repeatable run setup
- later execute scheduled discovery tasks automatically
- continue enriching comparison, path and scan result interpretation

### Inventory

- remain the shared cross-module asset model
- become the place where all modules enrich the same hosts and devices
- improve graph semantics for infrastructure devices and path visualization

### Security

- findings and security-centric checks
- later correlation above raw scan evidence

### Workbench

- hands-on operator tools
- likely a focused HTTP repeater / request lab style tool first

### Automation

- generic scheduler and task execution
- not discovery-only logic

### Help

- central operator documentation inside the suite
- plugin references, troubleshooting, run explanations and best practices

## Repository And Links

- GitHub: [grvtyai/tracer](https://github.com/grvtyai/tracer)
- Root workspace: `C:\Users\andre\Desktop\repos\tracer\tracer`

## More Documentation

- [scanner-core README](scanner-core/README.md)
- [Ubuntu install notes](docs/INSTALL-UBUNTU.md)
