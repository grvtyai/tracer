# tracer

`tracer` is a browser-first network scanning and inventory platform for Ubuntu.

It combines an orchestrated Go scanning core with a local web UI for projects, runs, assets, analytics and operator workflows. The long-term goal is a tool that can be installed on Ubuntu, scan private or lab networks repeatedly, build persistent host inventory and make changes between runs easy to review.

## What tracer is today

The current repository already contains two working layers:

- `scanner-core`: the Go runtime that plans, executes and persists scans
- `startrace` web UI inside the same repo: a browser interface for projects, runs, assets, analytics, settings and help

The product direction is now clearly browser-first. A desktop wrapper is not the target. The main deployment target is Ubuntu/Linux.

## Current feature set

### Scan orchestration

- scope preparation for targets and CIDR ranges
- active discovery with `naabu`
- route probing with `scamper`
- service and OS fingerprinting with `nmap`
- web verification with `httpx`
- layer-7 grabbing with `zgrab2`
- optional local-segment discovery via layer-2 / neighbor-style scanning

### Passive enrichment

- passive ingest through `Zeek`
- shared sensor modes: `off`, `auto`, `always`
- optional Zeek auto-start
- passive ingest constrained to the current run and scope so old logs do not leak into new runs

### Persistence

- local `SQLite` storage
- persisted projects
- persisted runs
- persisted job results
- normalized evidence
- blocking assessments
- reevaluation hints
- persistent asset inventory with manual overrides
- scheduled time-based reevaluation entries

### Browser UI

- project-first workflow
- project creation with metadata, storage path and target DB suggestion
- dashboard
- runs view
- run detail view
- asset inventory
- asset detail view
- analytics
- settings
- built-in help page

### Operator workflows

- launch scans from the browser
- compact preflight indicator in the top bar
- auto-detected active interface when possible
- safer scan defaults such as reevaluation being off by default
- host-level manual editing via `Edit Host`
- reevaluate a whole run or a single host
- acknowledge acceptable warnings and mark a run as completed

## Run states

The UI currently uses these run states:

- `Completed`: everything finished cleanly, or warnings were explicitly accepted
- `Needs attention`: one or more jobs failed or reevaluation is recommended
- `Running`: the run is still active
- `Failed`: the run could not complete

`Needs attention` is intentionally not a dead end anymore. The run detail page now shows:

- why the run needs attention
- which plugin failed
- on which host
- the stored error text
- a direct link to the built-in help page
- an operator action to accept warnings when the remaining results are good enough

## Why this matters for private networks

`tracer` is being shaped with private networks in mind, not only larger environments.

That means it should work well for mixed home or lab networks where the same subnet may contain:

- routers
- servers
- workstations
- smartphones
- tablets
- printers
- IoT devices

The asset model is designed so scanner observations stay intact while operator-confirmed information can be layered on top:

- display name
- device type
- connection type
- tags
- notes
- host-level reevaluation preference

This makes later dashboards much more useful than raw scan output alone.

## Ubuntu quick start

Install the tool dependencies:

```bash
bash scripts/install-ubuntu-tools.sh
```

Build the binaries:

```bash
cd scanner-core
go build -o ./bin/tracer ./cmd/tracer
go build -o ./bin/startrace ./cmd/startrace
```

Start the browser UI:

```bash
env "PATH=/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:/opt/zeek/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" ./bin/startrace --db-path /home/$USER/.local/share/tracer/tracer.db --listen 0.0.0.0:8080
```

Then open the UI in your browser:

```text
http://<ubuntu-ip>:8080
```

The normal workflow is now:

1. Open the browser UI
2. Create a project
3. Start a scan from the GUI
4. Review runs, assets and analytics
5. Reevaluate or acknowledge warnings where needed

## CLI modes that already exist

The CLI is still useful and writes into the same persistence model.

Examples:

```bash
./bin/tracer -mode run -template examples/tracer-home-lab.json
./bin/tracer -mode projects
./bin/tracer -mode runs --project "Heimnetz"
./bin/tracer -mode show-run --run-id <run-id>
./bin/tracer -mode diff --baseline-run <run-a> --candidate-run <run-b>
```

## Repository layout

- `scanner-core/cmd/tracer`: CLI entrypoint
- `scanner-core/cmd/startrace`: local web server entrypoint
- `scanner-core/internal/web`: browser UI, routes, templates and static assets
- `scanner-core/internal/storage`: SQLite persistence, projects, runs, assets and schedules
- `scanner-core/plugins`: tool integrations
- `docs`: installation and supporting documentation
- `BackUps`: manual repository snapshots with changelogs

## Roadmap

The next major steps are:

1. automatic execution for time-based reevaluations
2. richer dashboards for private-network asset groups
3. better plugin-specific remediation guidance
4. improved run scheduling and repeatable scan plans
5. more protocol coverage and passive sources
6. cleaner Ubuntu installation and service setup

## More documentation

- [scanner-core README](scanner-core/README.md)
- [Ubuntu install notes](docs/INSTALL-UBUNTU.md)
