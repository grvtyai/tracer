<p align="center">
  <img src="assets/pictures/logo.png" alt="Startrace logo" width="220">
</p>

# 🛰️ Startrace

A modular local operator suite for small infrastructure, lab networks and similar environments.

Built with Go, SQLite and a local browser UI.

A long-term goal is a suite with a shared data model, a shared browser UI and multiple modules that work on the same projects, assets and evidence.

`Radar` is the first live module, with more modules planned on top of the same foundation.

## 🌌 What Startrace Is

`Startrace` currently combines:

- a Go runtime for scan planning and execution
- a local browser UI for projects, runs and inventory
- shared `SQLite` persistence for projects, runs, assets and evidence

The current UI modules are:

- `Dashboard`
- `Inventory`
- `Radar`
- `Monitoring`
- `Security`
- `Workbench`
- `Automation`
- `Help`
- `Settings`

`Radar` and `Inventory` are meaningfully developed today. `Monitoring` has a working foundation (satellite registration, capability display). The other module areas already exist so new capabilities can be added inside the real product structure instead of being bolted on later.

## 🧱 Architecture

Startrace follows a **Nexus + Satellite** model:

- **Nexus** (`startrace`) — the controller. Runs the browser UI, project management, and operator-facing workflows. Communicates with one or more Satellites over HTTP.
- **Satellite** (`startrace-satellite`) — the runner. Executes scans, hosts scanner tool integrations, streams results back to Nexus via a typed REST + SSE API.

```
Nexus (startrace)  ──── HTTP API (JSON + SSE) ──── Satellite (startrace-satellite)
       └── SQLite (Nexus DB)                              └── SQLite (local to Satellite)
```

**Platform split:**

| Component | Supported Platforms |
|---|---|
| **Nexus** | Linux, Windows, macOS (pure Go web app) |
| **Satellite** | Linux only (scanner tools require Linux) |

**Deployment scenarios:**
1. **Standalone** — Nexus and Satellite on the same Linux host, talking over localhost.
2. **Distributed (Linux operator)** — Nexus on Linux workstation, Satellite on a separate Linux host.
3. **Distributed (Windows operator)** — Nexus on Windows, Satellite on a Linux VM (Hyper-V / WSL2 / remote).

The suite is **mid-migration** from a legacy subprocess model (`st-radar`) to the full daemon model. Both paths currently coexist.

## 📡 Current State

### Radar

`Radar` is the first live module. It currently covers:

- target and CIDR scope preparation
- active discovery with `naabu`
- route probing with `scamper`
- service and OS fingerprinting with `nmap`
- web verification with `httpx`
- layer-7 grabbing with `zgrab2`
- optional local-segment discovery
- passive ingest through `Zeek`
- browser-started runs
- run history, run detail and run comparison

### Shared Inventory

The suite already keeps a shared inventory above individual runs:

- persistent assets
- host metadata and observed ports
- manual name, type, tag and note overrides
- historical observations per run
- subnet-based grouping
- compact host and service summaries
- network view / topology view

This shared inventory model is important because later modules should work on the same assets instead of creating separate silos.

### Monitoring

Monitoring has a working foundation:

- satellites table in the Nexus database
- satellite registration UI with token exchange
- capability display (which scanner plugins are available on a given Satellite)
- Satellite API contract: `/health`, `/capabilities`, `/runs`, `/runs/{id}/status`, `/runs/{id}/events`, `/runs/{id}/evidence`

### Other Module Areas

These areas already exist in the UI as product spaces, but are still early:

- `Security`
- `Workbench`
- `Automation`
- `Help`

## 🧰 Planned Tooling

These integrations are currently planned because they can add useful visibility for home networks and smaller environments:

- `fping` for fast reachability, latency and packet-loss checks
- `snmpwalk` / `Net-SNMP` for switches, access points, printers, NAS systems and other SNMP-speaking devices
- `Avahi` for mDNS / Bonjour discovery on local networks
- `testssl.sh` for TLS and certificate inspection on exposed services
- `mtr` for path quality, latency and packet-loss diagnostics
- `Suricata` for passive network security telemetry and eventing
- `TShark` for packet capture and protocol-level troubleshooting
- `enum4linux-ng` for SMB / Windows network enumeration
- `Nuclei` for controlled template-based security checks
- `Amass` for broader attack-surface and external asset discovery

## 🚀 Ubuntu Installation

The main supported runtime target is Ubuntu.

Nexus and Satellite should be started with `sudo` / as `root` on Linux. Several scanners and sensors require elevated privileges.

### 1. Clone the repository

```bash
git clone https://github.com/grvtyai/startrace.git
cd startrace
```

### 2. Install the Ubuntu toolchain

Run the installer as your normal user:

```bash
bash scripts/install-ubuntu-tools.sh
```

Optional verification:

```bash
bash scripts/verify-ubuntu-tools.sh
```

What the installer sets up:

- Go
- `naabu`
- `httpx`
- `nmap`
- `arp-scan`
- `avahi-browse`
- `zmap`
- `scamper`
- `zgrab2`
- `testssl.sh`
- `snmpwalk`
- `Zeek`
- `ldapdomaindump`
- `impacket`
- a downloaded `SharpHound` bundle for later use

For more detail see [docs/INSTALL-UBUNTU.md](docs/INSTALL-UBUNTU.md).

### 3. Start Startrace (legacy standalone mode)

For day-to-day testing on a single Linux host, use the helper script:

```bash
bash scripts/run-startrace.sh
```

What it does:

- builds `st-radar` (legacy runner)
- builds `startrace` (Nexus)
- starts `startrace` with `sudo`
- keeps the common tool paths available under `sudo`
- listens on `0.0.0.0:8080` by default

Optional overrides:

```bash
STARTRACE_LISTEN=127.0.0.1:9090 bash scripts/run-startrace.sh
STARTRACE_DB_PATH=/home/$USER/.local/share/startrace/startrace.db bash scripts/run-startrace.sh
```

### 4. Start the Satellite daemon (new model)

Build the Satellite binary on a Linux host:

```bash
cd scanner-core
go build -o ./bin/startrace-satellite ./cmd/startrace-satellite
```

Start it with a pre-shared token:

```bash
STARTRACE_SATELLITE_TOKEN=<your-token> sudo ./bin/startrace-satellite -listen 127.0.0.1:8765
```

Then register the Satellite from the Nexus **Monitoring** UI (Settings → Monitoring).

### 5. Manual build and start

If you want the manual commands instead:

```bash
cd scanner-core
go build -o ./bin/st-radar ./cmd/st-radar
go build -o ./bin/startrace ./cmd/startrace
```

Start Nexus with:

```bash
sudo env "PATH=/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ./bin/startrace --db-path /home/$USER/.local/share/startrace/startrace.db --listen 0.0.0.0:8080
```

Then open:

```text
http://<ubuntu-ip>:8080
```

### 6. Typical first run

1. Open the browser UI
2. Create or select a project
3. Open `Radar`
4. Start a run from `Radar -> Start Run`
5. Review `Runs` or `Compare`
6. Review `Inventory`
7. Use `Help` for setup and troubleshooting notes

## 🖥️ CLI Usage

The legacy CLI writes to the same persistence model and should also be run with `sudo` on Linux.

Examples:

```bash
sudo ./bin/st-radar -mode run -template examples/st-radar-home-lab.json
sudo ./bin/st-radar -mode projects
sudo ./bin/st-radar -mode runs --project "Heimnetz"
sudo ./bin/st-radar -mode show-run --run-id <run-id>
sudo ./bin/st-radar -mode diff --baseline-run <run-a> --candidate-run <run-b>
```

## 🗂️ Repository Layout

```
scanner-core/
  cmd/
    startrace/           Nexus — web UI, controller
    startrace-satellite/ Satellite daemon (new)
    st-radar/            Legacy Radar CLI runner (being deprecated)
  internal/
    api/                 Wire contract types shared by Nexus and Satellite
    controller/
      runnerclient/      Nexus-side HTTP client for the Satellite API
    runner/
      service/           Satellite service interface + sentinel errors
      apiserver/         Satellite HTTP server, handlers, SSE streaming
    suite/               Browser UI layer (routing, templates, handlers)
    shared/
      storage/           Shared SQLite persistence (projects, runs, assets, satellites, …)
      platform/          Runtime/platform helpers (Linux-specific)
    modules/
      radar/
        runtime/         Radar planning and execution logic
        integrations/    13 scanner plugins (nmap, naabu, httpx, zgrab2, zeek, …)
docs/                    Supporting documentation
scripts/                 Install and verification helpers
```

## 🌠 Near-Term Plan

The current focus is completing the Nexus ↔ Satellite integration so that Radar runs flow through the Satellite daemon instead of the legacy subprocess.

| Step | State |
|---|---|
| Define wire contract (`internal/api`) | Done |
| Satellite daemon + stub service | Done |
| Nexus-side HTTP client (`runnerclient`) | Done |
| Real Radar Service implementation (wraps existing runtime) | Done |
| Satellite registration UI in Nexus | Done |
| Wire Nexus web handlers to use `runnerclient` | **Next** |
| TLS + cert pinning for distributed mode | Pending |
| Cross-platform release build | Pending |
| Decompose `internal/suite/server.go` by module | Pending |
| Deprecate / remove `cmd/st-radar` | Pending |

After the runner split is complete, the next priorities are:

- Scheduled scans and change alerting (schedules table already exists)
- Asset baseline locking and deviation detection
- Export / reporting (JSON, CSV, PDF)
- Vulnerability correlation (NVD/OSV API lookup)
- Webhook / notification hooks (Slack, email, generic)

## 📚 More Documentation

- [docs/INSTALL-UBUNTU.md](docs/INSTALL-UBUNTU.md)
- [docs/STARTRACE-WEB-ARCHITECTURE.md](docs/STARTRACE-WEB-ARCHITECTURE.md)
- [scanner-core/README.md](scanner-core/README.md)
