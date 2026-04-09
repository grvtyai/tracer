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
- `Security`
- `Workbench`
- `Automation`
- `Help`
- `Settings`

Only `Radar` and `Inventory` are meaningfully developed today. The other module areas already exist so new capabilities can be added inside the real product structure instead of being bolted on later.

## 🧱 Architecture

`Startrace` is built as a modular system:

- `suite`: owns the browser UI, routing, layout, templates, components and styling
- `shared`: owns canonical data, persistence and shared runtime/platform helpers
- `modules`: own capabilities, workflows, integrations and data preparation

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

On Linux, `startrace` and `tracer` should be started with `sudo` / as `root`. Several scanners and sensors require elevated privileges, and the suite no longer tries to escalate discovery runs in the background.

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

### 3. Build the binaries

```bash
cd scanner-core
go test ./...
go build -o ./bin/tracer ./cmd/tracer
go build -o ./bin/startrace ./cmd/startrace
```

### 4. Start the suite

Use `sudo` and keep the tool paths available:

```bash
sudo env "PATH=/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:/opt/zeek/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" ./bin/startrace --db-path /home/$USER/.local/share/tracer/tracer.db --listen 0.0.0.0:8080
```

Then open:

```text
http://<ubuntu-ip>:8080
```

### 5. Typical first run

1. Open the browser UI
2. Create or select a project
3. Open `Radar`
4. Start a run from `Radar -> Start Run`
5. Review `Runs` or `Compare`
6. Review `Inventory`
7. Use `Help` for setup and troubleshooting notes

## 🖥️ CLI Usage

The CLI writes to the same persistence model and should also be run with `sudo` on Linux.

Examples:

```bash
sudo ./bin/tracer -mode run -template examples/tracer-home-lab.json
sudo ./bin/tracer -mode projects
sudo ./bin/tracer -mode runs --project "Heimnetz"
sudo ./bin/tracer -mode show-run --run-id <run-id>
sudo ./bin/tracer -mode diff --baseline-run <run-a> --candidate-run <run-b>
```

## 🗂️ Repository Layout

- `scanner-core/cmd/startrace`: web server entrypoint
- `scanner-core/cmd/tracer`: CLI entrypoint
- `scanner-core/internal/suite`: browser UI layer
- `scanner-core/internal/shared/storage`: shared SQLite persistence and queries
- `scanner-core/internal/shared/platform`: shared runtime/platform helpers
- `scanner-core/internal/modules/radar/runtime`: Radar planning and execution logic
- `scanner-core/internal/modules/radar/integrations`: Radar-owned scanner integrations
- `docs`: supporting documentation
- `scripts`: install and verification helpers

## 🌠 Near-Term Plan

The near-term goal is not to add disconnected features. The priority is to make the suite structure hold.

Current focus:

1. keep improving `Radar` as the first major module in the suite
2. strengthen the shared suite shell and shared data model
3. turn scheduling into a more general automation runner
4. improve inventory quality, classification and topology views
5. continue building out `Security`, `Workbench` and `Automation`

## 📚 More Documentation

- [docs/INSTALL-UBUNTU.md](docs/INSTALL-UBUNTU.md)
- [docs/STARTRACE-WEB-ARCHITECTURE.md](docs/STARTRACE-WEB-ARCHITECTURE.md)
- [scanner-core/README.md](scanner-core/README.md)
