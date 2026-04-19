# Configuration Reference

## startrace-satellite (Satellite binary)

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | `0.0.0.0:8765` | Address and port to listen on |
| `-id` | auto-generated UUID | Satellite ID. Stable ID recommended for production (set explicitly) |
| `-token-env` | `STARTRACE_SATELLITE_TOKEN` | Name of the env var that holds the auth token |
| `-tls-cert` | `satellite.crt` | Path to TLS certificate PEM file. Auto-generated on first start if absent |
| `-tls-key` | `satellite.key` | Path to TLS private key PEM file. Auto-generated on first start if absent |

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `STARTRACE_SATELLITE_TOKEN` | Yes (unless `-token-env` overrides) | Bearer token for API authentication |

### Examples

Minimal (token via default env var):
```bash
export STARTRACE_SATELLITE_TOKEN=<token>
./startrace-satellite
```

Custom listen address and explicit satellite ID:
```bash
export STARTRACE_SATELLITE_TOKEN=<token>
./startrace-satellite -listen 0.0.0.0:9000 -id prod-satellite-01
```

Custom cert paths:
```bash
./startrace-satellite -tls-cert /etc/startrace/satellite.crt -tls-key /etc/startrace/satellite.key
```

Dev token env var name:
```bash
export MY_SCAN_TOKEN=<token>
./startrace-satellite -token-env MY_SCAN_TOKEN
```

---

## startrace (Nexus binary)

The Nexus has its own flags (defined in `cmd/startrace/main.go`). Check current flags with:
```bash
./startrace -help
```

Common flags (verify against binary output — may evolve):

| Flag | Default | Description |
|---|---|---|
| `-listen` | `0.0.0.0:8080` | Address and port for the web UI |
| `-db` | `./startrace.db` | Path to Nexus SQLite database file |

---

## Log Output

Both binaries use `log/slog` with a text handler writing to stderr. No log file by default.

To capture logs:
```bash
./startrace-satellite 2>> /var/log/startrace-satellite.log
```

Log level control is not currently exposed as a flag. Default level: `INFO`.

---

## Systemd Unit (Satellite)

Example unit file for running the Satellite as a service:

```ini
[Unit]
Description=Startrace Satellite
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/startrace
Environment=STARTRACE_SATELLITE_TOKEN=<your-token>
ExecStart=/opt/startrace/startrace-satellite -listen 0.0.0.0:8765 -id my-satellite
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now startrace-satellite
```
