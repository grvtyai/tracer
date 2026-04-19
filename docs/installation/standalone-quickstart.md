# Standalone Quickstart (Linux)

Both Nexus and Satellite on the same Linux machine.

## Prerequisites

- Linux (Ubuntu 20.04+ recommended)
- Root / sudo access (required by scanner tools)
- Go 1.22+ (for building from source)
- Scanner tools installed — see `installation/satellite-tools.md`

## Steps

### 1. Build the binaries

```bash
cd scanner-core
go build -o startrace ./cmd/startrace
go build -o startrace-satellite ./cmd/startrace-satellite
```

### 2. Generate a token

```bash
TOKEN=$(openssl rand -hex 32)
echo $TOKEN
```

Keep this value — you will enter it in the UI during registration.

### 3. Start the Satellite

```bash
export STARTRACE_SATELLITE_TOKEN=$TOKEN
sudo ./startrace-satellite -listen 0.0.0.0:8765
```

On first start, the Satellite generates `satellite.crt` and `satellite.key` in the current directory.

The Satellite is now listening at `https://localhost:8765`.

### 4. Start the Nexus

In a second terminal:

```bash
./startrace
```

The Nexus starts on `http://localhost:8080` by default (exact flag: `-listen`).

### 5. Register the Satellite in the UI

1. Open `http://localhost:8080` in a browser.
2. Go to **Monitoring → Satellites**.
3. Click **Register Satellite**.
4. Enter:
   - URL: `https://localhost:8765`
   - Token: the value from step 2
5. Click **Register**.

The Nexus probes the Satellite over TLS (InsecureSkipVerify for the first contact), captures the cert fingerprint, and stores it. Subsequent connections pin to that fingerprint.

### 6. Verify

The registered Satellite should appear in the list with status `ok` and its capabilities (available scanner plugins) listed.

## Automated Script

For local dev, `scripts/run-startrace.sh` wraps these steps. Check the script for current flags.
