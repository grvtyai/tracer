# Distributed Setup

Nexus and Satellite on separate machines. The Nexus can run on Linux, Windows, or macOS. The Satellite must run on Linux.

## Network Requirements

- Nexus must be able to reach `https://<satellite-host>:8765` (or your configured port)
- No inbound connectivity required from Satellite to Nexus
- No VPN required — the TLS + token model is safe over any network, but a private network is recommended for production

## Steps

### On the Satellite host (Linux)

#### 1. Build or copy the satellite binary

```bash
cd scanner-core
go build -o startrace-satellite ./cmd/startrace-satellite
```

Or copy a pre-built binary.

#### 2. Install scanner tools

```bash
bash scripts/install-ubuntu-tools.sh
```

See `installation/satellite-tools.md` for the full list.

#### 3. Generate a token

```bash
TOKEN=$(openssl rand -hex 32)
echo $TOKEN
```

#### 4. Start the Satellite

```bash
export STARTRACE_SATELLITE_TOKEN=$TOKEN
sudo ./startrace-satellite -listen 0.0.0.0:8765
```

The Satellite generates `satellite.crt` and `satellite.key` on first start.
The Satellite is now reachable at `https://<satellite-ip>:8765`.

---

### On the Nexus host (Linux / Windows / macOS)

#### 5. Build or copy the nexus binary

```bash
cd scanner-core
go build -o startrace ./cmd/startrace
```

#### 6. Start the Nexus

```bash
./startrace
```

#### 7. Register the Satellite

1. Open the Nexus UI in a browser.
2. Go to **Monitoring → Satellites**.
3. Click **Register Satellite**.
4. Enter:
   - URL: `https://<satellite-ip>:8765`
   - Token: the value from step 3
5. Click **Register**.

The Nexus does a one-time TLS probe with `InsecureSkipVerify`, captures the cert fingerprint, and stores it. All subsequent connections are pinned to that fingerprint.

---

## Cert Rotation

If you need to regenerate the Satellite's TLS cert (e.g., cert expired or files lost):

1. Stop the Satellite.
2. Delete `satellite.crt` and `satellite.key`.
3. Start the Satellite — new cert files are generated.
4. Re-register the Satellite in the Nexus UI (the fingerprint has changed).

---

## Firewall

Open port 8765 (TCP inbound) on the Satellite host for the Nexus IP.
The Nexus does not need any inbound ports opened for the Satellite connection.

---

## Windows Nexus Notes

The Nexus binary is a plain Go HTTP server. It runs on Windows without any special configuration. The only Windows-specific consideration is file paths — the Nexus uses the OS file separator for its SQLite path, which is handled automatically by Go's `filepath` package.
