# TLS Certificate Pinning

## Overview

The Satellite always serves HTTPS using a self-signed certificate. The Nexus does not trust a CA chain — instead it pins the exact certificate fingerprint obtained during the first connection (TOFU: Trust on First Use).

## Certificate Generation

Source: `internal/runner/apiserver/selfcert.go`

`GenerateSelfSignedCert(certFile, keyFile string) error`

- Called by the Satellite binary on startup, before the HTTP server starts.
- If both files already exist on disk: no-op. The existing cert is reused.
- If either file is missing: generates a new cert.

Generated cert properties:
- Algorithm: ECDSA P-256
- Validity: 10 years from generation time
- Subject/SAN: `localhost` + all non-loopback local IPs at generation time
- Self-signed (no CA)

The cert and key are written as PEM files. Paths are configured via `-tls-cert` and `-tls-key` flags (defaults: `satellite.crt`, `satellite.key` in the binary's working directory).

## TOFU Registration Flow

1. Operator enters Satellite URL + token in the Nexus UI.
2. Nexus creates a temporary `runnerclient` with `TLSFingerprint: ""` (no pinning).
3. The HTTP transport uses `InsecureSkipVerify: true` for this first connection only.
4. Nexus calls `GET /health` on the Satellite.
5. After the TLS handshake, Nexus reads `resp.TLS.PeerCertificates[0]` (the leaf cert).
6. Computes `SHA-256(cert.Raw)` — raw is the DER-encoded certificate bytes.
7. Encodes as lowercase hex string.
8. Stores in `satellites.tls_fingerprint` in Nexus SQLite.

## Pinned Transport

Source: `internal/controller/runnerclient/client.go` — `pinnedTLSTransport(fingerprint string)`

For all subsequent connections to a registered Satellite:
1. A custom `*http.Transport` is built.
2. `TLSClientConfig.InsecureSkipVerify = true` — bypasses Go's CA chain validation (we don't use a CA).
3. `TLSClientConfig.VerifyConnection` hook is set:
   - Reads the leaf cert from `cs.PeerCertificates[0]`
   - Computes `SHA-256(cert.Raw)`
   - Hex-encodes and compares to stored fingerprint
   - Returns `tls.AlertCertificateUnknown` error if mismatch

This means: a new cert signed by a trusted CA will be rejected. Only the exact cert that was present during registration is accepted.

## Cert Rotation

If the Satellite cert changes (files deleted, cert expired, new deployment), the Nexus will reject all connections with a fingerprint mismatch error. Resolution:
1. Stop the old Satellite.
2. Delete old cert files (if rotating).
3. Start new Satellite — cert regenerated.
4. In the Nexus UI: delete the old satellite registration and re-register.
5. The new fingerprint is captured during re-registration.

## Security Properties

- Protects against MITM after initial registration: any intercepted cert, even a CA-signed one, is rejected.
- Does not protect against MITM during the initial registration. Operators should register on a trusted network.
- No revocation mechanism. If a Satellite key is compromised: re-register (which rotates the pinned fingerprint).
- No expiry enforcement on the pinned cert. The 10-year validity is generous for operator deployments.
