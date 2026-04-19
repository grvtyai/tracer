# Authentication

## Bearer Token

Every request to the Satellite API (except `GET /health`) must include an `Authorization` header:

```
Authorization: Bearer <token>
```

The token is a shared secret set by the operator before starting the Satellite. It is compared using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

### Token Setup

On the Satellite:
```bash
export STARTRACE_SATELLITE_TOKEN=<your-secret-token>
./startrace-satellite
```

The environment variable name is configurable via the `-token-env` flag (default: `STARTRACE_SATELLITE_TOKEN`).

On the Nexus side, the token is entered during satellite registration in the UI and stored in the Nexus SQLite database (`satellites.registration_token_hint` stores only the first/last chars as a hint, not the full token). The full token is kept in memory during the registration session and passed to `runnerclient.Config.AuthToken`.

### Token Generation

There is no enforced format — any string works. Recommended approach:
```bash
openssl rand -hex 32
```

This produces a 64-character hex string with ~256 bits of entropy.

---

## TLS Transport Security

The Satellite always runs with TLS. It does not support plain HTTP.

### Self-Signed Certificate

On first start, the Satellite auto-generates a self-signed ECDSA P-256 certificate if the cert files do not exist:
- Default cert file: `satellite.crt` (same directory as binary)
- Default key file: `satellite.key`

Paths are configurable via `-tls-cert` and `-tls-key` flags.

The cert is intentionally self-signed. There is no CA requirement. Security is provided by fingerprint pinning (TOFU), not certificate authority trust.

---

## TOFU Fingerprint Pinning

Trust-on-first-use (TOFU) is how the Nexus establishes trust with a Satellite.

### Registration Flow

1. Operator enters Satellite URL and token in the Nexus UI.
2. Nexus makes an initial TLS connection with `InsecureSkipVerify: true` (first contact only).
3. Nexus extracts the SHA-256 fingerprint of the leaf certificate (DER-encoded).
4. Fingerprint is stored in the Nexus SQLite: `satellites.tls_fingerprint`.
5. All subsequent connections use a custom TLS transport (`pinnedTLSTransport`) that:
   - Verifies the peer certificate fingerprint matches the stored value
   - Rejects any certificate that does not match — including valid CA-signed certs

### What This Protects Against

- MITM attacks after initial registration: even a certificate signed by a trusted CA will be rejected if it doesn't match the pinned fingerprint.
- Accidental connection to the wrong host: the fingerprint uniquely identifies the correct Satellite.

### What This Does Not Protect Against

- MITM during the initial registration (first contact). The operator must ensure the registration is done on a trusted network.
- If the Satellite cert is regenerated (e.g., cert files deleted), the Nexus will reject connections. Re-registration is required.

### Fingerprint Format

SHA-256 hex string, lowercase, no colons. Example:
```
a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2
```

Stored in `satellites.tls_fingerprint` (TEXT column).
