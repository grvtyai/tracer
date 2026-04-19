# Token Model

## Purpose

The Bearer token is the primary authentication mechanism between Nexus and Satellite. It proves that the Nexus request was issued by a trusted operator, not an unauthorized party.

## Token Generation

There is no enforced format. The operator generates a token before starting the Satellite:

```bash
openssl rand -hex 32
# → 64-char hex string, ~256 bits entropy
```

Or any equivalent method (Python secrets, /dev/urandom, password manager generator).

## Token Lifecycle

1. **Operator generates** a token (before first Satellite start).
2. **Satellite** receives the token via environment variable on startup.
3. **Nexus UI** — operator enters the token once during satellite registration.
4. **Nexus** stores a partial hint (first/last chars) in `satellites.registration_token_hint` for display purposes only. The full token is not stored in the Nexus DB.
5. **Nexus** passes the full token to `runnerclient.Config.AuthToken` for each API call.

## Token Storage on Satellite

The Satellite reads the token from the environment variable at startup and holds it in memory. It is never written to disk by the Satellite.

Default environment variable: `STARTRACE_SATELLITE_TOKEN`
Configurable via: `-token-env` flag

## Token Comparison (Satellite)

Source: `internal/runner/apiserver/middleware.go`

```go
subtle.ConstantTimeCompare([]byte(incomingToken), []byte(configuredToken)) == 1
```

`crypto/subtle.ConstantTimeCompare` is used to prevent timing-based attacks that could allow an attacker to guess the token byte-by-byte by measuring response time differences.

## Token on Each Request

The Nexus includes the token on every API call:
```
Authorization: Bearer <token>
```

The Satellite middleware checks this header before any handler logic runs. Missing or incorrect token → `401 Unauthorized`.

## Token Scope

One token per Satellite. If multiple Satellites are deployed, each gets its own independently generated token.

There is currently no token rotation mechanism. Token rotation requires:
1. Restart the Satellite with a new token value.
2. Update the Nexus registration (re-register or update the stored token).

## What the Token Does NOT Protect

- The token does not expire automatically.
- The token does not scope access (no per-project or per-operation permissions).
- The token is not hashed before in-memory storage.

These are acceptable trade-offs for a local operator tool. For internet-exposed deployments, additional hardening (network-level access control, token rotation policy) is recommended.
