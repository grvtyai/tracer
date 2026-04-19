# Package: internal/runner/apiserver

The HTTP server that runs inside the Satellite. It implements the REST+SSE API defined in `internal/api` and delegates all business logic to a `service.Service` implementation.

## Files

| File | Role |
|---|---|
| `server.go` | `Config` struct, `New()`, `Start()` (ListenAndServeTLS) |
| `routes.go` | Route registration, maps HTTP paths to handlers |
| `handlers.go` | One handler function per endpoint |
| `middleware.go` | Bearer token authentication middleware |
| `sse.go` | SSE stream writer helper |
| `errors.go` | `api.ErrorResponse` writer, sentinel → HTTP status mapping |
| `selfcert.go` | Self-signed ECDSA P-256 cert generator |
| `server_test.go` | Contract tests against the stub service |

## Config

```go
type Config struct {
    ListenAddr  string       // default "0.0.0.0:8765"
    AuthToken   string       // required; compared constant-time
    SatelliteID string       // UUID identifying this satellite
    Version     string       // binary version string
    Logger      *slog.Logger // required
    TLSCertFile string       // path to cert PEM file
    TLSKeyFile  string       // path to key PEM file
}
```

## Auth Middleware

All routes except `GET /health` pass through `requireBearer` middleware:
- Reads `Authorization: Bearer <token>` header
- Compares with configured token using `crypto/subtle.ConstantTimeCompare`
- Returns `401 Unauthorized` on mismatch or missing header

## SSE Streaming

`GET /runs/{id}/events` upgrades the response to a streaming connection:
- Sets `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`
- Calls `service.SubscribeEvents` to get a `<-chan api.Event` channel
- Encodes each event as JSON, writes as SSE `data:` line
- Sends periodic heartbeat events to prevent proxy timeouts
- Flushes after each event (requires `http.Flusher`)

## TLS

The server calls `http.ListenAndServeTLS(addr, certFile, keyFile, mux)`.

Before `New()` is called, the binary calls `apiserver.GenerateSelfSignedCert(certFile, keyFile)`:
- If both files already exist: no-op (reuses existing cert)
- If either is missing: generates a new ECDSA P-256 self-signed cert valid for 10 years

## Error Handling

All handlers return structured `api.ErrorResponse` JSON on failure. The `writeError` helper maps `service` sentinel errors to HTTP status codes:
- `service.ErrNotFound` → 404
- `service.ErrBadRequest` / `service.ErrPluginMissing` → 400
- `service.ErrConflict` → 409
- `service.ErrUnavailable` → 503
- other → 500
