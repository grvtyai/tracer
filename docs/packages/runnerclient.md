# Package: internal/controller/runnerclient

The Nexus-side HTTP client for the Satellite API. It is the only place in the Nexus that knows how the wire format is serialized. The rest of the Nexus works with typed `api.*` values returned from this client.

## Location

`internal/controller/runnerclient/client.go`

## Config

```go
type Config struct {
    BaseURL        string       // e.g. "https://192.168.1.10:8765"
    AuthToken      string       // Bearer token
    TLSFingerprint string       // SHA-256 hex fingerprint; empty = no pinning
    HTTPClient     *http.Client // optional override (e.g. for tests)
}
```

When `TLSFingerprint` is set, the client builds a custom `http.Transport` (`pinnedTLSTransport`) that:
- Sets `InsecureSkipVerify: true` (bypasses CA chain validation)
- Adds a `VerifyConnection` hook that checks the peer's leaf cert SHA-256 against the stored fingerprint
- Rejects any cert that doesn't match — including valid CA-signed certs

When `TLSFingerprint` is empty, the client uses a plain `http.Client` with a 30-second timeout (no cert pinning). This is only used during the initial TOFU probe.

## Methods

All methods accept a `context.Context` for cancellation/timeout.

```go
func (c *Client) Health(ctx context.Context) (api.Health, error)
func (c *Client) Capabilities(ctx context.Context) (api.Capabilities, error)
func (c *Client) StartRun(ctx context.Context, req api.StartRunRequest) (api.StartRunResponse, error)
func (c *Client) ListRuns(ctx context.Context) (api.RunList, error)
func (c *Client) RunStatus(ctx context.Context, runID string) (api.RunStatus, error)
func (c *Client) RunEvidence(ctx context.Context, runID string) (api.EvidenceResponse, error)
func (c *Client) RunJobs(ctx context.Context, runID string) (api.JobsResponse, error)
func (c *Client) CancelRun(ctx context.Context, runID string) error
func (c *Client) StreamEvents(ctx context.Context, runID string, handler func(api.Event) error) error
```

## Error Types

On HTTP 4xx/5xx, the client returns `*APIError`:

```go
type APIError struct {
    StatusCode int
    Code       string
    Message    string
    Detail     string
}
```

The Nexus uses `errors.As(err, &apiErr)` and matches on `apiErr.Code` for programmatic handling (e.g., display a re-auth prompt on `unauthorized`).

## StreamEvents

`StreamEvents` connects to `GET /runs/{id}/events` and reads the SSE stream:
- Parses each `data:` line as `api.Event`
- Calls `handler(event)` for each event
- Returns when the stream closes (run finished) or `ctx` is cancelled
- The default HTTP client timeout is removed for stream connections (long-lived)

## TOFU Probe (Registration)

During satellite registration in the Nexus UI, the handler:
1. Creates a `runnerclient` with no `TLSFingerprint` (first contact, InsecureSkipVerify)
2. Calls `Health()` — this establishes the TLS connection
3. Extracts the leaf cert fingerprint from the TLS connection state
4. Stores the fingerprint in `satellites.tls_fingerprint`
5. Subsequent clients for that satellite always set `TLSFingerprint`
