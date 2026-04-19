# Package: internal/runner/service

Defines the abstraction that the Satellite API server depends on. The `apiserver` package imports this interface; it never imports a specific implementation.

## Purpose

Decouples the HTTP transport layer from the scan execution logic. This allows:
- The real Radar implementation to be swapped for a stub in tests
- Future alternative backends without touching the API layer

## Service Interface

```go
type Service interface {
    Capabilities(ctx context.Context) (api.Capabilities, error)
    StartRun(ctx context.Context, req api.StartRunRequest) (api.StartRunResponse, error)
    ListRuns(ctx context.Context) (api.RunList, error)
    RunStatus(ctx context.Context, runID string) (api.RunStatus, error)
    RunEvidence(ctx context.Context, runID string) (api.EvidenceResponse, error)
    RunJobs(ctx context.Context, runID string) (api.JobsResponse, error)
    CancelRun(ctx context.Context, runID string) error
    SubscribeEvents(ctx context.Context, runID string) (<-chan api.Event, error)
}
```

### SubscribeEvents behavior
- Returns a channel that delivers `api.Event` values for the given run.
- The channel is closed by the implementation when the run reaches a terminal state or when `ctx` is cancelled.
- If the run is already finished at call time: returns an open channel that is immediately closed (not an error).

## Sentinel Errors

The apiserver translates these to HTTP status codes:

```go
var (
    ErrNotFound      = errors.New("not found")       // → 404
    ErrBadRequest    = errors.New("bad request")      // → 400
    ErrUnavailable   = errors.New("unavailable")      // → 503
    ErrConflict      = errors.New("conflict")         // → 409
    ErrPluginMissing = errors.New("plugin missing")   // → 400 with code plugin_missing
)
```

Implementations return these errors (possibly wrapped with `fmt.Errorf(...%w...)`) to signal semantic failure modes. The apiserver uses `errors.Is` to match them.

## Implementations

| Package | Description |
|---|---|
| `internal/runner/service/stub` | In-memory stub for contract testing |
| `internal/runner/service/radar` | Real implementation wrapping the Radar module |

## Location

`internal/runner/service/service.go`
