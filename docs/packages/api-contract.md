# Package: internal/api

Wire contract between Nexus and Satellite. Contains only data types — no transport, no handlers, no business logic.

Both `internal/runner/apiserver` (Satellite side) and `internal/controller/runnerclient` (Nexus side) import this package. It is the single source of truth for request/response shapes.

## Stability

Types in this package are part of the public wire contract. Renaming or removing a field is a breaking change for any deployed Satellite/Nexus pair running different versions.

## Current API Version

```go
const Version = "v1"
```

## Files

### version.go
```go
const Version = "v1"
```

### health.go
```go
type Health struct {
    Status      string    `json:"status"`
    Version     string    `json:"version"`
    APIVersion  string    `json:"api_version"`
    SatelliteID string    `json:"satellite_id"`
    StartedAt   time.Time `json:"started_at"`
}
// Status constants: HealthStatusOK, HealthStatusDegraded, HealthStatusError
```

### capabilities.go
```go
type Capabilities struct {
    SatelliteID string   `json:"satellite_id"`
    Version     string   `json:"version"`
    APIVersion  string   `json:"api_version"`
    Plugins     []Plugin `json:"plugins"`
}

type Plugin struct {
    Name      string   `json:"name"`
    Kinds     []string `json:"kinds"`
    Available bool     `json:"available"`
    Reason    string   `json:"reason,omitempty"`
    Version   string   `json:"version,omitempty"`
}
```

### runs.go
```go
// Run lifecycle state constants
const (
    RunStatePending   = "pending"
    RunStateRunning   = "running"
    RunStateCompleted = "completed"
    RunStateFailed    = "failed"
    RunStateCancelled = "cancelled"
)

// Job lifecycle state constants
const (
    JobStatePending   = "pending"
    JobStateRunning   = "running"
    JobStateSucceeded = "succeeded"
    JobStateFailed    = "failed"
    JobStateSkipped   = "skipped"
)

type StartRunRequest struct {
    ProjectID string            `json:"project_id"`
    Template  json.RawMessage   `json:"template"`
    Overrides map[string]string `json:"overrides,omitempty"`
}

type StartRunResponse struct {
    RunID      string    `json:"run_id"`
    AcceptedAt time.Time `json:"accepted_at"`
}

type RunList struct {
    Runs []RunListEntry `json:"runs"`
}

type RunListEntry struct {
    RunID      string     `json:"run_id"`
    ProjectID  string     `json:"project_id"`
    State      string     `json:"state"`
    StartedAt  time.Time  `json:"started_at"`
    FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type RunStatus struct {
    RunID      string      `json:"run_id"`
    ProjectID  string      `json:"project_id"`
    State      string      `json:"state"`
    StartedAt  time.Time   `json:"started_at"`
    FinishedAt *time.Time  `json:"finished_at,omitempty"`
    Jobs       []JobStatus `json:"jobs"`
    Summary    RunSummary  `json:"summary"`
}
```

### events.go
See `api/sse-events.md` for the full event type reference.

```go
const (
    EventTypeRunState  = "run.state"
    EventTypeJobState  = "job.state"
    EventTypeEvidence  = "evidence.new"
    EventTypeLog       = "log"
    EventTypeHeartbeat = "heartbeat"
)

type Event struct {
    Type      string          `json:"type"`
    Timestamp time.Time       `json:"timestamp"`
    RunID     string          `json:"run_id"`
    Payload   json.RawMessage `json:"payload"`
}
```

### errors.go
```go
// Error code constants
const (
    ErrorCodeBadRequest     = "bad_request"
    ErrorCodeUnauthorized   = "unauthorized"
    ErrorCodeForbidden      = "forbidden"
    ErrorCodeNotFound       = "not_found"
    ErrorCodeConflict       = "conflict"
    ErrorCodeUnavailable    = "unavailable"
    ErrorCodeInternal       = "internal"
    ErrorCodePluginMissing  = "plugin_missing"
    ErrorCodeInvalidRequest = "invalid_request"
)

type ErrorResponse struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Detail  string `json:"detail,omitempty"`
}
```
