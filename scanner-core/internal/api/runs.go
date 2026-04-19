package api

import (
	"encoding/json"
	"time"
)

// Run lifecycle states as seen over the wire.
const (
	RunStatePending   = "pending"
	RunStateRunning   = "running"
	RunStateCompleted = "completed"
	RunStateFailed    = "failed"
	RunStateCancelled = "cancelled"
)

// Job lifecycle states as seen over the wire.
const (
	JobStatePending   = "pending"
	JobStateRunning   = "running"
	JobStateSucceeded = "succeeded"
	JobStateFailed    = "failed"
	JobStateSkipped   = "skipped"
)

// StartRunRequest is the body for POST /runs.
//
// Template is intentionally json.RawMessage for now: the template schema lives
// inside the Radar module and is still evolving. The Satellite parses it with
// its own loader. Once the schema stabilizes, this should become a typed field.
type StartRunRequest struct {
	ProjectID string            `json:"project_id"`
	Template  json.RawMessage   `json:"template"`
	Overrides map[string]string `json:"overrides,omitempty"`
}

// StartRunResponse is returned from POST /runs. The run is accepted
// asynchronously — the caller must poll status or subscribe to events.
type StartRunResponse struct {
	RunID      string    `json:"run_id"`
	AcceptedAt time.Time `json:"accepted_at"`
}

// RunList is the response body for GET /runs.
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

// RunStatus is the response body for GET /runs/{id}/status.
type RunStatus struct {
	RunID      string      `json:"run_id"`
	ProjectID  string      `json:"project_id"`
	State      string      `json:"state"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
	Jobs       []JobStatus `json:"jobs"`
	Summary    RunSummary  `json:"summary"`
}

type JobStatus struct {
	JobID      string     `json:"job_id"`
	Kind       string     `json:"kind"`
	Plugin     string     `json:"plugin"`
	State      string     `json:"state"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

type RunSummary struct {
	TotalJobs     int `json:"total_jobs"`
	CompletedJobs int `json:"completed_jobs"`
	FailedJobs    int `json:"failed_jobs"`
	EvidenceCount int `json:"evidence_count"`
}

// EvidenceResponse is the response body for GET /runs/{id}/evidence.
//
// Records is json.RawMessage during the API contract phase to avoid coupling
// the wire format to the internal evidence.Record type while it may still
// change. A later pass will replace this with a typed slice.
type EvidenceResponse struct {
	RunID   string          `json:"run_id"`
	Count   int             `json:"count"`
	Records json.RawMessage `json:"records"`
}

// JobsResponse is the response body for GET /runs/{id}/jobs. It returns the
// full job plan plus execution outcome per job.
type JobsResponse struct {
	RunID string      `json:"run_id"`
	Jobs  []JobDetail `json:"jobs"`
}

type JobDetail struct {
	JobStatus
	DependsOn    []string          `json:"depends_on,omitempty"`
	Targets      []string          `json:"targets,omitempty"`
	Ports        []int             `json:"ports,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	RecordsCount int               `json:"records_count"`
}
