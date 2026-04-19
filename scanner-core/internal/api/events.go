package api

import (
	"encoding/json"
	"time"
)

// Event types emitted on GET /runs/{id}/events (Server-Sent Events stream).
const (
	EventTypeRunState   = "run.state"
	EventTypeJobState   = "job.state"
	EventTypeEvidence   = "evidence.new"
	EventTypeLog        = "log"
	EventTypeHeartbeat  = "heartbeat"
)

// Event is the envelope delivered as one SSE message. Payload is typed by
// Type; consumers switch on Type and unmarshal Payload into the matching
// struct below.
type Event struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	RunID     string          `json:"run_id"`
	Payload   json.RawMessage `json:"payload"`
}

// RunStatePayload accompanies EventTypeRunState.
type RunStatePayload struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// JobStatePayload accompanies EventTypeJobState.
type JobStatePayload struct {
	JobID  string `json:"job_id"`
	Kind   string `json:"kind"`
	Plugin string `json:"plugin"`
	State  string `json:"state"`
	Error  string `json:"error,omitempty"`
}

// EvidencePayload accompanies EventTypeEvidence. The nested Record is
// json.RawMessage during the contract phase — same reasoning as in runs.go.
type EvidencePayload struct {
	JobID  string          `json:"job_id"`
	Record json.RawMessage `json:"record"`
}

// LogPayload accompanies EventTypeLog. Used for operator-visible progress
// messages that don't fit into the other event types (e.g. tool stdout lines
// worth surfacing).
type LogPayload struct {
	JobID   string `json:"job_id,omitempty"`
	Level   string `json:"level"`
	Message string `json:"message"`
}
