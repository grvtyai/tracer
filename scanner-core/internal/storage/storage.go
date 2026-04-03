package storage

import (
	"context"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

// EvidenceStore persists normalized findings independently from plugin execution.
type EvidenceStore interface {
	WriteEvidence(ctx context.Context, records []evidence.Record) error
}

type JobResultStore interface {
	WriteJobResults(ctx context.Context, results []jobs.ExecutionResult) error
}
