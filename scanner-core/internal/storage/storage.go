package storage

import (
	"context"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
)

// EvidenceStore persists normalized findings independently from plugin execution.
type EvidenceStore interface {
	WriteEvidence(ctx context.Context, records []evidence.Record) error
}
