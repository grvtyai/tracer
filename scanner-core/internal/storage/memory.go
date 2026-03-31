package storage

import (
	"context"
	"sync"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
)

// MemoryStore is a small bootstrap implementation for early development and tests.
type MemoryStore struct {
	mu      sync.Mutex
	records []evidence.Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) WriteEvidence(_ context.Context, records []evidence.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, records...)
	return nil
}

func (s *MemoryStore) Records() []evidence.Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	cloned := make([]evidence.Record, len(s.records))
	copy(cloned, s.records)
	return cloned
}
