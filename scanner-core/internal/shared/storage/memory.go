package storage

import (
	"context"
	"sync"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

// MemoryStore is a small bootstrap implementation for early development and tests.
type MemoryStore struct {
	mu      sync.Mutex
	records []evidence.Record
	results []jobs.ExecutionResult
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

func (s *MemoryStore) WriteJobResults(_ context.Context, results []jobs.ExecutionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.results = append(s.results, results...)
	return nil
}

func (s *MemoryStore) JobResults() []jobs.ExecutionResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	cloned := make([]jobs.ExecutionResult, len(s.results))
	copy(cloned, s.results)
	return cloned
}
