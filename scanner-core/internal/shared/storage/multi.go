package storage

import (
	"context"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

type MultiStore struct {
	stores []EvidenceStore
}

func NewMultiStore(stores ...EvidenceStore) *MultiStore {
	filtered := make([]EvidenceStore, 0, len(stores))
	for _, store := range stores {
		if store == nil {
			continue
		}
		filtered = append(filtered, store)
	}

	return &MultiStore{stores: filtered}
}

func (s *MultiStore) WriteEvidence(ctx context.Context, records []evidence.Record) error {
	for _, store := range s.stores {
		if err := store.WriteEvidence(ctx, records); err != nil {
			return err
		}
	}

	return nil
}

func (s *MultiStore) WriteJobResults(ctx context.Context, results []jobs.ExecutionResult) error {
	for _, store := range s.stores {
		jobStore, ok := store.(JobResultStore)
		if !ok {
			continue
		}
		if err := jobStore.WriteJobResults(ctx, results); err != nil {
			return err
		}
	}

	return nil
}
