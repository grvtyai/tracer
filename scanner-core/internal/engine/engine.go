package engine

import (
	"context"
	"fmt"

	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
)

// Engine dispatches jobs to matching plugins and stores normalized evidence.
type Engine struct {
	plugins []Plugin
	store   storage.EvidenceStore
}

func New(plugins []Plugin, store storage.EvidenceStore) *Engine {
	return &Engine{
		plugins: plugins,
		store:   store,
	}
}

func (e *Engine) Run(ctx context.Context, plan []jobs.Job) error {
	for _, job := range plan {
		handled := false

		for _, plugin := range e.plugins {
			if job.Plugin != "" && plugin.Name() != job.Plugin {
				continue
			}

			if !plugin.CanRun(job) {
				continue
			}

			records, err := plugin.Run(ctx, job)
			if err != nil {
				return fmt.Errorf("%s failed for job %s: %w", plugin.Name(), job.ID, err)
			}

			if len(records) > 0 && e.store != nil {
				if err := e.store.WriteEvidence(ctx, records); err != nil {
					return fmt.Errorf("write evidence for job %s: %w", job.ID, err)
				}
			}

			handled = true
			break
		}

		if !handled {
			return fmt.Errorf("no plugin registered for job %s (%s)", job.ID, job.Kind)
		}
	}

	return nil
}
