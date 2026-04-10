package engine

import (
	"context"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

// Plugin is the execution contract for every external scanner integration.
type Plugin interface {
	Name() string
	CanRun(job jobs.Job) bool
	Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error)
}
