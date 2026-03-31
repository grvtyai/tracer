package sharphound

import (
	"context"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

type Plugin struct{}

var _ engine.Plugin = (*Plugin)(nil)

func (Plugin) Name() string {
	return "sharphound"
}

func (Plugin) CanRun(job jobs.Job) bool {
	return false
}

func (Plugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	return nil, nil
}
