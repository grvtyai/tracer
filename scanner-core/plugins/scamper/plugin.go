package scamper

import (
	"context"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

type Plugin struct{}

var _ engine.Plugin = (*Plugin)(nil)

func (Plugin) Name() string {
	return "scamper"
}

func (Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindRouteProbe
}

func (Plugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	return nil, nil
}
