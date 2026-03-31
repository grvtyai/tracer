package arp_scan

import (
	"context"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

type Plugin struct{}

var _ engine.Plugin = (*Plugin)(nil)

func (Plugin) Name() string {
	return "arp-scan"
}

func (Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindL2Discover
}

func (Plugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	return nil, nil
}
