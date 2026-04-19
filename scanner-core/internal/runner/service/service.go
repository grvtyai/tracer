// Package service defines the abstraction the Satellite API server depends on.
// Implementations live in sub-packages (stub, real). The apiserver package
// imports this to declare what it needs; it never imports a specific
// implementation.
package service

import (
	"context"
	"errors"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

// Service is what the apiserver calls into for every request. Methods return
// sentinel errors below (possibly wrapped) to signal semantic failure modes;
// the apiserver translates them to HTTP status codes.
type Service interface {
	Capabilities(ctx context.Context) (api.Capabilities, error)
	StartRun(ctx context.Context, req api.StartRunRequest) (api.StartRunResponse, error)
	ListRuns(ctx context.Context) (api.RunList, error)
	RunStatus(ctx context.Context, runID string) (api.RunStatus, error)
	RunEvidence(ctx context.Context, runID string) (api.EvidenceResponse, error)
	RunJobs(ctx context.Context, runID string) (api.JobsResponse, error)
	CancelRun(ctx context.Context, runID string) error

	// SubscribeEvents returns a channel that delivers events for the given run.
	// The channel is closed by the implementation when the run reaches a
	// terminal state or when ctx is cancelled. A run that is already finished
	// returns an open-then-immediately-closed channel (not an error).
	SubscribeEvents(ctx context.Context, runID string) (<-chan api.Event, error)
}

var (
	ErrNotFound      = errors.New("not found")
	ErrBadRequest    = errors.New("bad request")
	ErrUnavailable   = errors.New("unavailable")
	ErrConflict      = errors.New("conflict")
	ErrPluginMissing = errors.New("plugin missing")
)
