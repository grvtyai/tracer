// Package radar is the production Service implementation for the Satellite.
// It wraps the existing internal/modules/radar/runtime code, which owns the
// real scan pipeline and scanner integrations.
//
// Scope of this package (what it does): translate the wire contract (api.*
// types) into runtime calls, track run state, and broadcast lifecycle events
// to subscribers.
//
// Out of scope for now: persistent storage (runs live only in memory),
// streaming evidence events during execution (the runtime batches them at
// the end), and parsing structured overrides from the string map. These are
// deliberate simplifications for v1 that are listed in the migration plan.
package radar

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/engine"
	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	radarruntime "github.com/grvtyai/startrace/scanner-core/internal/modules/radar/runtime"
	"github.com/grvtyai/startrace/scanner-core/internal/options"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service"
	"github.com/grvtyai/startrace/scanner-core/internal/templates"
)

type Config struct {
	SatelliteID string
	Version     string

	// Plugins is the list of engine.Plugin instances the runtime will dispatch
	// to. When nil, radarruntime.DefaultPlugins() is used. Tests inject
	// lightweight mocks to avoid needing real scanner binaries.
	Plugins []engine.Plugin

	Logger *slog.Logger
}

type Service struct {
	cfg     Config
	plugins []engine.Plugin
	logger  *slog.Logger

	mu   sync.Mutex
	runs map[string]*runState
}

func New(cfg Config) *Service {
	plugins := cfg.Plugins
	if plugins == nil {
		plugins = radarruntime.DefaultPlugins()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:     cfg,
		plugins: plugins,
		logger:  logger,
		runs:    make(map[string]*runState),
	}
}

// Capabilities advertises every plugin the runtime knows about, with a
// best-effort check for whether its required binary is installed.
func (s *Service) Capabilities(ctx context.Context) (api.Capabilities, error) {
	plugins := make([]api.Plugin, 0, len(s.plugins))
	for _, p := range s.plugins {
		plugins = append(plugins, buildPluginInfo(p))
	}
	return api.Capabilities{
		SatelliteID: s.cfg.SatelliteID,
		Version:     s.cfg.Version,
		APIVersion:  api.Version,
		Plugins:     plugins,
	}, nil
}

func (s *Service) StartRun(ctx context.Context, req api.StartRunRequest) (api.StartRunResponse, error) {
	if len(req.Template) == 0 {
		return api.StartRunResponse{}, fmt.Errorf("%w: template is required", service.ErrBadRequest)
	}

	var tmpl templates.Template
	if err := json.Unmarshal(req.Template, &tmpl); err != nil {
		return api.StartRunResponse{}, fmt.Errorf("%w: parse template: %v", service.ErrBadRequest, err)
	}

	// Overrides are a map[string]string on the wire for forward-compat. The
	// existing runtime takes a strongly-typed options.TemplateOptions. For v1
	// we pass empty overrides — the template's embedded options win. Parsing
	// overrides into the struct is a follow-up task.
	effective := radarruntime.ResolveOptions(tmpl, options.TemplateOptions{})

	runID := uuid.NewString()
	now := time.Now().UTC()

	// The run outlives this HTTP request, so we give it its own context that
	// only CancelRun can cancel.
	runCtx, cancel := context.WithCancel(context.Background())

	run := &runState{
		id:        runID,
		projectID: req.ProjectID,
		template:  tmpl,
		effective: effective,
		state:     api.RunStatePending,
		startedAt: now,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	s.mu.Lock()
	s.runs[runID] = run
	s.mu.Unlock()

	go s.executeRun(runCtx, run)

	return api.StartRunResponse{
		RunID:      runID,
		AcceptedAt: now,
	}, nil
}

// executeRun drives a run through its lifecycle and broadcasts state events.
// Evidence records produced by the runtime are emitted as events after
// execution completes (the runtime does not stream them).
func (s *Service) executeRun(ctx context.Context, run *runState) {
	defer close(run.done)
	defer run.cancel()

	s.setState(run, api.RunStateRunning, "")
	s.logger.Info("radar run started", "run_id", run.id, "project_id", run.projectID)

	plan, jobResults, records, err := radarruntime.ExecuteRunWithPersistence(
		ctx, s.plugins, run.template, run.effective, nil,
	)

	finishedAt := time.Now().UTC()
	s.mu.Lock()
	run.plan = plan
	run.jobResults = jobResults
	run.evidence = records
	run.finishedAt = &finishedAt
	s.mu.Unlock()

	finalState := api.RunStateCompleted
	errMsg := ""
	switch {
	case err != nil:
		finalState = api.RunStateFailed
		errMsg = err.Error()
	case ctx.Err() != nil:
		finalState = api.RunStateCancelled
	}

	for _, rec := range records {
		s.emitEvidence(run, rec)
	}

	s.setState(run, finalState, errMsg)
	s.closeSubs(run)
	s.logger.Info("radar run finished",
		"run_id", run.id,
		"state", finalState,
		"jobs", len(jobResults),
		"evidence", len(records),
	)
}

func (s *Service) ListRuns(ctx context.Context) (api.RunList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := make([]api.RunListEntry, 0, len(s.runs))
	for _, r := range s.runs {
		entries = append(entries, api.RunListEntry{
			RunID:      r.id,
			ProjectID:  r.projectID,
			State:      r.state,
			StartedAt:  r.startedAt,
			FinishedAt: r.finishedAt,
		})
	}
	return api.RunList{Runs: entries}, nil
}

func (s *Service) RunStatus(ctx context.Context, runID string) (api.RunStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.runs[runID]
	if !ok {
		return api.RunStatus{}, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}

	return api.RunStatus{
		RunID:      r.id,
		ProjectID:  r.projectID,
		State:      r.state,
		StartedAt:  r.startedAt,
		FinishedAt: r.finishedAt,
		Jobs:       jobStatusesFromResults(r.plan, r.jobResults),
		Summary:    summarize(r.jobResults, len(r.evidence)),
	}, nil
}

func (s *Service) RunEvidence(ctx context.Context, runID string) (api.EvidenceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.runs[runID]
	if !ok {
		return api.EvidenceResponse{}, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}

	records := r.evidence
	if records == nil {
		records = []evidence.Record{}
	}
	raw, err := json.Marshal(records)
	if err != nil {
		return api.EvidenceResponse{}, fmt.Errorf("marshal evidence: %w", err)
	}
	return api.EvidenceResponse{
		RunID:   runID,
		Count:   len(records),
		Records: raw,
	}, nil
}

func (s *Service) RunJobs(ctx context.Context, runID string) (api.JobsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.runs[runID]
	if !ok {
		return api.JobsResponse{}, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}

	return api.JobsResponse{
		RunID: runID,
		Jobs:  jobDetailsFromResults(r.plan, r.jobResults),
	}, nil
}

func (s *Service) CancelRun(ctx context.Context, runID string) error {
	s.mu.Lock()
	r, ok := s.runs[runID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}
	if r.state == api.RunStateCompleted || r.state == api.RunStateFailed || r.state == api.RunStateCancelled {
		s.mu.Unlock()
		return fmt.Errorf("%w: run already finished", service.ErrConflict)
	}
	s.mu.Unlock()

	// Signal cancellation; executeRun observes ctx.Err() and sets state.
	r.cancel()
	return nil
}

func (s *Service) SubscribeEvents(ctx context.Context, runID string) (<-chan api.Event, error) {
	s.mu.Lock()
	r, ok := s.runs[runID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}

	ch := make(chan api.Event, 64)
	if r.state == api.RunStateCompleted || r.state == api.RunStateFailed || r.state == api.RunStateCancelled {
		s.mu.Unlock()
		close(ch)
		return ch, nil
	}
	r.subs = append(r.subs, ch)
	s.mu.Unlock()
	return ch, nil
}

func jobStatusesFromResults(plan []jobs.Job, results []jobs.ExecutionResult) []api.JobStatus {
	resultByID := make(map[string]jobs.ExecutionResult, len(results))
	for _, r := range results {
		resultByID[r.JobID] = r
	}

	out := make([]api.JobStatus, 0, len(plan))
	for _, j := range plan {
		js := api.JobStatus{
			JobID:  j.ID,
			Kind:   string(j.Kind),
			Plugin: j.Plugin,
			State:  api.JobStatePending,
		}
		if r, ok := resultByID[j.ID]; ok {
			js.State = translateJobState(r.Status)
			js.Error = r.Error
			if !r.StartedAt.IsZero() {
				started := r.StartedAt
				js.StartedAt = &started
			}
			if !r.FinishedAt.IsZero() {
				finished := r.FinishedAt
				js.FinishedAt = &finished
			}
		}
		out = append(out, js)
	}
	return out
}

func jobDetailsFromResults(plan []jobs.Job, results []jobs.ExecutionResult) []api.JobDetail {
	resultByID := make(map[string]jobs.ExecutionResult, len(results))
	for _, r := range results {
		resultByID[r.JobID] = r
	}

	out := make([]api.JobDetail, 0, len(plan))
	for _, j := range plan {
		detail := api.JobDetail{
			JobStatus: api.JobStatus{
				JobID:  j.ID,
				Kind:   string(j.Kind),
				Plugin: j.Plugin,
				State:  api.JobStatePending,
			},
			DependsOn: j.DependsOn,
			Targets:   j.Targets,
			Ports:     j.Ports,
			Metadata:  j.Metadata,
		}
		if r, ok := resultByID[j.ID]; ok {
			detail.State = translateJobState(r.Status)
			detail.Error = r.Error
			detail.RecordsCount = r.RecordsWritten
			if !r.StartedAt.IsZero() {
				started := r.StartedAt
				detail.StartedAt = &started
			}
			if !r.FinishedAt.IsZero() {
				finished := r.FinishedAt
				detail.FinishedAt = &finished
			}
		}
		out = append(out, detail)
	}
	return out
}

func translateJobState(s jobs.ExecutionStatus) string {
	switch s {
	case jobs.StatusSucceeded:
		return api.JobStateSucceeded
	case jobs.StatusFailed:
		return api.JobStateFailed
	case jobs.StatusSkipped:
		return api.JobStateSkipped
	default:
		return api.JobStatePending
	}
}

func summarize(results []jobs.ExecutionResult, evidenceCount int) api.RunSummary {
	s := api.RunSummary{
		TotalJobs:     len(results),
		EvidenceCount: evidenceCount,
	}
	for _, r := range results {
		switch r.Status {
		case jobs.StatusSucceeded:
			s.CompletedJobs++
		case jobs.StatusFailed:
			s.FailedJobs++
		}
	}
	return s
}
