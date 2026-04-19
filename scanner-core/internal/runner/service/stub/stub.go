// Package stub provides an in-memory Service implementation that fakes scan
// runs. It exists so the Satellite binary and API contract can be exercised
// end-to-end before the real Radar backend is wired in.
package stub

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service"
)

type Service struct {
	satelliteID string
	version     string

	mu   sync.Mutex
	runs map[string]*stubRun
}

type stubRun struct {
	id         string
	projectID  string
	state      string
	startedAt  time.Time
	finishedAt *time.Time
	subs       []chan api.Event
	done       chan struct{}
}

func New(satelliteID, version string) *Service {
	return &Service{
		satelliteID: satelliteID,
		version:     version,
		runs:        make(map[string]*stubRun),
	}
}

func (s *Service) Capabilities(ctx context.Context) (api.Capabilities, error) {
	return api.Capabilities{
		SatelliteID: s.satelliteID,
		Version:     s.version,
		APIVersion:  api.Version,
		Plugins: []api.Plugin{
			{
				Name:      "stub-scanner",
				Kinds:     []string{"port_discover"},
				Available: true,
				Version:   "0.0.0",
			},
		},
	}, nil
}

func (s *Service) StartRun(ctx context.Context, req api.StartRunRequest) (api.StartRunResponse, error) {
	runID := uuid.NewString()
	now := time.Now().UTC()
	run := &stubRun{
		id:        runID,
		projectID: req.ProjectID,
		state:     api.RunStatePending,
		startedAt: now,
		done:      make(chan struct{}),
	}
	s.mu.Lock()
	s.runs[runID] = run
	s.mu.Unlock()

	go s.simulateRun(run)

	return api.StartRunResponse{
		RunID:      runID,
		AcceptedAt: now,
	}, nil
}

// simulateRun walks the run through pending → running → completed over a
// couple of seconds, broadcasting state events so event subscribers see
// something move.
func (s *Service) simulateRun(run *stubRun) {
	time.Sleep(200 * time.Millisecond)
	s.setState(run, api.RunStateRunning)

	time.Sleep(1500 * time.Millisecond)
	s.setState(run, api.RunStateCompleted)
	s.closeSubs(run)
	close(run.done)
}

func (s *Service) setState(run *stubRun, state string) {
	s.mu.Lock()
	run.state = state
	if state == api.RunStateCompleted || state == api.RunStateFailed || state == api.RunStateCancelled {
		t := time.Now().UTC()
		run.finishedAt = &t
	}
	subs := append([]chan api.Event(nil), run.subs...)
	s.mu.Unlock()

	ev := api.Event{
		Type:      api.EventTypeRunState,
		Timestamp: time.Now().UTC(),
		RunID:     run.id,
		Payload:   mustJSON(api.RunStatePayload{State: state}),
	}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Service) closeSubs(run *stubRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range run.subs {
		close(ch)
	}
	run.subs = nil
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
		Jobs:       []api.JobStatus{},
		Summary:    api.RunSummary{},
	}, nil
}

func (s *Service) RunEvidence(ctx context.Context, runID string) (api.EvidenceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[runID]; !ok {
		return api.EvidenceResponse{}, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}
	return api.EvidenceResponse{
		RunID:   runID,
		Count:   0,
		Records: json.RawMessage("[]"),
	}, nil
}

func (s *Service) RunJobs(ctx context.Context, runID string) (api.JobsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[runID]; !ok {
		return api.JobsResponse{}, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}
	return api.JobsResponse{
		RunID: runID,
		Jobs:  []api.JobDetail{},
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
	s.setState(r, api.RunStateCancelled)
	s.closeSubs(r)
	return nil
}

func (s *Service) SubscribeEvents(ctx context.Context, runID string) (<-chan api.Event, error) {
	s.mu.Lock()
	r, ok := s.runs[runID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: run %s", service.ErrNotFound, runID)
	}
	ch := make(chan api.Event, 16)
	if r.state == api.RunStateCompleted || r.state == api.RunStateFailed || r.state == api.RunStateCancelled {
		s.mu.Unlock()
		close(ch)
		return ch, nil
	}
	r.subs = append(r.subs, ch)
	s.mu.Unlock()
	return ch, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
