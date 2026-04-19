package radar

import (
	"context"
	"encoding/json"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/options"
	"github.com/grvtyai/startrace/scanner-core/internal/templates"
)

// runState is the in-memory bookkeeping for one run. All fields are guarded
// by Service.mu except done and cancel, which are created once and not
// mutated after construction.
type runState struct {
	id        string
	projectID string
	template  templates.Template
	effective options.EffectiveOptions

	state      string
	startedAt  time.Time
	finishedAt *time.Time
	errorMsg   string

	plan       []jobs.Job
	jobResults []jobs.ExecutionResult
	evidence   []evidence.Record

	subs []chan api.Event

	cancel context.CancelFunc
	done   chan struct{}
}

// setState updates the run's state and broadcasts a run.state event to all
// current subscribers. Non-blocking send: slow subscribers miss events rather
// than stalling the run.
func (s *Service) setState(run *runState, state, errMsg string) {
	s.mu.Lock()
	run.state = state
	run.errorMsg = errMsg
	subs := append([]chan api.Event(nil), run.subs...)
	s.mu.Unlock()

	ev := api.Event{
		Type:      api.EventTypeRunState,
		Timestamp: time.Now().UTC(),
		RunID:     run.id,
		Payload:   mustJSON(api.RunStatePayload{State: state, Error: errMsg}),
	}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Service) emitEvidence(run *runState, rec evidence.Record) {
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return
	}

	s.mu.Lock()
	subs := append([]chan api.Event(nil), run.subs...)
	s.mu.Unlock()

	ev := api.Event{
		Type:      api.EventTypeEvidence,
		Timestamp: time.Now().UTC(),
		RunID:     run.id,
		Payload:   mustJSON(api.EvidencePayload{Record: recJSON}),
	}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Service) closeSubs(run *runState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range run.subs {
		close(ch)
	}
	run.subs = nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
