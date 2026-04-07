package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/storage"
)

type fakePlugin struct {
	name    string
	records []evidence.Record
	err     error
}

func (p fakePlugin) Name() string {
	return p.name
}

func (p fakePlugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindPortDiscover
}

func (p fakePlugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	return p.records, p.err
}

func TestEngineMatchesExplicitPluginName(t *testing.T) {
	store := storage.NewMemoryStore()
	engine := New([]Plugin{
		fakePlugin{
			name: "wrong",
			records: []evidence.Record{
				{
					ID:         "wrong-record",
					Source:     "wrong",
					Kind:       "open_port",
					Target:     "10.0.0.1",
					Port:       80,
					Protocol:   "tcp",
					Summary:    "wrong plugin",
					Confidence: evidence.ConfidenceConfirmed,
					ObservedAt: time.Now().UTC(),
				},
			},
		},
		fakePlugin{
			name: "wanted",
			records: []evidence.Record{
				{
					ID:         "wanted-record",
					Source:     "wanted",
					Kind:       "open_port",
					Target:     "10.0.0.2",
					Port:       443,
					Protocol:   "tcp",
					Summary:    "wanted plugin",
					Confidence: evidence.ConfidenceConfirmed,
					ObservedAt: time.Now().UTC(),
				},
			},
		},
	}, store)

	results := engine.Run(context.Background(), []jobs.Job{
		{
			ID:      "port-discovery",
			Kind:    jobs.KindPortDiscover,
			Plugin:  "wanted",
			Targets: []string{"10.0.0.2"},
		},
	}, DefaultRunOptions())

	records := store.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].Source != "wanted" {
		t.Fatalf("expected plugin 'wanted', got %q", records[0].Source)
	}
	if len(results) != 1 || results[0].Status != jobs.StatusSucceeded {
		t.Fatalf("expected succeeded job result, got %#v", results)
	}
}

func TestEngineContinuesAfterPluginFailureWhenConfigured(t *testing.T) {
	store := storage.NewMemoryStore()
	engine := New([]Plugin{
		fakePlugin{name: "bad", err: errors.New("boom")},
		fakePlugin{name: "good", records: []evidence.Record{{
			ID:         "good-record",
			Source:     "good",
			Kind:       "open_port",
			Target:     "10.0.0.2",
			Port:       443,
			Protocol:   "tcp",
			Summary:    "good plugin",
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: time.Now().UTC(),
		}}},
	}, store)

	results := engine.Run(context.Background(), []jobs.Job{
		{ID: "first", Kind: jobs.KindPortDiscover, Plugin: "bad", Targets: []string{"10.0.0.1"}},
		{ID: "second", Kind: jobs.KindPortDiscover, Plugin: "good", Targets: []string{"10.0.0.2"}},
	}, DefaultRunOptions())

	if len(results) != 2 {
		t.Fatalf("expected 2 job results, got %d", len(results))
	}
	if results[0].Status != jobs.StatusFailed || !results[0].NeedsReevaluation {
		t.Fatalf("expected failed reevaluable first result, got %#v", results[0])
	}
	if results[1].Status != jobs.StatusSucceeded {
		t.Fatalf("expected second result to succeed, got %#v", results[1])
	}

	records := store.Records()
	if len(records) != 1 || records[0].Source != "good" {
		t.Fatalf("expected second plugin evidence to be retained, got %#v", records)
	}
}
