package engine

import (
	"context"
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
)

type fakePlugin struct {
	name    string
	records []evidence.Record
}

func (p fakePlugin) Name() string {
	return p.name
}

func (p fakePlugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindPortDiscover
}

func (p fakePlugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	return p.records, nil
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

	err := engine.Run(context.Background(), []jobs.Job{
		{
			ID:      "port-discovery",
			Kind:    jobs.KindPortDiscover,
			Plugin:  "wanted",
			Targets: []string{"10.0.0.2"},
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	records := store.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].Source != "wanted" {
		t.Fatalf("expected plugin 'wanted', got %q", records[0].Source)
	}
}
