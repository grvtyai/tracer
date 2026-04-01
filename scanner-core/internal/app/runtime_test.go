package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/templates"
)

func TestLoadTemplateAndBuildSeedPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.json")

	template := templates.Template{
		Name:        "test",
		Description: "seed plan template",
		Scope: ingest.Scope{
			Name:    "scope",
			CIDRs:   []string{"192.168.1.0/24"},
			Targets: []string{"192.168.1.10"},
		},
		Profile: ingest.RunProfile{
			Name:         "default",
			EnableLayer2: true,
		},
	}

	data, err := json.Marshal(template)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	loaded, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("LoadTemplate returned error: %v", err)
	}

	plan := BuildSeedPlan(loaded)
	if len(plan) != 3 {
		t.Fatalf("expected 3 jobs, got %d", len(plan))
	}

	if plan[0].Plugin != "internal" {
		t.Fatalf("expected internal scope plugin, got %q", plan[0].Plugin)
	}

	if plan[2].Plugin != "naabu" {
		t.Fatalf("expected naabu plugin, got %q", plan[2].Plugin)
	}
}

func TestRunPlanStoresEvidence(t *testing.T) {
	plan := []jobs.Job{
		{
			ID:      "scope-prepare",
			Kind:    jobs.KindScopePrepare,
			Plugin:  "internal",
			Targets: []string{"10.0.0.10"},
		},
		{
			ID:      "port-discovery",
			Kind:    jobs.KindPortDiscover,
			Plugin:  "naabu",
			Targets: []string{"10.0.0.10"},
		},
	}

	records, err := RunPlan(context.Background(), []engine.Plugin{anyPlugin{name: "naabu"}}, plan)
	if err == nil {
		t.Fatal("expected missing internal plugin error")
	}

	records, err = RunPlan(context.Background(), []engine.Plugin{
		anyPlugin{name: "internal"},
		anyPlugin{name: "naabu"},
	}, plan)
	if err != nil {
		t.Fatalf("RunPlan returned error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].Source != "naabu" {
		t.Fatalf("expected naabu evidence, got %q", records[0].Source)
	}
}

type anyPlugin struct {
	name string
}

func (p anyPlugin) Name() string {
	return p.name
}

func (p anyPlugin) CanRun(job jobs.Job) bool {
	switch p.name {
	case "internal":
		return job.Kind == jobs.KindScopePrepare
	case "naabu":
		return job.Kind == jobs.KindPortDiscover
	default:
		return false
	}
}

func (p anyPlugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	if p.name == "internal" {
		return nil, nil
	}

	return []evidence.Record{
		{
			ID:         "port-record",
			Source:     p.name,
			Kind:       "open_port",
			Target:     "10.0.0.10",
			Port:       443,
			Protocol:   "tcp",
			Summary:    "open tcp port 443 on 10.0.0.10",
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC),
		},
	}, nil
}
