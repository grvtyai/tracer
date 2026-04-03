package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/analysis"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
)

func TestSQLiteRepositoryPersistsRunArtifacts(t *testing.T) {
	repo, err := OpenSQLite(filepath.Join(t.TempDir(), "tracer.db"))
	if err != nil {
		t.Fatalf("OpenSQLite returned error: %v", err)
	}
	defer repo.Close()

	project, err := repo.EnsureProject(context.Background(), "Standort A", "Test project")
	if err != nil {
		t.Fatalf("EnsureProject returned error: %v", err)
	}

	run, runStore, err := repo.StartRun(context.Background(), project.ID, RunSpec{
		TemplateName: "smoke-zeek-lab",
		TemplatePath: "examples/tracer-smoke-zeek-lab.json",
		Mode:         "run",
		Scope: ingest.Scope{
			Targets: []string{"192.168.77.2"},
		},
		Profile: ingest.RunProfile{
			EnableServiceScan: true,
		},
		Options: options.EffectiveOptions{
			ContinueOnError:      true,
			RetainPartialResults: true,
			ReevaluateAmbiguous:  true,
			ReevaluateAfter:      "30m",
			Project:              "Standort A",
			DBPath:               repo.Path(),
		},
	})
	if err != nil {
		t.Fatalf("StartRun returned error: %v", err)
	}

	if err := runStore.WriteJobResults(context.Background(), []jobs.ExecutionResult{
		{
			JobID:          "port-discovery",
			Kind:           jobs.KindPortDiscover,
			Plugin:         "naabu",
			Targets:        []string{"192.168.77.2"},
			Status:         jobs.StatusSucceeded,
			RecordsWritten: 1,
			StartedAt:      time.Date(2026, 4, 3, 12, 0, 0, 0, time.UTC),
			FinishedAt:     time.Date(2026, 4, 3, 12, 1, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatalf("WriteJobResults returned error: %v", err)
	}

	if err := runStore.WriteEvidence(context.Background(), []evidence.Record{
		{
			ID:         "open-80",
			Source:     "naabu",
			Kind:       "open_port",
			Target:     "192.168.77.2",
			Port:       80,
			Protocol:   "tcp",
			Summary:    "open tcp port 80 on 192.168.77.2",
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: time.Date(2026, 4, 3, 12, 0, 30, 0, time.UTC),
			Attributes: map[string]string{
				"plugin": "naabu",
			},
		},
	}); err != nil {
		t.Fatalf("WriteEvidence returned error: %v", err)
	}

	if err := repo.CompleteRun(context.Background(), run.ID, RunCompletion{
		Status: "completed",
		Plan: []jobs.Job{
			{ID: "port-discovery", Kind: jobs.KindPortDiscover, Plugin: "naabu"},
		},
		Blocking: []analysis.BlockingAssessment{
			{Target: "192.168.77.2", Port: 80, Verdict: evidence.VerdictReachable, Confidence: evidence.ConfidenceConfirmed},
		},
		Reevaluation: []analysis.ReevaluationHint{
			{Target: "192.168.77.2", Port: 80, Reason: "example", SuggestedAfter: "30m"},
		},
	}); err != nil {
		t.Fatalf("CompleteRun returned error: %v", err)
	}

	assertCount(t, repo, "projects", 1)
	assertCount(t, repo, "runs", 1)
	assertCount(t, repo, "job_results", 1)
	assertCount(t, repo, "evidence", 1)
	assertCount(t, repo, "blocking_assessments", 1)
	assertCount(t, repo, "reevaluation_hints", 1)
}

func assertCount(t *testing.T, repo *SQLiteRepository, table string, want int) {
	t.Helper()

	var got int
	query := "SELECT COUNT(*) FROM " + table
	if err := repo.db.QueryRowContext(context.Background(), query).Scan(&got); err != nil {
		t.Fatalf("count %s returned error: %v", table, err)
	}
	if got != want {
		t.Fatalf("unexpected count for %s: want %d, got %d", table, want, got)
	}
}
