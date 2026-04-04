package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grvtyai/tracer/scanner-core/internal/analysis"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
)

func TestServerHealthAndProjectsAPI(t *testing.T) {
	repo := openTestRepo(t)
	defer repo.Close()

	runID := seedTestRun(t, repo)

	server, err := NewServer(repo, Options{
		DBPath:  repo.Path(),
		DataDir: filepath.Dir(repo.Path()),
		AppName: "Startrace",
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	health := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	healthRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(healthRecorder, health)
	if healthRecorder.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d", healthRecorder.Code)
	}

	projectsReq := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	projectsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(projectsRecorder, projectsReq)
	if projectsRecorder.Code != http.StatusOK {
		t.Fatalf("expected projects 200, got %d", projectsRecorder.Code)
	}

	var payload struct {
		Projects []storage.ProjectSummary `json:"projects"`
	}
	if err := json.Unmarshal(projectsRecorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal projects payload returned error: %v", err)
	}
	if len(payload.Projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(payload.Projects))
	}

	runReq := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID, nil)
	runRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(runRecorder, runReq)
	if runRecorder.Code != http.StatusOK {
		t.Fatalf("expected run 200, got %d", runRecorder.Code)
	}
}

func TestServerRunPageRendersHostData(t *testing.T) {
	repo := openTestRepo(t)
	defer repo.Close()

	runID := seedTestRun(t, repo)

	server, err := NewServer(repo, Options{
		DBPath:  repo.Path(),
		DataDir: filepath.Dir(repo.Path()),
		AppName: "Startrace",
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/runs/"+runID, nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected run page 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "192.168.178.1") {
		t.Fatalf("expected run page to contain target IP, body=%q", body)
	}
	if !strings.Contains(body, "reachable") {
		t.Fatalf("expected run page to contain reachable verdict, body=%q", body)
	}
}

func openTestRepo(t *testing.T) *storage.SQLiteRepository {
	t.Helper()
	repo, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "tracer.db"))
	if err != nil {
		t.Fatalf("OpenSQLite returned error: %v", err)
	}
	return repo
}

func seedTestRun(t *testing.T, repo *storage.SQLiteRepository) string {
	t.Helper()

	ctx := context.Background()
	project, err := repo.EnsureProject(ctx, "Heimnetz", "")
	if err != nil {
		t.Fatalf("EnsureProject returned error: %v", err)
	}

	run, store, err := repo.StartRun(ctx, project.ID, storage.RunSpec{
		TemplateName: "home-lab",
		TemplatePath: "examples/tracer-home-lab.json",
		Mode:         "run",
		Scope: ingest.Scope{
			Name:    "home",
			Targets: []string{"192.168.178.0/24"},
		},
		Profile: ingest.RunProfile{
			Name:                "default",
			EnableRouteSampling: true,
			EnableServiceScan:   true,
			EnablePassiveIngest: true,
			EnableOSDetection:   true,
			ZeekLogDir:          "/opt/zeek/logs/current",
		},
		Options: options.DefaultEffectiveOptions(),
	})
	if err != nil {
		t.Fatalf("StartRun returned error: %v", err)
	}

	jobResults := []jobs.ExecutionResult{
		{
			JobID:   "port-discovery",
			Kind:    jobs.KindPortDiscover,
			Plugin:  "naabu",
			Targets: []string{"192.168.178.1"},
			Status:  jobs.StatusSucceeded,
		},
	}
	if err := store.WriteJobResults(ctx, jobResults); err != nil {
		t.Fatalf("WriteJobResults returned error: %v", err)
	}

	records := []evidence.Record{
		{
			ID:         "port-1",
			Source:     "naabu",
			Kind:       "open_port",
			Target:     "192.168.178.1",
			Port:       443,
			Protocol:   "tcp",
			Summary:    "open tcp port 443 on 192.168.178.1",
			Confidence: evidence.ConfidenceConfirmed,
		},
		{
			ID:         "svc-1",
			Source:     "nmap",
			Kind:       "service_fingerprint",
			Target:     "192.168.178.1",
			Port:       443,
			Protocol:   "tcp",
			Summary:    "http detected on tcp/443 at 192.168.178.1",
			Confidence: evidence.ConfidenceConfirmed,
		},
	}
	if err := store.WriteEvidence(ctx, records); err != nil {
		t.Fatalf("WriteEvidence returned error: %v", err)
	}

	if err := repo.CompleteRun(ctx, run.ID, storage.RunCompletion{
		Status: "completed",
		Plan:   []jobs.Job{{ID: "port-discovery", Kind: jobs.KindPortDiscover, Plugin: "naabu"}},
		Blocking: []analysis.BlockingAssessment{
			{
				Target:       "192.168.178.1",
				Verdict:      evidence.VerdictReachable,
				Confidence:   evidence.ConfidenceConfirmed,
				Reasons:      []string{"active probing confirmed the target is reachable"},
				EvidenceRefs: []string{"port-1"},
			},
		},
	}); err != nil {
		t.Fatalf("CompleteRun returned error: %v", err)
	}

	return run.ID
}
