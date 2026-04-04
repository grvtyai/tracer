package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestServerAssetsAPIAndPageSupportManualOverrides(t *testing.T) {
	repo := openTestRepo(t)
	defer repo.Close()

	projectID, assetID := seedTestAsset(t, repo)

	server, err := NewServer(repo, Options{
		DBPath:  repo.Path(),
		DataDir: filepath.Dir(repo.Path()),
		AppName: "Startrace",
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/assets?project="+url.QueryEscape(projectID), nil)
	listRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(listRecorder, listReq)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected assets API 200, got %d", listRecorder.Code)
	}

	var listPayload struct {
		Assets []storage.AssetSummary `json:"assets"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("Unmarshal assets payload returned error: %v", err)
	}
	if len(listPayload.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(listPayload.Assets))
	}
	if listPayload.Assets[0].EffectiveDeviceType != "smartphone" {
		t.Fatalf("unexpected effective device type: got %q", listPayload.Assets[0].EffectiveDeviceType)
	}

	form := url.Values{
		"display_name":           {"Andres iPhone"},
		"manual_device_type":     {"smartphone"},
		"manual_connection_type": {"wifi"},
		"tags":                   {"family, privat"},
		"manual_notes":           {"Confirmed manually from the dashboard."},
	}
	updateReq := httptest.NewRequest(http.MethodPost, "/api/assets/"+assetID, strings.NewReader(form.Encode()))
	updateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	updateRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(updateRecorder, updateReq)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("expected asset update 200, got %d", updateRecorder.Code)
	}

	var details storage.AssetDetails
	if err := json.Unmarshal(updateRecorder.Body.Bytes(), &details); err != nil {
		t.Fatalf("Unmarshal asset details returned error: %v", err)
	}
	if details.Asset.DisplayName != "Andres iPhone" {
		t.Fatalf("unexpected updated display name: got %q", details.Asset.DisplayName)
	}
	if len(details.Asset.Tags) != 2 {
		t.Fatalf("unexpected updated tags: %#v", details.Asset.Tags)
	}

	pageReq := httptest.NewRequest(http.MethodGet, "/assets/"+assetID, nil)
	pageRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(pageRecorder, pageReq)
	if pageRecorder.Code != http.StatusOK {
		t.Fatalf("expected asset page 200, got %d", pageRecorder.Code)
	}
	body := pageRecorder.Body.String()
	if !strings.Contains(body, "Andres iPhone") {
		t.Fatalf("expected asset page to contain manual display name, body=%q", body)
	}
	if !strings.Contains(body, "operator-confirmed labels") {
		t.Fatalf("expected asset page to contain override guidance, body=%q", body)
	}
}

func TestServerCanCreateProjectAndPersistDefaultProject(t *testing.T) {
	repo := openTestRepo(t)
	defer repo.Close()

	server, err := NewServer(repo, Options{
		DBPath:  repo.Path(),
		DataDir: filepath.Dir(repo.Path()),
		AppName: "Startrace",
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	createForm := url.Values{
		"name":           {"Standort A"},
		"notes":          {"Primary home network"},
		"owner_username": {"grvty"},
	}
	createReq := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(createForm.Encode()))
	createReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createRecorder, createReq)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected project create 201, got %d", createRecorder.Code)
	}

	var project storage.Project
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &project); err != nil {
		t.Fatalf("Unmarshal project returned error: %v", err)
	}
	if project.PublicID == "" {
		t.Fatalf("expected auto-generated public id")
	}
	if project.StoragePath == "" {
		t.Fatalf("expected auto-generated storage path")
	}

	settingsForm := url.Values{
		"default_project_id": {project.ID},
	}
	settingsReq := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(settingsForm.Encode()))
	settingsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	settingsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(settingsRecorder, settingsReq)
	if settingsRecorder.Code != http.StatusOK {
		t.Fatalf("expected settings save 200, got %d", settingsRecorder.Code)
	}

	var appSettings storage.AppSettings
	if err := json.Unmarshal(settingsRecorder.Body.Bytes(), &appSettings); err != nil {
		t.Fatalf("Unmarshal app settings returned error: %v", err)
	}
	if appSettings.DefaultProjectID != project.ID {
		t.Fatalf("unexpected default project id: want %q, got %q", project.ID, appSettings.DefaultProjectID)
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

func seedTestAsset(t *testing.T, repo *storage.SQLiteRepository) (string, string) {
	t.Helper()

	ctx := context.Background()
	project, err := repo.EnsureProject(ctx, "Heimnetz Assets", "")
	if err != nil {
		t.Fatalf("EnsureProject returned error: %v", err)
	}

	run, store, err := repo.StartRun(ctx, project.ID, storage.RunSpec{
		TemplateName: "home-assets",
		TemplatePath: "examples/tracer-home-lab.json",
		Mode:         "run",
		Scope: ingest.Scope{
			Targets: []string{"192.168.178.50"},
		},
		Profile: ingest.RunProfile{
			EnableServiceScan: true,
		},
		Options: options.EffectiveOptions{
			Project: "Heimnetz Assets",
			DBPath:  repo.Path(),
		},
	})
	if err != nil {
		t.Fatalf("StartRun returned error: %v", err)
	}

	if err := store.WriteEvidence(ctx, []evidence.Record{
		{
			ID:         "asset-open",
			Source:     "naabu",
			Kind:       "open_port",
			Target:     "192.168.178.50",
			Port:       62078,
			Protocol:   "tcp",
			Summary:    "open tcp port 62078 on 192.168.178.50",
			Confidence: evidence.ConfidenceConfirmed,
		},
		{
			ID:         "asset-service",
			Source:     "nmap",
			Kind:       "service_fingerprint",
			Target:     "192.168.178.50",
			Port:       62078,
			Protocol:   "tcp",
			Summary:    "iphone sync service detected on tcp/62078 at 192.168.178.50",
			Confidence: evidence.ConfidenceConfirmed,
			Attributes: map[string]string{
				"hostname": "iphone-von-andre.fritz.box",
				"os_name":  "iOS",
				"product":  "Apple iPhone sync",
				"vendor":   "Apple",
			},
		},
	}); err != nil {
		t.Fatalf("WriteEvidence returned error: %v", err)
	}

	if err := repo.CompleteRun(ctx, run.ID, storage.RunCompletion{
		Status: "completed",
		Plan: []jobs.Job{
			{ID: "service-iphone", Kind: jobs.KindServiceProbe, Plugin: "nmap"},
		},
		Blocking: []analysis.BlockingAssessment{
			{
				Target:     "192.168.178.50",
				Verdict:    evidence.VerdictReachable,
				Confidence: evidence.ConfidenceConfirmed,
			},
		},
	}); err != nil {
		t.Fatalf("CompleteRun returned error: %v", err)
	}

	assets, err := repo.ListAssets(ctx, project.ID)
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("unexpected asset count: want 1, got %d", len(assets))
	}

	return project.ID, assets[0].ID
}
