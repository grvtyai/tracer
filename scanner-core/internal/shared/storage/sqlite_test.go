package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/analysis"
	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/ingest"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/options"
)

func TestSQLiteRepositoryPersistsRunArtifacts(t *testing.T) {
	repo, err := OpenSQLite(filepath.Join(t.TempDir(), "startrace.db"))
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
		TemplatePath: "examples/st-radar-smoke-zeek-lab.json",
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

func TestDefaultDataDirPrefersInvokingUserUnderSudo(t *testing.T) {
	dir := defaultDataDir(
		"linux",
		func(key string) string {
			switch key {
			case "SUDO_USER":
				return "grvty"
			default:
				return ""
			}
		},
		func() (string, error) {
			return "/root", nil
		},
		func(username string) (string, error) {
			if username != "grvty" {
				return "", fmt.Errorf("unexpected user %q", username)
			}
			return "/home/grvty", nil
		},
		"startrace",
	)

	if want := filepath.Join("/home/grvty", ".local", "share", "startrace"); dir != want {
		t.Fatalf("unexpected sudo-aware default data dir: want %q, got %q", want, dir)
	}
}

func TestInvokingUserIDsPrefersSudoUserOwnership(t *testing.T) {
	uid, gid, ok := invokingUserIDs(func(key string) string {
		switch key {
		case "SUDO_UID":
			return "1000"
		case "SUDO_GID":
			return "1000"
		default:
			return ""
		}
	})

	if !ok {
		t.Fatalf("expected sudo uid/gid to be detected")
	}
	if uid != 1000 || gid != 1000 {
		t.Fatalf("unexpected sudo ownership ids: got uid=%d gid=%d", uid, gid)
	}
}

func TestSQLiteRepositoryListsRunsAndBuildsDiff(t *testing.T) {
	repo, err := OpenSQLite(filepath.Join(t.TempDir(), "startrace.db"))
	if err != nil {
		t.Fatalf("OpenSQLite returned error: %v", err)
	}
	defer repo.Close()

	project, err := repo.EnsureProject(context.Background(), "Standort A", "Test project")
	if err != nil {
		t.Fatalf("EnsureProject returned error: %v", err)
	}

	baselineRun := seedRun(t, repo, project.ID, "baseline", []evidence.Record{
		record("baseline-open-25", "naabu", "open_port", "192.168.77.2", 25, "tcp", "open tcp port 25 on 192.168.77.2", map[string]string{"service_name": "smtp"}),
		record("baseline-http", "nmap", "service_fingerprint", "192.168.77.2", 80, "tcp", "http detected on tcp/80 at 192.168.77.2", map[string]string{
			"service_name": "http",
			"product":      "SimpleHTTPServer",
			"version":      "0.6",
		}),
	})

	candidateRun := seedRun(t, repo, project.ID, "candidate", []evidence.Record{
		record("candidate-http", "nmap", "service_fingerprint", "192.168.77.2", 80, "tcp", "http detected on tcp/80 at 192.168.77.2", map[string]string{
			"service_name": "http",
			"product":      "SimpleHTTPServer",
			"version":      "0.7",
		}),
		record("candidate-open-443", "naabu", "open_port", "192.168.77.2", 443, "tcp", "open tcp port 443 on 192.168.77.2", map[string]string{"service_name": "https"}),
	})

	projects, err := repo.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("unexpected project count: want 1, got %d", len(projects))
	}
	if projects[0].RunCount != 2 {
		t.Fatalf("unexpected run count on project summary: want 2, got %d", projects[0].RunCount)
	}

	runs, err := repo.ListRuns(context.Background(), "Standort A")
	if err != nil {
		t.Fatalf("ListRuns returned error: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("unexpected run count: want 2, got %d", len(runs))
	}

	diff, err := repo.DiffRuns(context.Background(), baselineRun.ID, candidateRun.ID)
	if err != nil {
		t.Fatalf("DiffRuns returned error: %v", err)
	}
	if diff.NewCount != 1 {
		t.Fatalf("unexpected new evidence count: want 1, got %d", diff.NewCount)
	}
	if diff.MissingCount != 1 {
		t.Fatalf("unexpected missing evidence count: want 1, got %d", diff.MissingCount)
	}
	if diff.ChangedCount != 1 {
		t.Fatalf("unexpected changed evidence count: want 1, got %d", diff.ChangedCount)
	}
	if got := diff.NewEvidence[0].Port; got != 443 {
		t.Fatalf("unexpected new evidence port: want 443, got %d", got)
	}
	if got := diff.MissingEvidence[0].Port; got != 25 {
		t.Fatalf("unexpected missing evidence port: want 25, got %d", got)
	}
	if got := diff.ChangedEvidence[0].Candidate.Attributes["version"]; got != "0.7" {
		t.Fatalf("unexpected changed evidence version: want 0.7, got %q", got)
	}
}

func TestSQLiteRepositoryBackfillsAssetsAndSupportsManualOverrides(t *testing.T) {
	repo, err := OpenSQLite(filepath.Join(t.TempDir(), "startrace.db"))
	if err != nil {
		t.Fatalf("OpenSQLite returned error: %v", err)
	}
	defer repo.Close()

	project, err := repo.EnsureProject(context.Background(), "Heimnetz", "Private network")
	if err != nil {
		t.Fatalf("EnsureProject returned error: %v", err)
	}

	run, runStore, err := repo.StartRun(context.Background(), project.ID, RunSpec{
		TemplateName: "home-lab",
		TemplatePath: "examples/st-radar-home-lab.json",
		Mode:         "run",
		Scope: ingest.Scope{
			Targets: []string{"192.168.178.50"},
		},
		Profile: ingest.RunProfile{
			EnableServiceScan: true,
		},
		Options: options.EffectiveOptions{
			Project: "Heimnetz",
			DBPath:  repo.Path(),
		},
	})
	if err != nil {
		t.Fatalf("StartRun returned error: %v", err)
	}

	if err := runStore.WriteEvidence(context.Background(), []evidence.Record{
		{
			ID:         "iphone-open",
			Source:     "naabu",
			Kind:       "open_port",
			Target:     "192.168.178.50",
			Port:       62078,
			Protocol:   "tcp",
			Summary:    "open tcp port 62078 on 192.168.178.50",
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: time.Date(2026, 4, 4, 13, 0, 0, 0, time.UTC),
		},
		{
			ID:         "iphone-service",
			Source:     "nmap",
			Kind:       "service_fingerprint",
			Target:     "192.168.178.50",
			Port:       62078,
			Protocol:   "tcp",
			Summary:    "iphone sync service detected on tcp/62078 at 192.168.178.50",
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: time.Date(2026, 4, 4, 13, 0, 30, 0, time.UTC),
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

	if err := repo.CompleteRun(context.Background(), run.ID, RunCompletion{
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

	assets, err := repo.ListAssets(context.Background(), "Heimnetz")
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("unexpected asset count: want 1, got %d", len(assets))
	}

	asset := assets[0]
	if asset.EffectiveDeviceType != "smartphone" {
		t.Fatalf("unexpected effective device type: want smartphone, got %q", asset.EffectiveDeviceType)
	}
	if asset.EffectiveConnectionType != "wifi" {
		t.Fatalf("unexpected effective connection type: want wifi, got %q", asset.EffectiveConnectionType)
	}
	if asset.DisplayName != "iphone-von-andre.fritz.box" {
		t.Fatalf("unexpected asset display name: got %q", asset.DisplayName)
	}

	details, err := repo.UpdateAsset(context.Background(), asset.ID, AssetUpdateInput{
		DisplayName:    "Andres iPhone",
		DeviceType:     "smartphone",
		ConnectionType: "wifi",
		Tags:           []string{"privat", "family", "privat"},
		Notes:          "Manually confirmed phone on home wifi.",
	})
	if err != nil {
		t.Fatalf("UpdateAsset returned error: %v", err)
	}

	if details.Asset.DisplayName != "Andres iPhone" {
		t.Fatalf("unexpected overridden display name: got %q", details.Asset.DisplayName)
	}
	if details.Asset.EffectiveDeviceType != "smartphone" {
		t.Fatalf("unexpected overridden device type: got %q", details.Asset.EffectiveDeviceType)
	}
	if details.Asset.EffectiveConnectionType != "wifi" {
		t.Fatalf("unexpected overridden connection type: got %q", details.Asset.EffectiveConnectionType)
	}
	if len(details.Asset.Tags) != 2 || details.Asset.Tags[0] != "family" || details.Asset.Tags[1] != "privat" {
		t.Fatalf("unexpected normalized tags: %#v", details.Asset.Tags)
	}
	if len(details.Observations) != 1 {
		t.Fatalf("unexpected observation count: want 1, got %d", len(details.Observations))
	}
}

func TestNormalizeAssetTargetFiltersNonHostTargets(t *testing.T) {
	tests := map[string]string{
		"":                            "",
		"/":                           "",
		"192.168.178.0/24":            "",
		"192.168.178.1/192.168.178.1": "192.168.178.1",
		"https://192.168.178.1:443/":  "192.168.178.1",
		"http://fritz.box/login.lua":  "fritz.box",
		"192.168.178.1:8443":          "192.168.178.1",
		"fritz.box:443":               "fritz.box",
		"printer.local.":              "printer.local",
		"bad target with spaces":      "",
		"2001:db8::1":                 "2001:db8::1",
		"[2001:db8::1]:443":           "2001:db8::1",
		"2001:db8::/64":               "",
	}

	for input, want := range tests {
		if got := normalizeAssetTarget(input); got != want {
			t.Fatalf("normalizeAssetTarget(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeAssetSummariesSkipsInvalidAndDuplicateTargets(t *testing.T) {
	assets := normalizeAssetSummaries([]AssetSummary{
		{ID: "bad-path", PrimaryTarget: "/", DisplayName: "/"},
		{ID: "router", PrimaryTarget: "192.168.178.1", DisplayName: "fritz.box"},
		{ID: "router-duplicate", PrimaryTarget: "192.168.178.1/192.168.178.1", DisplayName: "192.168.178.1/192.168.178.1"},
		{ID: "server", PrimaryTarget: "https://server.local:8443/", DisplayName: "https://server.local:8443/"},
	})

	if len(assets) != 2 {
		t.Fatalf("unexpected asset count: want 2, got %d (%#v)", len(assets), assets)
	}
	if assets[0].ID != "router" || assets[0].PrimaryTarget != "192.168.178.1" {
		t.Fatalf("unexpected first asset: %#v", assets[0])
	}
	if assets[1].ID != "server" || assets[1].PrimaryTarget != "server.local" || assets[1].DisplayName != "server.local" {
		t.Fatalf("unexpected second asset: %#v", assets[1])
	}
}

func TestAssetSyncSkipsInvalidInventoryTargets(t *testing.T) {
	repo, err := OpenSQLite(filepath.Join(t.TempDir(), "startrace.db"))
	if err != nil {
		t.Fatalf("OpenSQLite returned error: %v", err)
	}
	defer repo.Close()

	project, err := repo.EnsureProject(context.Background(), "Heimnetz", "")
	if err != nil {
		t.Fatalf("EnsureProject returned error: %v", err)
	}

	run, runStore, err := repo.StartRun(context.Background(), project.ID, RunSpec{
		TemplateName: "bad-targets",
		TemplatePath: "gui://test",
		Mode:         "run",
		Scope: ingest.Scope{
			CIDRs: []string{"192.168.178.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("StartRun returned error: %v", err)
	}

	if err := runStore.WriteEvidence(context.Background(), []evidence.Record{
		record("path-only", "httpx", "http_probe", "/", 443, "tcp", "bad path target", nil),
		record("cidr-only", "naabu", "open_port", "192.168.178.0/24", 80, "tcp", "bad subnet target", nil),
		record("joined-host", "testssl.sh", "tls_check", "192.168.178.1/192.168.178.1", 443, "tcp", "normalizable host target", nil),
	}); err != nil {
		t.Fatalf("WriteEvidence returned error: %v", err)
	}

	if err := repo.CompleteRun(context.Background(), run.ID, RunCompletion{
		Status: "completed",
		Plan:   []jobs.Job{{ID: "bad-targets-job", Kind: jobs.KindWebProbe, Plugin: "httpx"}},
	}); err != nil {
		t.Fatalf("CompleteRun returned error: %v", err)
	}

	assets, err := repo.ListAssets(context.Background(), project.ID)
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("unexpected asset count: want 1, got %d (%#v)", len(assets), assets)
	}
	if assets[0].PrimaryTarget != "192.168.178.1" {
		t.Fatalf("unexpected primary target: got %q", assets[0].PrimaryTarget)
	}
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

func seedRun(t *testing.T, repo *SQLiteRepository, projectID string, templateName string, records []evidence.Record) RunRecord {
	t.Helper()

	run, runStore, err := repo.StartRun(context.Background(), projectID, RunSpec{
		TemplateName: templateName,
		TemplatePath: "examples/" + templateName + ".json",
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
			JobID:          templateName + "-job",
			Kind:           jobs.KindServiceProbe,
			Plugin:         "nmap",
			Targets:        []string{"192.168.77.2"},
			Status:         jobs.StatusSucceeded,
			RecordsWritten: len(records),
			StartedAt:      time.Date(2026, 4, 3, 12, 0, 0, 0, time.UTC),
			FinishedAt:     time.Date(2026, 4, 3, 12, 1, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatalf("WriteJobResults returned error: %v", err)
	}

	if err := runStore.WriteEvidence(context.Background(), records); err != nil {
		t.Fatalf("WriteEvidence returned error: %v", err)
	}

	if err := repo.CompleteRun(context.Background(), run.ID, RunCompletion{
		Status: "completed",
		Plan: []jobs.Job{
			{ID: templateName + "-job", Kind: jobs.KindServiceProbe, Plugin: "nmap"},
		},
	}); err != nil {
		t.Fatalf("CompleteRun returned error: %v", err)
	}

	return run
}

func record(id string, source string, kind string, target string, port int, protocol string, summary string, attributes map[string]string) evidence.Record {
	return evidence.Record{
		ID:         id,
		Source:     source,
		Kind:       kind,
		Target:     target,
		Port:       port,
		Protocol:   protocol,
		Summary:    summary,
		Attributes: attributes,
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: time.Date(2026, 4, 3, 12, 0, 30, 0, time.UTC),
	}
}
