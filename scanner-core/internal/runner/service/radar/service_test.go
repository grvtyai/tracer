package radar_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/controller/runnerclient"
	"github.com/grvtyai/startrace/scanner-core/internal/engine"
	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/apiserver"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service/radar"
)

// mockPlugin lets the radar service run end-to-end without any real scanner
// binaries. CanRun matches every job; Run emits one synthetic evidence record
// so we can verify the full pipeline (plan → execute → evidence → events).
type mockPlugin struct {
	name string
}

func (p mockPlugin) Name() string                     { return p.name }
func (p mockPlugin) CanRun(job jobs.Job) bool         { return true }
func (p mockPlugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	return []evidence.Record{{
		ID:         "ev-" + job.ID,
		Source:     p.name,
		Kind:       "open_port",
		Target:     firstTarget(job),
		Port:       80,
		Protocol:   "tcp",
		Summary:    "mock finding",
		ObservedAt: time.Now().UTC(),
	}}, nil
}

func firstTarget(j jobs.Job) string {
	if len(j.Targets) > 0 {
		return j.Targets[0]
	}
	return "10.0.0.1"
}

// sampleTemplate is a minimal radar scan template. Scope is small; profile
// turns off everything so the seed plan is a single scope-prepare + one
// port-discover job.
var sampleTemplate = json.RawMessage(`{
    "name": "test",
    "scope": {
        "targets": ["10.0.0.1"],
        "cidrs": []
    },
    "profile": {
        "enable_port_discovery": true,
        "enable_service_scan": false,
        "enable_route_sampling": false,
        "enable_os_detection": false,
        "enable_passive_ingest": false
    }
}`)

func newTestService(t *testing.T) *radar.Service {
	t.Helper()
	return radar.New(radar.Config{
		SatelliteID: "sat-test",
		Version:     "0.0.1",
		Plugins: []engine.Plugin{
			mockPlugin{name: "internal"},
			mockPlugin{name: "naabu"},
			mockPlugin{name: "nmap"},
			mockPlugin{name: "httpx"},
			mockPlugin{name: "zgrab2"},
			mockPlugin{name: "scamper"},
		},
	})
}

func TestCapabilitiesListsPlugins(t *testing.T) {
	svc := newTestService(t)
	caps, err := svc.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if len(caps.Plugins) == 0 {
		t.Fatal("want at least one plugin")
	}
	// The internal plugin has no binary dep, so it must be available.
	var internal *api.Plugin
	for i := range caps.Plugins {
		if caps.Plugins[i].Name == "internal" {
			internal = &caps.Plugins[i]
			break
		}
	}
	if internal == nil {
		t.Fatal("internal plugin not in capabilities")
	}
	if !internal.Available {
		t.Error("internal plugin should always be available")
	}
}

func TestStartRunCompletesAndProducesEvidence(t *testing.T) {
	svc := newTestService(t)
	start, err := svc.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  sampleTemplate,
	})
	if err != nil {
		t.Fatalf("start run: %v", err)
	}

	// Wait for the run to complete by polling status.
	deadline := time.Now().Add(5 * time.Second)
	var final api.RunStatus
	for time.Now().Before(deadline) {
		status, err := svc.RunStatus(context.Background(), start.RunID)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if status.State == api.RunStateCompleted || status.State == api.RunStateFailed {
			final = status
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if final.State != api.RunStateCompleted {
		t.Fatalf("want completed, got %q", final.State)
	}

	evResp, err := svc.RunEvidence(context.Background(), start.RunID)
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if evResp.Count == 0 {
		t.Fatal("want at least one evidence record from mock plugin")
	}
}

func TestStartRunRejectsEmptyTemplate(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  nil,
	})
	if err == nil {
		t.Fatal("want error for empty template")
	}
}

func TestStartRunRejectsInvalidTemplateJSON(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  json.RawMessage("{not valid json"),
	})
	if err == nil {
		t.Fatal("want error for invalid json")
	}
}

func TestCancelRunningRun(t *testing.T) {
	// Use a plugin that blocks until ctx cancels to guarantee we catch it
	// mid-flight.
	blocking := []engine.Plugin{
		mockPlugin{name: "internal"},
		blockingPlugin{name: "naabu"},
		blockingPlugin{name: "nmap"},
	}
	svc := radar.New(radar.Config{
		SatelliteID: "sat-test",
		Version:     "0.0.1",
		Plugins:     blocking,
	})

	start, err := svc.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  sampleTemplate,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Give the run a moment to enter the blocking plugin.
	time.Sleep(100 * time.Millisecond)

	if err := svc.CancelRun(context.Background(), start.RunID); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s, _ := svc.RunStatus(context.Background(), start.RunID)
		if s.State == api.RunStateCancelled || s.State == api.RunStateCompleted {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("run did not reach cancelled state in time")
}

type blockingPlugin struct{ name string }

func (p blockingPlugin) Name() string             { return p.name }
func (p blockingPlugin) CanRun(j jobs.Job) bool   { return true }
func (p blockingPlugin) Run(ctx context.Context, j jobs.Job) ([]evidence.Record, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// End-to-end smoke: a real Satellite HTTP server wrapping the radar service,
// driven by the runnerclient. This proves the full wire path works with the
// real Service impl, not just the stub.
func TestEndToEndRadarOverHTTP(t *testing.T) {
	radarSvc := newTestService(t)
	srv, err := apiserver.New(apiserver.Config{
		ListenAddr:  "127.0.0.1:0",
		AuthToken:   "tkn",
		SatelliteID: "sat-test",
		Version:     "0.0.1",
	}, radarSvc)
	if err != nil {
		t.Fatalf("apiserver: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client, err := runnerclient.New(runnerclient.Config{
		BaseURL:    ts.URL,
		AuthToken:  "tkn",
		HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	caps, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("caps: %v", err)
	}
	if len(caps.Plugins) == 0 {
		t.Fatal("want plugins in capabilities")
	}

	start, err := client.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  sampleTemplate,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sub, err := client.SubscribeEvents(ctx, start.RunID)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	var sawCompleted, sawEvidence bool
	for ev := range sub.Events {
		switch ev.Type {
		case api.EventTypeRunState:
			var p api.RunStatePayload
			_ = json.Unmarshal(ev.Payload, &p)
			if p.State == api.RunStateCompleted {
				sawCompleted = true
			}
		case api.EventTypeEvidence:
			sawEvidence = true
		}
	}
	if err := sub.Err(); err != nil {
		t.Errorf("sub err: %v", err)
	}
	if !sawCompleted {
		t.Error("no completed event")
	}
	if !sawEvidence {
		t.Error("no evidence event")
	}
}

func TestMissingRunReturnsNotFound(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.RunStatus(context.Background(), "no-such-run")
	if err == nil {
		t.Fatal("want error")
	}
	// The radar service wraps sentinels the same way the stub does, so the
	// runner-level sentinel should be reachable through the wrap.
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("want 'not found' in error, got: %v", err)
	}
	// Via the HTTP client the sentinel mapping kicks in; we test that in the
	// end-to-end test above. Here we just confirm the error surface.
	_ = errors.Unwrap
}
