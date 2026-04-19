package runnerclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/controller/runnerclient"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/apiserver"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service/stub"
)

const testToken = "test-token"

// setup boots an in-process Satellite (handler only — no real socket) wrapped
// in httptest.Server, and returns a client configured to talk to it.
func setup(t *testing.T) *runnerclient.Client {
	t.Helper()
	svc := stub.New("sat-test", "0.0.1")
	srv, err := apiserver.New(apiserver.Config{
		ListenAddr:  "127.0.0.1:0",
		AuthToken:   testToken,
		SatelliteID: "sat-test",
		Version:     "0.0.1",
	}, svc)
	if err != nil {
		t.Fatalf("apiserver.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	c, err := runnerclient.New(runnerclient.Config{
		BaseURL:    ts.URL,
		AuthToken:  testToken,
		HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatalf("runnerclient.New: %v", err)
	}
	return c
}

func TestClientHealth(t *testing.T) {
	c := setup(t)
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if h.Status != api.HealthStatusOK {
		t.Errorf("want status ok, got %q", h.Status)
	}
	if h.APIVersion != api.Version {
		t.Errorf("want api version %q, got %q", api.Version, h.APIVersion)
	}
}

func TestClientCapabilities(t *testing.T) {
	c := setup(t)
	caps, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if len(caps.Plugins) == 0 {
		t.Fatal("want at least one plugin")
	}
	if caps.Plugins[0].Name != "stub-scanner" {
		t.Errorf("want stub-scanner, got %q", caps.Plugins[0].Name)
	}
}

func TestClientStartRunAndStatus(t *testing.T) {
	c := setup(t)
	start, err := c.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	if start.RunID == "" {
		t.Fatal("want non-empty run id")
	}

	status, err := c.RunStatus(context.Background(), start.RunID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.RunID != start.RunID {
		t.Errorf("want run id %q, got %q", start.RunID, status.RunID)
	}
}

func TestClientMissingRunReturnsNotFound(t *testing.T) {
	c := setup(t)
	_, err := c.RunStatus(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, runnerclient.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	var apiErr *runnerclient.APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("want *APIError")
	}
	if apiErr.Code != api.ErrorCodeNotFound {
		t.Errorf("want code %q, got %q", api.ErrorCodeNotFound, apiErr.Code)
	}
}

func TestClientBadTokenReturnsUnauthorized(t *testing.T) {
	svc := stub.New("sat-test", "0.0.1")
	srv, _ := apiserver.New(apiserver.Config{
		ListenAddr:  "127.0.0.1:0",
		AuthToken:   testToken,
		SatelliteID: "sat-test",
		Version:     "0.0.1",
	}, svc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c, _ := runnerclient.New(runnerclient.Config{
		BaseURL:    ts.URL,
		AuthToken:  "wrong-token",
		HTTPClient: ts.Client(),
	})

	_, err := c.Capabilities(context.Background())
	if !errors.Is(err, runnerclient.ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized, got %v", err)
	}
}

func TestClientSubscribeEventsUntilCompletion(t *testing.T) {
	c := setup(t)
	start, err := c.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("start run: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := c.SubscribeEvents(ctx, start.RunID)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	var sawRunning, sawCompleted bool
	for ev := range sub.Events {
		if ev.Type != api.EventTypeRunState {
			continue
		}
		var p api.RunStatePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		switch p.State {
		case api.RunStateRunning:
			sawRunning = true
		case api.RunStateCompleted:
			sawCompleted = true
		}
	}
	if err := sub.Err(); err != nil {
		t.Errorf("subscription error: %v", err)
	}
	if !sawRunning {
		t.Error("never saw running state")
	}
	if !sawCompleted {
		t.Error("never saw completed state")
	}
}

func TestClientListRunsIncludesNewRun(t *testing.T) {
	c := setup(t)
	start, err := c.StartRun(context.Background(), api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	list, err := c.ListRuns(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, r := range list.Runs {
		if r.RunID == start.RunID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("new run %q not in list", start.RunID)
	}
}
