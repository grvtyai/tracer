package apiserver_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/apiserver"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service/stub"
)

const testToken = "test-token"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	svc := stub.New("sat-test", "0.0.1")
	srv, err := apiserver.New(apiserver.Config{
		ListenAddr:  "127.0.0.1:0",
		AuthToken:   testToken,
		SatelliteID: "sat-test",
		Version:     "0.0.1",
	}, svc)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, ts *httptest.Server, method, path string, body []byte, withAuth bool) *http.Response {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, reqBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if withAuth {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func TestHealthIsPublic(t *testing.T) {
	ts := newTestServer(t)
	resp := do(t, ts, "GET", "/health", nil, false)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var h api.Health
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Status != api.HealthStatusOK {
		t.Errorf("want status ok, got %q", h.Status)
	}
	if h.APIVersion != api.Version {
		t.Errorf("want api version %q, got %q", api.Version, h.APIVersion)
	}
}

func TestCapabilitiesRequiresAuth(t *testing.T) {
	ts := newTestServer(t)
	resp := do(t, ts, "GET", "/capabilities", nil, false)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestCapabilitiesReturnsStubPlugins(t *testing.T) {
	ts := newTestServer(t)
	resp := do(t, ts, "GET", "/capabilities", nil, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var c api.Capabilities
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(c.Plugins) == 0 {
		t.Fatal("want at least one plugin")
	}
	if c.Plugins[0].Name != "stub-scanner" {
		t.Errorf("want stub-scanner, got %q", c.Plugins[0].Name)
	}
}

func TestStartRunAndFetchStatus(t *testing.T) {
	ts := newTestServer(t)

	body, _ := json.Marshal(api.StartRunRequest{
		ProjectID: "proj-1",
		Template:  json.RawMessage(`{}`),
	})
	resp := do(t, ts, "POST", "/runs", body, true)
	if resp.StatusCode != http.StatusAccepted {
		resp.Body.Close()
		t.Fatalf("start run: want 202, got %d", resp.StatusCode)
	}
	var start api.StartRunResponse
	if err := json.NewDecoder(resp.Body).Decode(&start); err != nil {
		resp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if start.RunID == "" {
		t.Fatal("want non-empty run id")
	}

	resp = do(t, ts, "GET", "/runs/"+start.RunID+"/status", nil, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
	var status api.RunStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.RunID != start.RunID {
		t.Errorf("want run id %q, got %q", start.RunID, status.RunID)
	}
}

func TestMissingRunReturns404(t *testing.T) {
	ts := newTestServer(t)
	resp := do(t, ts, "GET", "/runs/does-not-exist/status", nil, true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
	var e api.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Code != api.ErrorCodeNotFound {
		t.Errorf("want code %q, got %q", api.ErrorCodeNotFound, e.Code)
	}
}

func TestSSEStreamsUntilRunCompletes(t *testing.T) {
	ts := newTestServer(t)

	body, _ := json.Marshal(api.StartRunRequest{ProjectID: "proj-1", Template: json.RawMessage(`{}`)})
	resp := do(t, ts, "POST", "/runs", body, true)
	var start api.StartRunResponse
	_ = json.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/runs/"+start.RunID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	client := &http.Client{Timeout: 5 * time.Second}
	streamResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("sse: %v", err)
	}
	defer streamResp.Body.Close()
	if streamResp.StatusCode != http.StatusOK {
		t.Fatalf("sse status: want 200, got %d", streamResp.StatusCode)
	}

	buf := make([]byte, 4096)
	n, err := streamResp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read sse: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "event: "+api.EventTypeRunState) {
		t.Errorf("want run.state event in stream, got: %s", got)
	}
}
