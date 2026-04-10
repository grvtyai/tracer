package zeek

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

func TestPluginRunParsesConnAndHTTPLogs(t *testing.T) {
	dir := t.TempDir()

	connLog := `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1712218800.123456	C1	10.0.0.5	51514	10.0.0.10	80	tcp	http	0.123	123	456	SF
`
	httpLog := `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	user_agent	status_code	status_msg
1712218801.654321	C1	10.0.0.5	51514	10.0.0.10	80	1	GET	app.local	/hello	curl/8.0	200	OK
`

	if err := os.WriteFile(filepath.Join(dir, "conn.log"), []byte(connLog), 0o600); err != nil {
		t.Fatalf("WriteFile conn.log returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "http.log"), []byte(httpLog), 0o600); err != nil {
		t.Fatalf("WriteFile http.log returned error: %v", err)
	}

	plugin := New()
	records, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "zeek-ingest",
		Kind:    jobs.KindPassiveIngest,
		Plugin:  "zeek",
		Targets: []string{"10.0.0.10"},
		Metadata: map[string]string{
			"zeek_log_dir": dir,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].Kind != "passive_conn" {
		t.Fatalf("expected passive_conn, got %#v", records[0])
	}
	if records[1].Kind != "passive_http" {
		t.Fatalf("expected passive_http, got %#v", records[1])
	}
	if records[1].Attributes["status_code"] != "200" {
		t.Fatalf("expected status_code 200, got %#v", records[1].Attributes)
	}
}

func TestPluginRunRequiresZeekLogDir(t *testing.T) {
	plugin := New()

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:     "zeek-ingest",
		Kind:   jobs.KindPassiveIngest,
		Plugin: "zeek",
		Metadata: map[string]string{
			"zeek_mode": "always",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing zeek_log_dir")
	}
}

func TestPluginRunErrorsWhenNoLogsExist(t *testing.T) {
	plugin := New()

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:     "zeek-ingest",
		Kind:   jobs.KindPassiveIngest,
		Plugin: "zeek",
		Metadata: map[string]string{
			"zeek_log_dir": t.TempDir(),
			"zeek_mode":    "always",
		},
	})
	if err == nil {
		t.Fatal("expected error when no zeek logs exist")
	}
}

func TestPluginRunAutoModeSkipsWhenNoLogsExist(t *testing.T) {
	plugin := New()

	records, err := plugin.Run(context.Background(), jobs.Job{
		ID:     "zeek-ingest",
		Kind:   jobs.KindPassiveIngest,
		Plugin: "zeek",
		Metadata: map[string]string{
			"zeek_log_dir": t.TempDir(),
			"zeek_mode":    "auto",
		},
	})
	if err != nil {
		t.Fatalf("expected no error in auto mode, got %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records in auto mode with no logs, got %d", len(records))
	}
}

func TestPluginRunAutoStartsZeekDeployWhenRequested(t *testing.T) {
	dir := t.TempDir()
	connLogPath := filepath.Join(dir, "conn.log")

	plugin := New()
	plugin.runner = fakeRunner{run: func(_ context.Context, name string, args []string) ([]byte, error) {
		if name != "zeekctl" {
			t.Fatalf("unexpected binary %q", name)
		}
		if len(args) != 1 || args[0] != "deploy" {
			t.Fatalf("unexpected args %#v", args)
		}
		connLog := `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1712218800.123456	C1	10.0.0.5	51514	10.0.0.10	80	tcp	http	0.123	123	456	SF
`
		if err := os.WriteFile(connLogPath, []byte(connLog), 0o600); err != nil {
			t.Fatalf("WriteFile conn.log returned error: %v", err)
		}
		return []byte("deployed"), nil
	}}
	plugin.now = func() time.Time {
		return time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	}

	records, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "zeek-ingest",
		Kind:    jobs.KindPassiveIngest,
		Plugin:  "zeek",
		Targets: []string{"10.0.0.10"},
		Metadata: map[string]string{
			"zeek_log_dir":    dir,
			"zeek_mode":       "auto",
			"zeek_auto_start": "true",
		},
	})
	if err != nil {
		t.Fatalf("expected auto-start deploy to succeed, got %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 conn record after deploy, got %d", len(records))
	}
}

func TestPluginRunFiltersByCIDRAndRunStartTime(t *testing.T) {
	dir := t.TempDir()

	connLog := `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1712218700.000000	Cold	10.0.0.5	51514	192.168.178.1	80	tcp	http	0.123	123	456	SF
1712218800.123456	Cgood	10.0.0.5	51515	192.168.178.1	80	tcp	http	0.123	123	456	SF
1712218801.123456	Cskip	10.0.0.5	51516	224.0.0.251	5353	udp	dns	0.123	123	0	S0
`

	if err := os.WriteFile(filepath.Join(dir, "conn.log"), []byte(connLog), 0o600); err != nil {
		t.Fatalf("WriteFile conn.log returned error: %v", err)
	}

	plugin := New()
	records, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "zeek-ingest",
		Kind:    jobs.KindPassiveIngest,
		Plugin:  "zeek",
		Targets: []string{"192.168.178.0/24"},
		Metadata: map[string]string{
			"zeek_log_dir":   dir,
			"zeek_mode":      "always",
			"run_started_at": "2024-04-04T08:19:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected only 1 filtered record, got %d", len(records))
	}
	if records[0].Target != "192.168.178.1" {
		t.Fatalf("unexpected target after filtering: %#v", records[0])
	}
}

type fakeRunner struct {
	run func(ctx context.Context, name string, args []string) ([]byte, error)
}

func (f fakeRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	return f.run(ctx, name, args)
}
