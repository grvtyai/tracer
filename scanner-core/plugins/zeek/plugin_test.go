package zeek

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
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
		},
	})
	if err == nil {
		t.Fatal("expected error when no zeek logs exist")
	}
}
