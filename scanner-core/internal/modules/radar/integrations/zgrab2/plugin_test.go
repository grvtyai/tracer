package zgrab2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

type fakeRunner struct {
	output []byte
	err    error
	name   string
	args   []string
	env    []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, env []string) ([]byte, error) {
	f.name = name
	f.args = append([]string{}, args...)
	f.env = append([]string{}, env...)
	return f.output, f.err
}

func TestBuildArgs(t *testing.T) {
	job := jobs.Job{
		ID:      "grab-10.0.0.10",
		Kind:    jobs.KindGrabProbe,
		Targets: []string{"10.0.0.10"},
		Ports:   []int{443},
		Metadata: map[string]string{
			"module":        "http",
			"timeout":       "10",
			"max_redirects": "1",
			"endpoint":      "/",
		},
	}

	got := BuildArgs(job, "/tmp/input.csv")
	want := []string{
		"http",
		"--input-file", "/tmp/input.csv",
		"--output-file", "-",
		"--connect-timeout", "10",
		"--target-timeout", "10",
		"--max-redirects", "1",
		"--use-https",
		"--endpoint", "/",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestParseOutputBuildsGrabRecords(t *testing.T) {
	job := jobs.Job{
		ID:             "grab-10.0.0.10",
		Kind:           jobs.KindGrabProbe,
		Targets:        []string{"10.0.0.10"},
		Ports:          []int{443},
		ServiceClass:   "web",
		ServiceClasses: []string{"web"},
		Metadata: map[string]string{
			"run_id":                     "run-1",
			"module":                     "http",
			"host_primary_service_class": "remote_access",
			"host_service_classes":       "remote_access,messaging,printing,web",
		},
	}

	output := []byte(`{"ip":"10.0.0.10","timestamp":"2026-04-01T12:00:00.000000000Z","data":{"http":{"status":"success","port":443,"result":{"response":{"status_line":"HTTP/1.1 200 OK","status_code":200,"body_title":"Welcome","headers":{"server":["nginx"],"content-type":["text/html"]},"request":{"tls":{"version":"TLSv1.3"}}}}}}}`)

	records, err := ParseOutput(output, job, time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	record := records[0]
	if record.Kind != "l7_grab" {
		t.Fatalf("unexpected kind: %s", record.Kind)
	}
	if record.Attributes["service_class"] != "web" {
		t.Fatalf("expected web classification, got %q", record.Attributes["service_class"])
	}
	if record.Attributes["host_primary_service_class"] != "remote_access" {
		t.Fatalf("expected inherited host class, got %q", record.Attributes["host_primary_service_class"])
	}
	if record.Attributes["tls_version"] != "TLSv1.3" {
		t.Fatalf("expected tls_version, got %q", record.Attributes["tls_version"])
	}
}

func TestParseOutputSkipsMetadataLineAndUsesInputTarget(t *testing.T) {
	job := jobs.Job{
		ID:      "grab-127.0.0.1",
		Kind:    jobs.KindGrabProbe,
		Targets: []string{"127.0.0.1"},
		Ports:   []int{80},
		Metadata: map[string]string{
			"module": "http",
		},
	}

	output := []byte(strings.Join([]string{
		`{"ip":"127.0.0.1","input":"127.0.0.1:80","data":{"http":{"status":"success","port":80,"result":{"response":{"status_code":200}}}}}`,
		`{"metadata":{"cli_args":["http"]}}`,
		`{"input":"127.0.0.1:80","data":{"http":{"status":"success","port":80,"result":{"response":{"status_code":404}}}}}`,
	}, "\n"))

	records, err := ParseOutput(output, job, time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[1].Target != "127.0.0.1" {
		t.Fatalf("expected target from input fallback, got %q", records[1].Target)
	}
}

func TestWriteInputFile(t *testing.T) {
	dir := t.TempDir()
	plugin := &Plugin{
		tempDir: func() string { return dir },
	}

	job := jobs.Job{
		ID:      "grab-10.0.0.10",
		Targets: []string{"10.0.0.10"},
		Ports:   []int{80, 443},
	}

	path, err := plugin.writeInputFile(job)
	if err != nil {
		t.Fatalf("writeInputFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	got := string(data)
	if !strings.Contains(got, "10.0.0.10,,,80") || !strings.Contains(got, "10.0.0.10,,,443") {
		t.Fatalf("unexpected input file content: %q", got)
	}
}

func TestPluginRun(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`{"ip":"10.0.0.20","data":{"http":{"status":"success","port":443,"result":{"response":{"status_code":200}}}}}`),
	}

	dir := t.TempDir()
	now := time.Date(2026, 4, 1, 12, 30, 0, 0, time.UTC)
	plugin := &Plugin{
		binary: "zgrab2-bin",
		runner: runner,
		now: func() time.Time {
			return now
		},
		tempDir: func() string { return dir },
	}

	job := jobs.Job{
		ID:      "grab-10.0.0.20",
		Kind:    jobs.KindGrabProbe,
		Targets: []string{"10.0.0.20"},
		Ports:   []int{443},
	}

	records, err := plugin.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if runner.name != "zgrab2-bin" {
		t.Fatalf("unexpected binary: %s", runner.name)
	}
	envJoined := strings.Join(runner.env, " ")
	if !strings.Contains(envJoined, "XDG_CONFIG_HOME=") || !strings.Contains(envJoined, "HOME=") {
		t.Fatalf("expected HOME and XDG_CONFIG_HOME override, got %#v", runner.env)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].ObservedAt != now {
		t.Fatalf("unexpected observed time: %v", records[0].ObservedAt)
	}
}

func TestPluginRunRequiresTargetsAndPorts(t *testing.T) {
	plugin := New()

	_, err := plugin.Run(context.Background(), jobs.Job{ID: "empty", Kind: jobs.KindGrabProbe, Ports: []int{443}})
	if err == nil {
		t.Fatal("expected error for missing targets")
	}

	_, err = plugin.Run(context.Background(), jobs.Job{ID: "empty", Kind: jobs.KindGrabProbe, Targets: []string{"10.0.0.10"}})
	if err == nil {
		t.Fatal("expected error for missing ports")
	}
}

func TestPluginRunIncludesCommandFailureOutput(t *testing.T) {
	runner := &fakeRunner{
		output: []byte("zgrab2: target unavailable"),
		err:    errors.New("exit status 1"),
	}

	dir := t.TempDir()
	plugin := &Plugin{
		runner:  runner,
		now:     time.Now,
		tempDir: func() string { return dir },
	}

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "grab-10.0.0.10",
		Kind:    jobs.KindGrabProbe,
		Targets: []string{"10.0.0.10"},
		Ports:   []int{443},
	})
	if err == nil {
		t.Fatal("expected runner error")
	}
	if !strings.Contains(err.Error(), "target unavailable") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestSanitize(t *testing.T) {
	got := sanitize("grab:10.0.0.10/http test")
	if strings.ContainsAny(got, `\/: `) {
		t.Fatalf("sanitize did not strip path separators: %q", got)
	}

	if filepath.Base(got) != got {
		t.Fatalf("sanitize should not create path components: %q", got)
	}
}

func TestPrepareConfigEnvCreatesBlocklist(t *testing.T) {
	dir := t.TempDir()
	plugin := &Plugin{
		tempDir: func() string { return dir },
	}

	configRoot, env, err := plugin.prepareConfigEnv(jobs.Job{ID: "grab-10.0.0.10"})
	if err != nil {
		t.Fatalf("prepareConfigEnv returned error: %v", err)
	}
	defer os.RemoveAll(configRoot)

	if len(env) != 2 {
		t.Fatalf("unexpected env: %#v", env)
	}
	envJoined := strings.Join(env, " ")
	if !strings.Contains(envJoined, "XDG_CONFIG_HOME=") || !strings.Contains(envJoined, "HOME=") {
		t.Fatalf("unexpected env values: %#v", env)
	}

	blocklistPaths := []string{
		filepath.Join(configRoot, "zgrab2", "blocklist.conf"),
		filepath.Join(configRoot, ".config", "zgrab2", "blocklist.conf"),
	}
	for _, blocklistPath := range blocklistPaths {
		data, err := os.ReadFile(blocklistPath)
		if err != nil {
			t.Fatalf("ReadFile returned error for %s: %v", blocklistPath, err)
		}
		if string(data) != "" {
			t.Fatalf("expected empty blocklist file at %s, got %q", blocklistPath, string(data))
		}
	}
}
