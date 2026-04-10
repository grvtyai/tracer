package httpx

import (
	"context"
	"errors"
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
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string) ([]byte, error) {
	f.name = name
	f.args = append([]string{}, args...)
	return f.output, f.err
}

func TestBuildArgs(t *testing.T) {
	job := jobs.Job{
		ID:             "http-10.0.0.10",
		Kind:           jobs.KindWebProbe,
		Targets:        []string{"10.0.0.10"},
		Ports:          []int{80, 443},
		ServiceClass:   "web",
		ServiceClasses: []string{"web"},
		Metadata: map[string]string{
			"tech_detect":      "true",
			"follow_redirects": "true",
			"retries":          "2",
			"timeout":          "10",
		},
	}

	got := BuildArgs(job)
	want := []string{
		"-json", "-silent",
		"-td",
		"-fr",
		"-retries", "2",
		"-timeout", "10",
		"-u", "10.0.0.10:80",
		"-u", "10.0.0.10:443",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestParseOutputBuildsHTTPRecords(t *testing.T) {
	job := jobs.Job{
		ID:             "http-10.0.0.10",
		Kind:           jobs.KindWebProbe,
		Targets:        []string{"10.0.0.10"},
		Ports:          []int{443},
		ServiceClass:   "web",
		ServiceClasses: []string{"web"},
		Metadata: map[string]string{
			"run_id":                     "run-1",
			"host_primary_service_class": "remote_access",
			"host_service_classes":       "remote_access,messaging,printing,web",
		},
	}

	output := []byte(`{"timestamp":"2026-04-01T11:20:00.000000000Z","port":"443","url":"https://10.0.0.10","input":"10.0.0.10:443","title":"Welcome","scheme":"https","webserver":"nginx","content_type":"text/html","method":"GET","host":"10.0.0.10","status_code":200,"content_length":1234,"tech":["nginx","ubuntu"]}`)

	records, err := ParseOutput(output, job, time.Date(2026, 4, 1, 11, 20, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	record := records[0]
	if record.Kind != "http_probe" {
		t.Fatalf("unexpected kind: %s", record.Kind)
	}
	if record.Port != 443 {
		t.Fatalf("expected port 443, got %d", record.Port)
	}
	if record.Attributes["service_class"] != "web" {
		t.Fatalf("expected web service class, got %q", record.Attributes["service_class"])
	}
	if record.Attributes["host_primary_service_class"] != "remote_access" {
		t.Fatalf("expected inherited host primary class, got %q", record.Attributes["host_primary_service_class"])
	}
	if record.Attributes["status_code"] != "200" {
		t.Fatalf("expected status_code 200, got %q", record.Attributes["status_code"])
	}
}

func TestPluginRun(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`{"url":"https://10.0.0.20","host":"10.0.0.20","port":"8443","scheme":"https","status_code":200}`),
	}

	now := time.Date(2026, 4, 1, 11, 30, 0, 0, time.UTC)
	plugin := &Plugin{
		binary: "httpx-bin",
		runner: runner,
		now: func() time.Time {
			return now
		},
	}

	job := jobs.Job{
		ID:      "http-10.0.0.20",
		Kind:    jobs.KindWebProbe,
		Targets: []string{"10.0.0.20"},
		Ports:   []int{8443},
	}

	records, err := plugin.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if runner.name != "httpx-bin" {
		t.Fatalf("unexpected binary: %s", runner.name)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].ObservedAt != now {
		t.Fatalf("unexpected observed time: %v", records[0].ObservedAt)
	}
}

func TestPluginRunRequiresTargets(t *testing.T) {
	plugin := New()

	_, err := plugin.Run(context.Background(), jobs.Job{ID: "empty", Kind: jobs.KindWebProbe})
	if err == nil {
		t.Fatal("expected error for missing targets")
	}
}

func TestPluginRunIncludesCommandFailureOutput(t *testing.T) {
	runner := &fakeRunner{
		output: []byte("httpx: target unavailable"),
		err:    errors.New("exit status 1"),
	}

	plugin := &Plugin{
		runner: runner,
		now:    time.Now,
	}

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "http-10.0.0.10",
		Kind:    jobs.KindWebProbe,
		Targets: []string{"10.0.0.10"},
	})
	if err == nil {
		t.Fatal("expected runner error")
	}
	if !strings.Contains(err.Error(), "target unavailable") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}
