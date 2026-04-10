package naabu

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
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
		ID:      "port-discovery",
		Kind:    jobs.KindPortDiscover,
		Targets: []string{"10.0.0.10", "10.0.0.11"},
		Ports:   []int{80, 443},
		Metadata: map[string]string{
			"rate":         "1000",
			"retries":      "2",
			"warm_up_time": "1",
			"scan_type":    "connect",
			"exclude_cdn":  "true",
		},
	}

	got := BuildArgs(job)
	want := []string{
		"-json",
		"-silent",
		"-p", "80,443",
		"-rate", "1000",
		"-retries", "2",
		"-warm-up-time", "1",
		"-scan-type", "connect",
		"-exclude-cdn",
		"-host", "10.0.0.10,10.0.0.11",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestParseOutputJSONAndPlainLines(t *testing.T) {
	job := jobs.Job{
		ID:      "port-discovery",
		Kind:    jobs.KindPortDiscover,
		Targets: []string{"10.0.0.10"},
		Metadata: map[string]string{
			"run_id": "run-1",
		},
	}

	observedAt := time.Date(2026, 3, 31, 20, 0, 0, 0, time.UTC)
	output := strings.Join([]string{
		`{"ip":"10.0.0.10","port":443,"protocol":"tcp"}`,
		"10.0.0.11:53 udp",
	}, "\n")

	records, err := ParseOutput([]byte(output), job, observedAt)
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].Target != "10.0.0.10" || records[0].Port != 443 || records[0].Protocol != "tcp" {
		t.Fatalf("unexpected first record: %#v", records[0])
	}

	if records[1].Target != "10.0.0.11" || records[1].Port != 53 || records[1].Protocol != "udp" {
		t.Fatalf("unexpected second record: %#v", records[1])
	}

	if records[0].Confidence != evidence.ConfidenceConfirmed {
		t.Fatalf("expected confirmed confidence, got %s", records[0].Confidence)
	}
}

func TestPluginRun(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`{"ip":"10.0.0.10","port":8443,"protocol":"tcp"}`),
	}

	now := time.Date(2026, 3, 31, 20, 30, 0, 0, time.UTC)
	plugin := &Plugin{
		binary: "naabu-bin",
		runner: runner,
		now: func() time.Time {
			return now
		},
	}

	job := jobs.Job{
		ID:      "port-discovery",
		Kind:    jobs.KindPortDiscover,
		Targets: []string{"10.0.0.10"},
		Ports:   []int{8443},
	}

	records, err := plugin.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if runner.name != "naabu-bin" {
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

	_, err := plugin.Run(context.Background(), jobs.Job{ID: "empty", Kind: jobs.KindPortDiscover})
	if err == nil {
		t.Fatal("expected error for missing targets")
	}
}

func TestPluginRunIncludesCommandFailureOutput(t *testing.T) {
	runner := &fakeRunner{
		output: []byte("naabu: command not found"),
		err:    errors.New("exit status 1"),
	}

	plugin := &Plugin{
		runner: runner,
		now:    time.Now,
	}

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "port-discovery",
		Kind:    jobs.KindPortDiscover,
		Targets: []string{"10.0.0.10"},
	})
	if err == nil {
		t.Fatal("expected runner error")
	}

	if !strings.Contains(err.Error(), "command not found") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}
