package scamper

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
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
		ID:             "route-10.0.0.10",
		Kind:           jobs.KindRouteProbe,
		Targets:        []string{"10.0.0.10"},
		Ports:          []int{443},
		ServiceClass:   "web",
		ServiceClasses: []string{"web"},
		Metadata: map[string]string{
			"trace_method": "tcp",
			"attempts":     "2",
			"wait":         "3",
			"max_ttl":      "24",
			"pps":          "10",
			"window":       "1",
		},
	}

	got := BuildArgs(job)
	want := []string{
		"-O", "json",
		"-c", "trace -P tcp -q 2 -w 3 -m 24 -d 443",
		"-i", "10.0.0.10",
		"-p", "10",
		"-w", "1",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestParseOutputBuildsRouteAndHopRecords(t *testing.T) {
	job := jobs.Job{
		ID:             "route-10.0.0.10",
		Kind:           jobs.KindRouteProbe,
		Plugin:         "scamper",
		Targets:        []string{"10.0.0.10"},
		ServiceClass:   "web",
		ServiceClasses: []string{"web"},
		Metadata: map[string]string{
			"run_id": "run-1",
		},
	}

	output := []byte(`{"type":"trace","version":"0.1","method":"icmp-paris","src":"10.0.0.5","dst":"10.0.0.10","stop_reason":"COMPLETED","stop_data":0,"hop_count":3,"start":{"sec":1711965600,"usec":123456},"hops":[{"addr":"10.0.0.1","probe_ttl":1,"probe_id":0,"rtt":0.321,"reply_ttl":64},{"addr":"10.0.0.10","probe_ttl":2,"probe_id":0,"rtt":0.654,"reply_ttl":64,"icmp_type":0,"icmp_code":0}]}`)

	records, err := ParseOutput(output, job, time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	routeRecord := records[0]
	if routeRecord.Kind != "route_trace" {
		t.Fatalf("unexpected route record kind: %s", routeRecord.Kind)
	}
	if routeRecord.Attributes["final_hop_addr"] != "10.0.0.10" {
		t.Fatalf("expected final hop attr, got %#v", routeRecord.Attributes)
	}
	if routeRecord.Confidence != evidence.ConfidenceConfirmed {
		t.Fatalf("expected confirmed route confidence, got %s", routeRecord.Confidence)
	}

	hopRecord := records[1]
	if hopRecord.Kind != "route_hop" {
		t.Fatalf("unexpected hop record kind: %s", hopRecord.Kind)
	}
	if hopRecord.Attributes["probe_ttl"] != "1" {
		t.Fatalf("expected ttl attr, got %#v", hopRecord.Attributes)
	}
	if hopRecord.Attributes["service_class"] != "web" {
		t.Fatalf("expected inherited host class, got %q", hopRecord.Attributes["service_class"])
	}
}

func TestPluginRun(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`{"type":"trace","version":"0.1","method":"icmp-paris","dst":"10.0.0.20","stop_reason":"COMPLETED","hop_count":1,"hops":[{"addr":"10.0.0.20","probe_ttl":1,"probe_id":0,"rtt":0.12}]}`),
	}

	now := time.Date(2026, 4, 1, 12, 30, 0, 0, time.UTC)
	plugin := &Plugin{
		binary: "scamper-bin",
		runner: runner,
		now: func() time.Time {
			return now
		},
	}

	job := jobs.Job{
		ID:      "route-10.0.0.20",
		Kind:    jobs.KindRouteProbe,
		Targets: []string{"10.0.0.20"},
	}

	records, err := plugin.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if runner.name != "scamper-bin" {
		t.Fatalf("unexpected binary: %s", runner.name)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].ObservedAt != now {
		t.Fatalf("unexpected observed time: %v", records[0].ObservedAt)
	}
}

func TestPluginRunRequiresTargets(t *testing.T) {
	plugin := New()

	_, err := plugin.Run(context.Background(), jobs.Job{ID: "empty", Kind: jobs.KindRouteProbe})
	if err == nil {
		t.Fatal("expected error for missing targets")
	}
}

func TestPluginRunIncludesCommandFailureOutput(t *testing.T) {
	runner := &fakeRunner{
		output: []byte("scamper: permission denied"),
		err:    errors.New("exit status 1"),
	}

	plugin := &Plugin{
		runner: runner,
		now:    time.Now,
	}

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "route-10.0.0.10",
		Kind:    jobs.KindRouteProbe,
		Targets: []string{"10.0.0.10"},
	})
	if err == nil {
		t.Fatal("expected runner error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}
