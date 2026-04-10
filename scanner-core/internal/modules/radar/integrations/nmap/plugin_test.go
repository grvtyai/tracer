package nmap

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
		ID:      "service-host",
		Kind:    jobs.KindServiceProbe,
		Targets: []string{"10.0.0.10"},
		Ports:   []int{80, 443},
		Metadata: map[string]string{
			"os_detection":      "true",
			"version_intensity": "7",
			"timing_template":   "4",
		},
	}

	got := BuildArgs(job)
	want := []string{
		"-oX", "-",
		"-Pn",
		"-sV",
		"-O",
		"--version-intensity", "7",
		"-T4",
		"-p", "80,443",
		"10.0.0.10",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestParseOutputBuildsServiceAndOSRecords(t *testing.T) {
	job := jobs.Job{
		ID:           "service-10.0.0.10",
		Kind:         jobs.KindServiceProbe,
		Plugin:       "nmap",
		Targets:      []string{"10.0.0.10"},
		ServiceClass: "web",
		Metadata: map[string]string{
			"run_id": "run-1",
		},
	}

	observedAt := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	output := []byte(`
<nmaprun>
  <host>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web01.lab.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15 - 6.1" accuracy="98">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="98"/>
      </osmatch>
    </os>
  </host>
</nmaprun>`)

	records, err := ParseOutput(output, job, observedAt)
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}

	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	openStateRecord := records[0]
	if openStateRecord.Kind != "port_state" {
		t.Fatalf("unexpected first record kind: %s", openStateRecord.Kind)
	}
	if openStateRecord.Attributes["state"] != "open" {
		t.Fatalf("expected open state, got %#v", openStateRecord.Attributes)
	}

	serviceRecord := records[1]
	if serviceRecord.Kind != "service_fingerprint" {
		t.Fatalf("unexpected service record kind: %s", serviceRecord.Kind)
	}
	if serviceRecord.Target != "10.0.0.10" || serviceRecord.Port != 443 {
		t.Fatalf("unexpected service record target/port: %#v", serviceRecord)
	}
	if serviceRecord.Attributes["service_name"] != "https" {
		t.Fatalf("expected service_name https, got %q", serviceRecord.Attributes["service_name"])
	}
	if serviceRecord.Attributes["hostname"] != "web01.lab.local" {
		t.Fatalf("expected hostname, got %q", serviceRecord.Attributes["hostname"])
	}
	if serviceRecord.Attributes["service_class"] != "web" {
		t.Fatalf("expected per-service class web, got %q", serviceRecord.Attributes["service_class"])
	}

	closedStateRecord := records[2]
	if closedStateRecord.Kind != "port_state" {
		t.Fatalf("unexpected closed state record kind: %s", closedStateRecord.Kind)
	}
	if closedStateRecord.Port != 22 || closedStateRecord.Attributes["state"] != "closed" {
		t.Fatalf("unexpected closed state record: %#v", closedStateRecord)
	}

	osRecord := records[3]
	if osRecord.Kind != "host_os_fingerprint" {
		t.Fatalf("unexpected os record kind: %s", osRecord.Kind)
	}
	if osRecord.Attributes["os_family"] != "Linux" {
		t.Fatalf("expected Linux family, got %q", osRecord.Attributes["os_family"])
	}
	if osRecord.Confidence != evidence.ConfidenceConfirmed {
		t.Fatalf("expected confirmed OS confidence, got %s", osRecord.Confidence)
	}
}

func TestPluginRun(t *testing.T) {
	runner := &fakeRunner{
		output: []byte(`
<nmaprun>
  <host>
    <address addr="10.0.0.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8443">
        <state state="open" reason="syn-ack"/>
        <service name="https-alt" product="Caddy" version="2.8.4"/>
      </port>
    </ports>
  </host>
</nmaprun>`),
	}

	now := time.Date(2026, 4, 1, 10, 30, 0, 0, time.UTC)
	plugin := &Plugin{
		binary: "nmap-bin",
		runner: runner,
		now: func() time.Time {
			return now
		},
	}

	job := jobs.Job{
		ID:      "service-10.0.0.20",
		Kind:    jobs.KindServiceProbe,
		Targets: []string{"10.0.0.20"},
		Ports:   []int{8443},
	}

	records, err := plugin.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if runner.name != "nmap-bin" {
		t.Fatalf("unexpected binary: %s", runner.name)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[1].Attributes["service_class"] != "web" {
		t.Fatalf("expected web classification for 8443, got %q", records[1].Attributes["service_class"])
	}
	if records[1].ObservedAt != now {
		t.Fatalf("unexpected observed time: %v", records[1].ObservedAt)
	}
}

func TestPluginRunRequiresTargets(t *testing.T) {
	plugin := New()

	_, err := plugin.Run(context.Background(), jobs.Job{ID: "empty", Kind: jobs.KindServiceProbe})
	if err == nil {
		t.Fatal("expected error for missing targets")
	}
}

func TestPluginRunIncludesCommandFailureOutput(t *testing.T) {
	runner := &fakeRunner{
		output: []byte("nmap: failed to resolve target"),
		err:    errors.New("exit status 1"),
	}

	plugin := &Plugin{
		runner: runner,
		now:    time.Now,
	}

	_, err := plugin.Run(context.Background(), jobs.Job{
		ID:      "service-10.0.0.10",
		Kind:    jobs.KindServiceProbe,
		Targets: []string{"10.0.0.10"},
	})
	if err == nil {
		t.Fatal("expected runner error")
	}
	if !strings.Contains(err.Error(), "failed to resolve target") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}
