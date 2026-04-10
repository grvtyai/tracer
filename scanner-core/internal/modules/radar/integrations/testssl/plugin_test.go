package testssl

import (
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

func TestParseOutputJSONArray(t *testing.T) {
	job := jobs.Job{ID: "job-1", Kind: jobs.KindTLSInspect, Targets: []string{"192.168.1.10"}, Ports: []int{443}}
	output := []byte(`[{"id":"TLS1_2","ip":"192.168.1.10","port":"443","severity":"LOW","finding":"TLS 1.2 offered","cve":"","cwe":"","hint":""}]`)

	records, err := ParseOutput(output, job, time.Unix(300, 0).UTC())
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Kind != "tls_check" {
		t.Fatalf("unexpected kind: %q", records[0].Kind)
	}
	if records[0].Attributes["check_id"] != "TLS1_2" {
		t.Fatalf("unexpected check id: %q", records[0].Attributes["check_id"])
	}
}
