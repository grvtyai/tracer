package avahi

import (
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

func TestParseOutputResolvedService(t *testing.T) {
	job := jobs.Job{ID: "job-1", Kind: jobs.KindLocalService}
	output := []byte("=;eth0;IPv4;Office Printer;_ipp._tcp;local;printer.local;192.168.1.42;631;txtvers=1\n")

	records, err := ParseOutput(output, job, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Target != "192.168.1.42" {
		t.Fatalf("unexpected target: %q", records[0].Target)
	}
	if records[0].Port != 631 {
		t.Fatalf("unexpected port: %d", records[0].Port)
	}
	if records[0].Attributes["service_type"] != "_ipp._tcp" {
		t.Fatalf("unexpected service type: %q", records[0].Attributes["service_type"])
	}
}
