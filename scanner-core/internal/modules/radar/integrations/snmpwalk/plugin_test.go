package snmpwalk

import (
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

func TestParseOutputSystemTree(t *testing.T) {
	job := jobs.Job{ID: "job-1", Kind: jobs.KindSNMPProbe, Targets: []string{"192.168.1.1"}}
	output := []byte(".1.3.6.1.2.1.1.5.0 router01\n.1.3.6.1.2.1.1.1.0 RouterOS 7.0\n")

	records, err := ParseOutput(output, job, time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatalf("ParseOutput returned error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Attributes["snmp_field"] != "sysName" {
		t.Fatalf("unexpected first field: %q", records[0].Attributes["snmp_field"])
	}
	if records[1].Attributes["snmp_field"] != "sysDescr" {
		t.Fatalf("unexpected second field: %q", records[1].Attributes["snmp_field"])
	}
}
