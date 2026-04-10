package analysis

import (
	"reflect"
	"testing"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
)

func TestBuildBlockingAssessmentsReachablePortAndTarget(t *testing.T) {
	records := []evidence.Record{
		{
			ID:       "route-1",
			Source:   "scamper",
			Kind:     "route_trace",
			Target:   "10.0.0.10",
			Protocol: "ip",
			Attributes: map[string]string{
				"completed":      "true",
				"final_hop_addr": "10.0.0.10",
			},
		},
		{
			ID:       "open-1",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "10.0.0.10",
			Port:     443,
			Protocol: "tcp",
		},
		{
			ID:       "svc-1",
			Source:   "nmap",
			Kind:     "service_fingerprint",
			Target:   "10.0.0.10",
			Port:     443,
			Protocol: "tcp",
		},
	}

	got := BuildBlockingAssessments(records)
	if len(got) != 2 {
		t.Fatalf("expected 2 assessments, got %d", len(got))
	}

	if got[0].Port != 0 || got[0].Verdict != evidence.VerdictReachable {
		t.Fatalf("unexpected target assessment: %#v", got[0])
	}
	if got[1].Port != 443 || got[1].Verdict != evidence.VerdictReachable {
		t.Fatalf("unexpected port assessment: %#v", got[1])
	}
}

func TestBuildBlockingAssessmentsConfirmedBlockedFromAdminProhibited(t *testing.T) {
	records := []evidence.Record{
		{
			ID:       "hop-1",
			Source:   "scamper",
			Kind:     "route_hop",
			Target:   "10.0.0.20",
			Protocol: "ip",
			Attributes: map[string]string{
				"icmp_type": "3",
				"icmp_code": "13",
			},
		},
	}

	got := BuildBlockingAssessments(records)
	if len(got) != 1 {
		t.Fatalf("expected 1 assessment, got %d", len(got))
	}
	if got[0].Verdict != evidence.VerdictConfirmedBlocked {
		t.Fatalf("expected confirmed_blocked, got %#v", got[0])
	}
}

func TestBuildBlockingAssessmentsProbableAndAmbiguousTimeouts(t *testing.T) {
	probable := BuildBlockingAssessments([]evidence.Record{
		{ID: "t1", Source: "probe-a", Kind: "timeout", Target: "10.0.0.30", Port: 443, Protocol: "tcp"},
		{ID: "t2", Source: "probe-b", Kind: "timeout", Target: "10.0.0.30", Port: 443, Protocol: "tcp"},
	})

	if len(probable) != 1 {
		t.Fatalf("expected 1 port assessment, got %d", len(probable))
	}
	if probable[0].Verdict != evidence.VerdictProbableBlocked {
		t.Fatalf("expected probable_blocked port assessment, got %#v", probable[0])
	}

	ambiguous := BuildBlockingAssessments([]evidence.Record{
		{ID: "t1", Source: "probe-a", Kind: "timeout", Target: "10.0.0.31", Port: 443, Protocol: "tcp"},
	})

	if len(ambiguous) != 1 {
		t.Fatalf("expected 1 port assessment, got %d", len(ambiguous))
	}
	if ambiguous[0].Verdict != evidence.VerdictAmbiguous {
		t.Fatalf("expected ambiguous port assessment, got %#v", ambiguous[0])
	}
}

func TestClassifyBlockingReturnsFirstSortedAssessment(t *testing.T) {
	records := []evidence.Record{
		{ID: "open-1", Source: "naabu", Kind: "open_port", Target: "10.0.0.10", Port: 22, Protocol: "tcp"},
	}

	got := ClassifyBlocking(records)
	want := BlockingAssessment{
		Target:       "10.0.0.10",
		Port:         0,
		Verdict:      evidence.VerdictReachable,
		Confidence:   evidence.ConfidenceConfirmed,
		Reasons:      []string{"active probing confirmed the target is reachable"},
		EvidenceRefs: []string{"open-1"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected assessment\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestBuildBlockingAssessmentsReachableFromPassiveEvidence(t *testing.T) {
	records := []evidence.Record{
		{
			ID:       "conn-1",
			Source:   "zeek",
			Kind:     "passive_conn",
			Target:   "10.0.0.50",
			Port:     443,
			Protocol: "tcp",
			Attributes: map[string]string{
				"conn_state": "SF",
			},
		},
		{
			ID:       "http-1",
			Source:   "zeek",
			Kind:     "passive_http",
			Target:   "10.0.0.50",
			Port:     443,
			Protocol: "tcp",
		},
	}

	got := BuildBlockingAssessments(records)
	if len(got) != 2 {
		t.Fatalf("expected 2 assessments, got %d", len(got))
	}

	if got[0].Target != "10.0.0.50" || got[0].Port != 0 || got[0].Verdict != evidence.VerdictReachable {
		t.Fatalf("unexpected target assessment: %#v", got[0])
	}
	if got[1].Port != 443 || got[1].Verdict != evidence.VerdictReachable {
		t.Fatalf("unexpected port assessment: %#v", got[1])
	}
	if got[1].Reasons[0] != "passive telemetry observed a response on the port" {
		t.Fatalf("unexpected port reason: %#v", got[1])
	}
}

func TestBuildBlockingAssessmentsActiveReachabilityOverridesRouteFailureAtTargetLevel(t *testing.T) {
	records := []evidence.Record{
		{
			ID:       "route-1",
			Source:   "scamper",
			Kind:     "route_trace",
			Target:   "192.168.178.30",
			Protocol: "ip",
			Attributes: map[string]string{
				"stop_reason": "GAPLIMIT",
			},
		},
		{
			ID:       "open-1",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "192.168.178.30",
			Port:     8888,
			Protocol: "tcp",
		},
	}

	got := BuildBlockingAssessments(records)
	if len(got) != 2 {
		t.Fatalf("expected 2 assessments, got %d", len(got))
	}
	if got[0].Target != "192.168.178.30" || got[0].Port != 0 || got[0].Verdict != evidence.VerdictReachable {
		t.Fatalf("expected target-level reachable assessment, got %#v", got[0])
	}
	if got[0].Reasons[0] != "active probing confirmed the target is reachable" {
		t.Fatalf("unexpected target-level reason: %#v", got[0])
	}
}
