package analysis

import (
	"testing"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

func TestBuildReevaluationHintsFromJobFailureAndAmbiguousBlocking(t *testing.T) {
	hints := BuildReevaluationHints(
		[]jobs.ExecutionResult{
			{
				JobID:              "service-10.0.0.10",
				Kind:               jobs.KindServiceProbe,
				Plugin:             "nmap",
				Targets:            []string{"10.0.0.10"},
				Ports:              []int{443},
				Status:             jobs.StatusFailed,
				StartedAt:          time.Date(2026, 4, 3, 12, 0, 0, 0, time.UTC),
				FinishedAt:         time.Date(2026, 4, 3, 12, 1, 0, 0, time.UTC),
				NeedsReevaluation:  true,
				ReevaluationAfter:  "20m",
				ReevaluationReason: "job execution failed before the full scan pipeline completed",
			},
		},
		[]BlockingAssessment{
			{
				Target:       "10.0.0.10",
				Port:         443,
				Verdict:      evidence.VerdictAmbiguous,
				Confidence:   evidence.ConfidenceAmbiguous,
				EvidenceRefs: []string{"timeout-1"},
			},
		},
		"30m",
	)

	if len(hints) != 2 {
		t.Fatalf("expected 2 reevaluation hints, got %d", len(hints))
	}
	if hints[0].Target != "10.0.0.10" {
		t.Fatalf("unexpected hint target: %#v", hints[0])
	}
}
