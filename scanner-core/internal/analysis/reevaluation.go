package analysis

import (
	"fmt"
	"sort"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
)

type ReevaluationHint struct {
	Target         string   `json:"target,omitempty"`
	Port           int      `json:"port,omitempty"`
	Reason         string   `json:"reason"`
	SuggestedAfter string   `json:"suggested_after,omitempty"`
	Sources        []string `json:"sources,omitempty"`
}

func BuildReevaluationHints(jobResults []jobs.ExecutionResult, assessments []BlockingAssessment, suggestedAfter string) []ReevaluationHint {
	hints := make([]ReevaluationHint, 0)

	for _, result := range jobResults {
		if !result.NeedsReevaluation {
			continue
		}

		targets := result.Targets
		if len(targets) == 0 {
			targets = []string{""}
		}

		for _, target := range targets {
			hint := ReevaluationHint{
				Target:         target,
				Reason:         result.ReevaluationReason,
				SuggestedAfter: firstNonEmpty(result.ReevaluationAfter, suggestedAfter),
				Sources:        []string{result.JobID},
			}
			if len(result.Ports) == 1 {
				hint.Port = result.Ports[0]
			}
			hints = append(hints, hint)
		}
	}

	for _, assessment := range assessments {
		if assessment.Verdict != evidence.VerdictAmbiguous && assessment.Verdict != evidence.VerdictProbableBlocked {
			continue
		}

		reason := "ambiguous evidence should be revisited with another observation window"
		if assessment.Verdict == evidence.VerdictProbableBlocked {
			reason = "probable blocking should be rechecked to confirm whether the behavior is persistent"
		}

		hints = append(hints, ReevaluationHint{
			Target:         assessment.Target,
			Port:           assessment.Port,
			Reason:         reason,
			SuggestedAfter: suggestedAfter,
			Sources:        append([]string{}, assessment.EvidenceRefs...),
		})
	}

	sort.SliceStable(hints, func(i, j int) bool {
		if hints[i].Target != hints[j].Target {
			return hints[i].Target < hints[j].Target
		}
		if hints[i].Port != hints[j].Port {
			return hints[i].Port < hints[j].Port
		}
		return hints[i].Reason < hints[j].Reason
	})

	return dedupeHints(hints)
}

func dedupeHints(hints []ReevaluationHint) []ReevaluationHint {
	seen := make(map[string]struct{}, len(hints))
	deduped := make([]ReevaluationHint, 0, len(hints))

	for _, hint := range hints {
		key := fmt.Sprintf("%s|%d|%s|%s", hint.Target, hint.Port, hint.Reason, hint.SuggestedAfter)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, hint)
	}

	return deduped
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
