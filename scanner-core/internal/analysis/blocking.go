package analysis

import "github.com/grvtyai/tracer/scanner-core/internal/evidence"

// BlockingAssessment represents the result of evidence correlation.
type BlockingAssessment struct {
	Target       string                `json:"target"`
	Port         int                   `json:"port,omitempty"`
	Verdict      evidence.Verdict      `json:"verdict"`
	Confidence   evidence.Confidence   `json:"confidence"`
	Reasons      []string              `json:"reasons,omitempty"`
	EvidenceRefs []string              `json:"evidence_refs,omitempty"`
}

// ClassifyBlocking keeps the three-level model explicit from day one.
func ClassifyBlocking(records []evidence.Record) BlockingAssessment {
	result := BlockingAssessment{
		Verdict:    evidence.VerdictAmbiguous,
		Confidence: evidence.ConfidenceAmbiguous,
	}

	for _, record := range records {
		if record.Attributes["signal"] == "admin_prohibited" {
			result.Target = record.Target
			result.Port = record.Port
			result.Verdict = evidence.VerdictConfirmedBlocked
			result.Confidence = evidence.ConfidenceConfirmed
			result.Reasons = append(result.Reasons, "explicit administrative prohibition observed")
			result.EvidenceRefs = append(result.EvidenceRefs, record.ID)
			return result
		}
	}

	for _, record := range records {
		if record.Kind == "timeout" {
			result.Target = record.Target
			result.Port = record.Port
			result.Reasons = append(result.Reasons, "timeout without explicit reject signal")
			result.EvidenceRefs = append(result.EvidenceRefs, record.ID)
		}
	}

	if len(result.Reasons) > 0 {
		result.Verdict = evidence.VerdictProbableBlocked
		result.Confidence = evidence.ConfidenceProbable
	}

	return result
}
