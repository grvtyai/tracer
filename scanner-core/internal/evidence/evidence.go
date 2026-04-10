package evidence

import "time"

// Confidence expresses how strongly the collected data supports a conclusion.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceProbable  Confidence = "probable"
	ConfidenceAmbiguous Confidence = "ambiguous"
)

// Verdict models the blocking / reachability classification.
type Verdict string

const (
	VerdictReachable        Verdict = "reachable"
	VerdictConfirmedBlocked Verdict = "confirmed_blocked"
	VerdictProbableBlocked  Verdict = "probable_blocked"
	VerdictAmbiguous        Verdict = "ambiguous"
)

// Record stores normalized facts emitted by active and passive tooling.
type Record struct {
	ID         string            `json:"id"`
	RunID      string            `json:"run_id"`
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	Target     string            `json:"target"`
	Port       int               `json:"port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Summary    string            `json:"summary"`
	RawRef     string            `json:"raw_ref,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Confidence Confidence        `json:"confidence"`
	ObservedAt time.Time         `json:"observed_at"`
}
