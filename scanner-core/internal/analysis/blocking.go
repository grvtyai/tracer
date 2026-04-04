package analysis

import (
	"sort"
	"strconv"
	"strings"

	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
)

// BlockingAssessment represents the result of evidence correlation.
type BlockingAssessment struct {
	Target       string              `json:"target"`
	Port         int                 `json:"port,omitempty"`
	Verdict      evidence.Verdict    `json:"verdict"`
	Confidence   evidence.Confidence `json:"confidence"`
	Reasons      []string            `json:"reasons,omitempty"`
	EvidenceRefs []string            `json:"evidence_refs,omitempty"`
}

type assessmentKey struct {
	target string
	port   int
}

// BuildBlockingAssessments derives target- and port-level blocking assessments
// from the normalized evidence collected so far.
func BuildBlockingAssessments(records []evidence.Record) []BlockingAssessment {
	targetKeys := make(map[assessmentKey]struct{})
	portKeys := make(map[assessmentKey]struct{})

	for _, record := range records {
		if strings.TrimSpace(record.Target) == "" {
			continue
		}

		targetKeys[assessmentKey{target: record.Target}] = struct{}{}

		switch record.Kind {
		case "open_port", "service_fingerprint", "timeout", "passive_conn", "passive_http":
			if record.Port != 0 {
				portKeys[assessmentKey{target: record.Target, port: record.Port}] = struct{}{}
			}
		case "route_hop":
			if explicitAdministrativeBlock(record) {
				portKeys[assessmentKey{target: record.Target}] = struct{}{}
			}
		}
	}

	assessments := make([]BlockingAssessment, 0, len(targetKeys)+len(portKeys))

	for key := range targetKeys {
		related := filterRecords(records, key.target, 0)
		if assessment, ok := classifyTarget(key.target, related); ok {
			assessments = append(assessments, assessment)
		}
	}

	for key := range portKeys {
		if key.port == 0 {
			continue
		}

		related := filterRecords(records, key.target, key.port)
		if assessment, ok := classifyPort(key.target, key.port, related); ok {
			assessments = append(assessments, assessment)
		}
	}

	sort.SliceStable(assessments, func(i, j int) bool {
		if assessments[i].Target != assessments[j].Target {
			return assessments[i].Target < assessments[j].Target
		}
		return assessments[i].Port < assessments[j].Port
	})

	return assessments
}

func ClassifyBlocking(records []evidence.Record) BlockingAssessment {
	assessments := BuildBlockingAssessments(records)
	if len(assessments) == 0 {
		return BlockingAssessment{
			Verdict:    evidence.VerdictAmbiguous,
			Confidence: evidence.ConfidenceAmbiguous,
		}
	}

	return assessments[0]
}

func classifyTarget(target string, records []evidence.Record) (BlockingAssessment, bool) {
	result := BlockingAssessment{
		Target:     target,
		Verdict:    evidence.VerdictAmbiguous,
		Confidence: evidence.ConfidenceAmbiguous,
	}

	if record, ok := findExplicitAdministrativeBlock(records); ok {
		result.Verdict = evidence.VerdictConfirmedBlocked
		result.Confidence = evidence.ConfidenceConfirmed
		result.Reasons = []string{"explicit administrative prohibition observed on route"}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	if record, ok := findRouteCompletion(records); ok {
		result.Verdict = evidence.VerdictReachable
		result.Confidence = evidence.ConfidenceConfirmed
		result.Reasons = []string{"route trace completed to target"}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	if record, ok := findActiveReachableTarget(records); ok {
		result.Verdict = evidence.VerdictReachable
		result.Confidence = evidence.ConfidenceConfirmed
		result.Reasons = []string{activeReachableTargetReason(record)}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	if record, ok := findPassiveReachable(records); ok {
		result.Verdict = evidence.VerdictReachable
		result.Confidence = evidence.ConfidenceConfirmed
		result.Reasons = []string{"passive telemetry observed successful traffic to target"}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	if record, ok := findRouteFailure(records); ok {
		result.Verdict = evidence.VerdictProbableBlocked
		result.Confidence = evidence.ConfidenceProbable
		result.Reasons = []string{"route trace stopped before confidently reaching the target"}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	return BlockingAssessment{}, false
}

func classifyPort(target string, port int, records []evidence.Record) (BlockingAssessment, bool) {
	result := BlockingAssessment{
		Target:     target,
		Port:       port,
		Verdict:    evidence.VerdictAmbiguous,
		Confidence: evidence.ConfidenceAmbiguous,
	}

	if record, ok := findExplicitAdministrativeBlock(records); ok {
		result.Verdict = evidence.VerdictConfirmedBlocked
		result.Confidence = evidence.ConfidenceConfirmed
		result.Reasons = []string{"explicit administrative prohibition observed"}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	if record, ok := findReachablePort(records); ok {
		result.Verdict = evidence.VerdictReachable
		result.Confidence = evidence.ConfidenceConfirmed
		result.Reasons = []string{reachableReason(record)}
		result.EvidenceRefs = []string{record.ID}
		return result, true
	}

	timeouts := timeoutRecords(records)
	if len(timeouts) >= 2 && distinctSources(timeouts) >= 2 {
		result.Verdict = evidence.VerdictProbableBlocked
		result.Confidence = evidence.ConfidenceProbable
		result.Reasons = []string{"multiple timeout-style observations without explicit reject signal"}
		result.EvidenceRefs = evidenceIDs(timeouts)
		return result, true
	}

	if len(timeouts) == 1 {
		result.Verdict = evidence.VerdictAmbiguous
		result.Confidence = evidence.ConfidenceAmbiguous
		result.Reasons = []string{"single timeout observation without explicit reject signal"}
		result.EvidenceRefs = evidenceIDs(timeouts)
		return result, true
	}

	return BlockingAssessment{}, false
}

func filterRecords(records []evidence.Record, target string, port int) []evidence.Record {
	filtered := make([]evidence.Record, 0)

	for _, record := range records {
		if record.Target != target {
			continue
		}
		if port != 0 && record.Port != 0 && record.Port != port {
			continue
		}
		if port != 0 && record.Port == 0 && record.Kind != "route_hop" && record.Kind != "route_trace" {
			continue
		}

		filtered = append(filtered, record)
	}

	return filtered
}

func findExplicitAdministrativeBlock(records []evidence.Record) (evidence.Record, bool) {
	for _, record := range records {
		if explicitAdministrativeBlock(record) {
			return record, true
		}
	}

	return evidence.Record{}, false
}

func explicitAdministrativeBlock(record evidence.Record) bool {
	if strings.EqualFold(strings.TrimSpace(record.Attributes["signal"]), "admin_prohibited") {
		return true
	}

	icmpType, typeOK := parseInt(record.Attributes["icmp_type"])
	icmpCode, codeOK := parseInt(record.Attributes["icmp_code"])
	return typeOK && codeOK && icmpType == 3 && icmpCode == 13
}

func findRouteCompletion(records []evidence.Record) (evidence.Record, bool) {
	for _, record := range records {
		if record.Kind != "route_trace" {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(record.Attributes["completed"]), "true") {
			return record, true
		}
		if strings.EqualFold(strings.TrimSpace(record.Attributes["final_hop_addr"]), record.Target) {
			return record, true
		}
	}

	return evidence.Record{}, false
}

func findRouteFailure(records []evidence.Record) (evidence.Record, bool) {
	for _, record := range records {
		if record.Kind != "route_trace" {
			continue
		}

		switch strings.ToUpper(strings.TrimSpace(record.Attributes["stop_reason"])) {
		case "GAPLIMIT", "HOPLIMIT", "LOOP", "UNREACH":
			return record, true
		}
	}

	return evidence.Record{}, false
}

func findReachablePort(records []evidence.Record) (evidence.Record, bool) {
	for _, record := range records {
		switch record.Kind {
		case "service_fingerprint", "open_port":
			return record, true
		case "passive_http":
			return record, true
		case "passive_conn":
			if passiveConnReachable(record) {
				return record, true
			}
		}
	}

	return evidence.Record{}, false
}

func findPassiveReachable(records []evidence.Record) (evidence.Record, bool) {
	for _, record := range records {
		switch record.Kind {
		case "passive_http":
			return record, true
		case "passive_conn":
			if passiveConnReachable(record) {
				return record, true
			}
		}
	}

	return evidence.Record{}, false
}

func findActiveReachableTarget(records []evidence.Record) (evidence.Record, bool) {
	for _, record := range records {
		switch record.Kind {
		case "open_port", "service_fingerprint", "http_probe", "l7_grab":
			return record, true
		}
	}

	return evidence.Record{}, false
}

func timeoutRecords(records []evidence.Record) []evidence.Record {
	timeoutLike := make([]evidence.Record, 0)
	for _, record := range records {
		if record.Kind == "timeout" {
			timeoutLike = append(timeoutLike, record)
		}
	}

	return timeoutLike
}

func distinctSources(records []evidence.Record) int {
	seen := make(map[string]struct{})
	for _, record := range records {
		seen[record.Source] = struct{}{}
	}
	return len(seen)
}

func evidenceIDs(records []evidence.Record) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

func passiveConnReachable(record evidence.Record) bool {
	state := strings.ToUpper(strings.TrimSpace(record.Attributes["conn_state"]))
	if state == "" {
		return false
	}

	switch state {
	case "S0":
		return false
	default:
		return true
	}
}

func reachableReason(record evidence.Record) string {
	switch record.Kind {
	case "passive_http":
		return "passive telemetry observed HTTP traffic on the port"
	case "passive_conn":
		return "passive telemetry observed a response on the port"
	default:
		return "port responded to active probing"
	}
}

func activeReachableTargetReason(record evidence.Record) string {
	switch record.Kind {
	case "service_fingerprint":
		return "active service fingerprinting confirmed the target is reachable"
	case "http_probe":
		return "active HTTP probing confirmed the target is reachable"
	case "l7_grab":
		return "application grab confirmed the target is reachable"
	default:
		return "active probing confirmed the target is reachable"
	}
}

func parseInt(value string) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return parsed, true
}
