package scamper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/platform"
)

type Runner interface {
	Run(ctx context.Context, name string, args []string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type Plugin struct {
	binary string
	runner Runner
	now    func() time.Time
}

var _ engine.Plugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{
		binary: "scamper",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "scamper"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindRouteProbe
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("scamper requires at least one target")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "scamper"
	}
	if _, ok := runner.(ExecRunner); ok {
		resolvedBinary, resolveErr := platform.ResolveExecutable(binary)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve scamper binary: %w", resolveErr)
		}
		binary = resolvedBinary
	}

	output, err := runner.Run(ctx, binary, BuildArgs(job))
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("run scamper: %w", err)
		}
		return nil, fmt.Errorf("run scamper: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return ParseOutput(output, job, p.timeNow())
}

func (p *Plugin) timeNow() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}

	return time.Now().UTC()
}

func BuildArgs(job jobs.Job) []string {
	args := []string{
		"-O", "json",
		"-c", buildTraceCommand(job),
		"-i", strings.Join(job.Targets, ","),
	}

	if pps := strings.TrimSpace(job.Metadata["pps"]); pps != "" {
		args = append(args, "-p", pps)
	}

	if window := strings.TrimSpace(job.Metadata["window"]); window != "" {
		args = append(args, "-w", window)
	}

	return args
}

func buildTraceCommand(job jobs.Job) string {
	method := strings.TrimSpace(job.Metadata["trace_method"])
	if method == "" {
		method = "icmp-paris"
	}

	parts := []string{
		"trace",
		"-P", method,
		"-q", firstNonEmpty(job.Metadata["attempts"], "1"),
		"-w", firstNonEmpty(job.Metadata["wait"], "2"),
		"-m", firstNonEmpty(job.Metadata["max_ttl"], "20"),
	}

	if firstHop := strings.TrimSpace(job.Metadata["first_hop"]); firstHop != "" {
		parts = append(parts, "-f", firstHop)
	}
	if gapLimit := strings.TrimSpace(job.Metadata["gap_limit"]); gapLimit != "" {
		parts = append(parts, "-g", gapLimit)
	}
	if waitProbe := strings.TrimSpace(job.Metadata["wait_probe"]); waitProbe != "" {
		parts = append(parts, "-W", waitProbe)
	}
	if len(job.Ports) > 0 {
		parts = append(parts, "-d", strconv.Itoa(job.Ports[0]))
	}

	return strings.Join(parts, " ")
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func ParseOutput(output []byte, job jobs.Job, observedAt time.Time) ([]evidence.Record, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	records := make([]evidence.Record, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		trace, ok, err := parseTraceLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse scamper json line %d: %w", lineNumber, err)
		}
		if !ok {
			continue
		}

		traceObservedAt := observedAt
		if start, ok := trace.startTime(); ok {
			traceObservedAt = start
		}

		records = append(records, buildRouteRecord(trace, job, traceObservedAt))
		records = append(records, buildHopRecords(trace, job, traceObservedAt)...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan scamper output: %w", err)
	}

	return records, nil
}

func parseTraceLine(line string) (traceResult, bool, error) {
	var header struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(line), &header); err != nil {
		return traceResult{}, false, err
	}
	if !shouldParseType(header.Type) {
		return traceResult{}, false, nil
	}

	var trace traceResult
	if err := json.Unmarshal([]byte(line), &trace); err != nil {
		return traceResult{}, false, err
	}

	if strings.TrimSpace(trace.Dst) == "" {
		return traceResult{}, false, errors.New("missing destination")
	}

	return trace, true, nil
}

func shouldParseType(recordType string) bool {
	switch strings.TrimSpace(recordType) {
	case "trace":
		return true
	case "cycle-start", "cycle-stop", "list-start", "list-stop":
		return false
	default:
		return false
	}
}

func buildRouteRecord(trace traceResult, job jobs.Job, observedAt time.Time) evidence.Record {
	hops := compactHopAddrs(trace.Hops)
	stopReason := strings.TrimSpace(trace.StopReason)
	if stopReason == "" {
		stopReason = "UNKNOWN"
	}

	attributes := map[string]string{
		"job_id":               job.ID,
		"plugin":               "scamper",
		"job_kind":             string(job.Kind),
		"trace_method":         trace.Method,
		"stop_reason":          stopReason,
		"stop_data":            strconv.Itoa(trace.StopData),
		"hop_count":            strconv.Itoa(trace.HopCount),
		"hop_addrs":            strings.Join(hops, ","),
		"responsive_hop_count": strconv.Itoa(len(hops)),
		"service_class":        job.ServiceClass,
		"service_classes":      strings.Join(job.ServiceClasses, ","),
		"completed":            boolString(strings.EqualFold(stopReason, "COMPLETED")),
	}

	if trace.Src != "" {
		attributes["src"] = trace.Src
	}
	if len(hops) > 0 {
		attributes["final_hop_addr"] = hops[len(hops)-1]
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:route", job.ID, trace.Dst),
		RunID:      job.Metadata["run_id"],
		Source:     "scamper",
		Kind:       "route_trace",
		Target:     trace.Dst,
		Protocol:   "ip",
		Summary:    fmt.Sprintf("route trace to %s via %s with %d responsive hops", trace.Dst, trace.Method, len(hops)),
		RawRef:     fmt.Sprintf("stdout:trace:%s", trace.Dst),
		Attributes: attributes,
		Confidence: confidenceFromStopReason(stopReason),
		ObservedAt: observedAt,
	}
}

func buildHopRecords(trace traceResult, job jobs.Job, observedAt time.Time) []evidence.Record {
	records := make([]evidence.Record, 0, len(trace.Hops))

	for _, hop := range trace.Hops {
		if strings.TrimSpace(hop.Addr) == "" {
			continue
		}

		attributes := map[string]string{
			"job_id":        job.ID,
			"plugin":        "scamper",
			"trace_method":  trace.Method,
			"probe_ttl":     strconv.Itoa(hop.ProbeTTL),
			"probe_id":      strconv.Itoa(hop.ProbeID),
			"reply_ttl":     strconv.Itoa(hop.ReplyTTL),
			"reply_size":    strconv.Itoa(hop.ReplySize),
			"service_class": job.ServiceClass,
		}

		if hop.Name != "" {
			attributes["name"] = hop.Name
		}
		if hop.ICMPType != 0 || hop.ICMPCode != 0 {
			attributes["icmp_type"] = strconv.Itoa(hop.ICMPType)
			attributes["icmp_code"] = strconv.Itoa(hop.ICMPCode)
		}
		if hop.RTT > 0 {
			attributes["rtt_ms"] = formatFloat(hop.RTT)
		}
		if len(job.ServiceClasses) > 0 {
			attributes["service_classes"] = strings.Join(job.ServiceClasses, ",")
		}

		records = append(records, evidence.Record{
			ID:         fmt.Sprintf("%s:%s:hop:%d:%d", job.ID, trace.Dst, hop.ProbeTTL, hop.ProbeID),
			RunID:      job.Metadata["run_id"],
			Source:     "scamper",
			Kind:       "route_hop",
			Target:     trace.Dst,
			Protocol:   "ip",
			Summary:    fmt.Sprintf("hop %d to %s responded from %s", hop.ProbeTTL, trace.Dst, hop.Addr),
			RawRef:     fmt.Sprintf("stdout:trace:%s:ttl:%d", trace.Dst, hop.ProbeTTL),
			Attributes: attributes,
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: observedAt,
		})
	}

	return records
}

func compactHopAddrs(hops []traceHop) []string {
	seen := make(map[string]struct{})
	addrs := make([]string, 0, len(hops))

	for _, hop := range hops {
		addr := strings.TrimSpace(hop.Addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}

		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
	}

	return addrs
}

func confidenceFromStopReason(stopReason string) evidence.Confidence {
	switch strings.ToUpper(strings.TrimSpace(stopReason)) {
	case "COMPLETED":
		return evidence.ConfidenceConfirmed
	case "GAPLIMIT", "LOOP", "HOPLIMIT":
		return evidence.ConfidenceProbable
	default:
		return evidence.ConfidenceAmbiguous
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

type traceResult struct {
	Type       string     `json:"type"`
	Version    string     `json:"version"`
	Method     string     `json:"method"`
	Src        string     `json:"src"`
	Dst        string     `json:"dst"`
	StopReason string     `json:"stop_reason"`
	StopData   int        `json:"stop_data"`
	HopCount   int        `json:"hop_count"`
	Hops       []traceHop `json:"hops"`
	Start      traceStart `json:"start"`
}

func (t traceResult) startTime() (time.Time, bool) {
	if t.Start.Sec == 0 && t.Start.Usec == 0 {
		return time.Time{}, false
	}

	return time.Unix(t.Start.Sec, t.Start.Usec*1000).UTC(), true
}

type traceStart struct {
	Sec  int64 `json:"sec"`
	Usec int64 `json:"usec"`
}

type traceHop struct {
	Addr      string  `json:"addr"`
	Name      string  `json:"name"`
	ProbeTTL  int     `json:"probe_ttl"`
	ProbeID   int     `json:"probe_id"`
	RTT       float64 `json:"rtt"`
	ReplyTTL  int     `json:"reply_ttl"`
	ReplySize int     `json:"reply_size"`
	ICMPType  int     `json:"icmp_type"`
	ICMPCode  int     `json:"icmp_code"`
}
