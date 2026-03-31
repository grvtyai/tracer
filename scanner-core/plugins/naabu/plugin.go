package naabu

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
		binary: "naabu",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "naabu"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindPortDiscover
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("naabu requires at least one target")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "naabu"
	}

	output, err := runner.Run(ctx, binary, BuildArgs(job))
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("run naabu: %w", err)
		}
		return nil, fmt.Errorf("run naabu: %w: %s", err, strings.TrimSpace(string(output)))
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
	args := []string{"-json", "-silent"}

	if ports := joinPorts(job.Ports); ports != "" {
		args = append(args, "-p", ports)
	}

	if rate := strings.TrimSpace(job.Metadata["rate"]); rate != "" {
		args = append(args, "-rate", rate)
	}

	if retries := strings.TrimSpace(job.Metadata["retries"]); retries != "" {
		args = append(args, "-retries", retries)
	}

	if warmUp := strings.TrimSpace(job.Metadata["warm_up_time"]); warmUp != "" {
		args = append(args, "-warm-up-time", warmUp)
	}

	if scanType := strings.TrimSpace(job.Metadata["scan_type"]); scanType != "" {
		args = append(args, "-scan-type", scanType)
	}

	if excludeCDN, ok := job.Metadata["exclude_cdn"]; ok && isTrue(excludeCDN) {
		args = append(args, "-exclude-cdn")
	}

	args = append(args, "-host", strings.Join(job.Targets, ","))
	return args
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

		record, err := parseLine(line, job, observedAt, lineNumber)
		if err != nil {
			return nil, err
		}

		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan naabu output: %w", err)
	}

	return records, nil
}

func parseLine(line string, job jobs.Job, observedAt time.Time, lineNumber int) (evidence.Record, error) {
	if strings.HasPrefix(line, "{") {
		record, err := parseJSONLine(line)
		if err != nil {
			return evidence.Record{}, fmt.Errorf("parse naabu json line %d: %w", lineNumber, err)
		}
		return buildRecord(record.target, record.port, record.protocol, job, observedAt, lineNumber), nil
	}

	target, port, protocol, err := parsePlainLine(line)
	if err != nil {
		return evidence.Record{}, fmt.Errorf("parse naabu line %d: %w", lineNumber, err)
	}

	return buildRecord(target, port, protocol, job, observedAt, lineNumber), nil
}

type parsedResult struct {
	target   string
	port     int
	protocol string
}

func parseJSONLine(line string) (parsedResult, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return parsedResult{}, err
	}

	target := firstString(payload, "ip", "host", "target")
	if target == "" {
		return parsedResult{}, errors.New("missing target")
	}

	port, err := firstInt(payload, "port")
	if err != nil {
		return parsedResult{}, fmt.Errorf("missing or invalid port: %w", err)
	}

	protocol := firstString(payload, "protocol", "proto", "transport")
	if protocol == "" {
		protocol = "tcp"
	}

	return parsedResult{
		target:   target,
		port:     port,
		protocol: strings.ToLower(protocol),
	}, nil
}

func parsePlainLine(line string) (string, int, string, error) {
	protocol := "tcp"
	hostPort := line

	fields := strings.Fields(line)
	if len(fields) == 2 {
		if strings.Contains(fields[0], ":") && !strings.Contains(fields[0], ".") {
			protocol = strings.ToLower(fields[0][:strings.Index(fields[0], ":")])
			hostPort = fields[1]
		} else if looksLikeProtocol(fields[1]) {
			protocol = strings.ToLower(fields[1])
			hostPort = fields[0]
		}
	}

	lastColon := strings.LastIndex(hostPort, ":")
	if lastColon <= 0 || lastColon == len(hostPort)-1 {
		return "", 0, "", errors.New("expected host:port")
	}

	target := hostPort[:lastColon]
	port, err := strconv.Atoi(hostPort[lastColon+1:])
	if err != nil {
		return "", 0, "", err
	}

	return target, port, protocol, nil
}

func buildRecord(target string, port int, protocol string, job jobs.Job, observedAt time.Time, lineNumber int) evidence.Record {
	normalizedProtocol := strings.ToLower(strings.TrimSpace(protocol))
	if normalizedProtocol == "" {
		normalizedProtocol = "tcp"
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%s:%d", job.ID, target, normalizedProtocol, port),
		RunID:      job.Metadata["run_id"],
		Source:     "naabu",
		Kind:       "open_port",
		Target:     target,
		Port:       port,
		Protocol:   normalizedProtocol,
		Summary:    fmt.Sprintf("open %s port %d on %s", normalizedProtocol, port, target),
		RawRef:     fmt.Sprintf("stdout:line:%d", lineNumber),
		Attributes: buildAttributes(job, normalizedProtocol),
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}
}

func buildAttributes(job jobs.Job, protocol string) map[string]string {
	attributes := map[string]string{
		"job_id":    job.ID,
		"plugin":    "naabu",
		"protocol":  protocol,
		"job_kind":  string(job.Kind),
		"scan_type": "syn",
	}

	if scanType := strings.TrimSpace(job.Metadata["scan_type"]); scanType != "" {
		attributes["scan_type"] = scanType
	}

	if serviceClass := strings.TrimSpace(job.ServiceClass); serviceClass != "" {
		attributes["service_class"] = serviceClass
	}

	return attributes
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}

	return strings.Join(values, ",")
}

func isTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func firstString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok {
			continue
		}

		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		}
	}

	return ""
}

func firstInt(payload map[string]any, keys ...string) (int, error) {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok {
			continue
		}

		switch typed := value.(type) {
		case float64:
			return int(typed), nil
		case string:
			port, err := strconv.Atoi(typed)
			if err != nil {
				return 0, err
			}
			return port, nil
		}
	}

	return 0, errors.New("integer field not found")
}

func looksLikeProtocol(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp", "udp":
		return true
	default:
		return false
	}
}
