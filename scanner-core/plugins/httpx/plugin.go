package httpx

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

	"github.com/grvtyai/tracer/scanner-core/internal/classify"
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
		binary: "httpx",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "httpx"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindWebProbe
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("httpx requires at least one target")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "httpx"
	}

	output, err := runner.Run(ctx, binary, BuildArgs(job))
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("run httpx: %w", err)
		}
		return nil, fmt.Errorf("run httpx: %w: %s", err, strings.TrimSpace(string(output)))
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

	if techDetect(job) {
		args = append(args, "-td")
	}
	if followRedirects(job) {
		args = append(args, "-fr")
	}
	if retries := strings.TrimSpace(job.Metadata["retries"]); retries != "" {
		args = append(args, "-retries", retries)
	}
	if timeout := strings.TrimSpace(job.Metadata["timeout"]); timeout != "" {
		args = append(args, "-timeout", timeout)
	}

	for _, target := range expandTargets(job) {
		args = append(args, "-u", target)
	}

	return args
}

func expandTargets(job jobs.Job) []string {
	if len(job.Ports) == 0 {
		return append([]string{}, job.Targets...)
	}

	targets := make([]string, 0, len(job.Targets)*len(job.Ports))
	for _, target := range job.Targets {
		for _, port := range job.Ports {
			targets = append(targets, fmt.Sprintf("%s:%d", target, port))
		}
	}

	return targets
}

func ParseOutput(output []byte, job jobs.Job, observedAt time.Time) ([]evidence.Record, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	records := make([]evidence.Record, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		result, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse httpx json line %d: %w", lineNumber, err)
		}

		recordObservedAt := observedAt
		if timestamp, ok := result.observedAt(); ok {
			recordObservedAt = timestamp
		}

		records = append(records, buildRecord(result, job, recordObservedAt))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan httpx output: %w", err)
	}

	return records, nil
}

func parseLine(line string) (result, error) {
	var payload result
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return result{}, err
	}

	if strings.TrimSpace(payload.URL) == "" {
		return result{}, errors.New("missing url")
	}

	return payload, nil
}

func buildRecord(result result, job jobs.Job, observedAt time.Time) evidence.Record {
	port := result.port()
	serviceClass := classify.FromPort(port)
	if strings.TrimSpace(result.Scheme) == "http" || strings.TrimSpace(result.Scheme) == "https" {
		serviceClass = "web"
	}

	statusCode := 0
	if result.StatusCode != nil {
		statusCode = *result.StatusCode
	}

	summary := fmt.Sprintf("http probe for %s", result.URL)
	if statusCode > 0 {
		summary = fmt.Sprintf("%s returned HTTP %d", result.URL, statusCode)
	}

	attributes := map[string]string{
		"job_id":                     job.ID,
		"plugin":                     "httpx",
		"job_kind":                   string(job.Kind),
		"url":                        result.URL,
		"input":                      result.Input,
		"host":                       result.Host,
		"scheme":                     result.Scheme,
		"service_class":              serviceClass,
		"host_primary_service_class": firstNonEmpty(job.Metadata["host_primary_service_class"], job.ServiceClass),
		"host_service_classes":       firstNonEmpty(job.Metadata["host_service_classes"], strings.Join(job.ServiceClasses, ",")),
	}

	if statusCode > 0 {
		attributes["status_code"] = strconv.Itoa(statusCode)
	}
	if result.Title != "" {
		attributes["title"] = result.Title
	}
	if result.WebServer != "" {
		attributes["web_server"] = result.WebServer
	}
	if result.ContentType != "" {
		attributes["content_type"] = result.ContentType
	}
	if result.Method != "" {
		attributes["method"] = result.Method
	}
	if result.Location != "" {
		attributes["location"] = result.Location
	}
	if result.IP != "" {
		attributes["ip"] = result.IP
	}
	if result.CNAME != nil && *result.CNAME != "" {
		attributes["cname"] = *result.CNAME
	}
	if result.ResponseTime != "" {
		attributes["response_time"] = result.ResponseTime
	}
	if result.ContentLength != nil {
		attributes["content_length"] = strconv.Itoa(*result.ContentLength)
	}
	if len(result.Tech) > 0 {
		attributes["tech"] = strings.Join(result.Tech, ",")
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:http", job.ID, result.URL),
		RunID:      job.Metadata["run_id"],
		Source:     "httpx",
		Kind:       "http_probe",
		Target:     coalesce(result.Host, result.Input),
		Port:       port,
		Protocol:   "tcp",
		Summary:    summary,
		RawRef:     fmt.Sprintf("stdout:url:%s", result.URL),
		Attributes: attributes,
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func techDetect(job jobs.Job) bool {
	return truthy(job.Metadata["tech_detect"])
}

func followRedirects(job jobs.Job) bool {
	return truthy(job.Metadata["follow_redirects"])
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type result struct {
	Timestamp     string   `json:"timestamp"`
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Host          string   `json:"host"`
	Port          any      `json:"port"`
	Scheme        string   `json:"scheme"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	ContentType   string   `json:"content_type"`
	Method        string   `json:"method"`
	Location      string   `json:"location"`
	IP            string   `json:"ip"`
	CNAME         *string  `json:"cname"`
	ResponseTime  string   `json:"response_time"`
	StatusCode    *int     `json:"status_code"`
	ContentLength *int     `json:"content_length"`
	Tech          []string `json:"tech"`
}

func (r result) port() int {
	switch typed := r.Port.(type) {
	case float64:
		return int(typed)
	case string:
		value, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return value
		}
	}

	return 0
}

func (r result) observedAt() (time.Time, bool) {
	if strings.TrimSpace(r.Timestamp) == "" {
		return time.Time{}, false
	}

	timestamp, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		return time.Time{}, false
	}

	return timestamp.UTC(), true
}
