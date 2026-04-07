package zgrab2

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/classify"
	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/platform"
)

var errSkipLine = errors.New("skip zgrab2 line")

type Runner interface {
	Run(ctx context.Context, name string, args []string, env []string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.CombinedOutput()
}

type Plugin struct {
	binary  string
	runner  Runner
	now     func() time.Time
	tempDir func() string
}

var _ engine.Plugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{
		binary:  "zgrab2",
		runner:  ExecRunner{},
		now:     time.Now,
		tempDir: os.TempDir,
	}
}

func (p *Plugin) Name() string {
	return "zgrab2"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindGrabProbe
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("zgrab2 requires at least one target")
	}
	if len(job.Ports) == 0 {
		return nil, errors.New("zgrab2 requires at least one port")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "zgrab2"
	}
	if _, ok := runner.(ExecRunner); ok {
		resolvedBinary, resolveErr := platform.ResolveExecutable(binary)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve zgrab2 binary: %w", resolveErr)
		}
		binary = resolvedBinary
	}

	inputFile, err := p.writeInputFile(job)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inputFile)

	configRoot, env, err := p.prepareConfigEnv(job)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(configRoot)

	output, err := runner.Run(ctx, binary, BuildArgs(job, inputFile), env)
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("run zgrab2: %w", err)
		}
		return nil, fmt.Errorf("run zgrab2: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return ParseOutput(output, job, p.timeNow())
}

func (p *Plugin) timeNow() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}

	return time.Now().UTC()
}

func (p *Plugin) tempBase() string {
	if p.tempDir != nil {
		return p.tempDir()
	}
	return os.TempDir()
}

func (p *Plugin) writeInputFile(job jobs.Job) (string, error) {
	path := filepath.Join(p.tempBase(), fmt.Sprintf("tracer-zgrab2-%s.csv", sanitize(job.ID)))
	lines := make([]string, 0, len(job.Targets)*len(job.Ports))

	for _, target := range job.Targets {
		for _, port := range job.Ports {
			lines = append(lines, fmt.Sprintf("%s,,,%d", target, port))
		}
	}

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write zgrab2 input file: %w", err)
	}

	return path, nil
}

func (p *Plugin) prepareConfigEnv(job jobs.Job) (string, []string, error) {
	configRoot, err := os.MkdirTemp(p.tempBase(), fmt.Sprintf("tracer-zgrab2-config-%s-", sanitize(job.ID)))
	if err != nil {
		return "", nil, fmt.Errorf("create zgrab2 config dir: %w", err)
	}

	configDirs := []string{
		filepath.Join(configRoot, "zgrab2"),
		filepath.Join(configRoot, ".config", "zgrab2"),
	}

	for _, configDir := range configDirs {
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			os.RemoveAll(configRoot)
			return "", nil, fmt.Errorf("create zgrab2 config dir: %w", err)
		}

		blocklistPath := filepath.Join(configDir, "blocklist.conf")
		if err := os.WriteFile(blocklistPath, []byte(""), 0o600); err != nil {
			os.RemoveAll(configRoot)
			return "", nil, fmt.Errorf("write zgrab2 blocklist file: %w", err)
		}
	}

	return configRoot, []string{
		fmt.Sprintf("HOME=%s", configRoot),
		fmt.Sprintf("XDG_CONFIG_HOME=%s", configRoot),
	}, nil
}

func BuildArgs(job jobs.Job, inputFile string) []string {
	module := strings.TrimSpace(job.Metadata["module"])
	if module == "" {
		module = "http"
	}

	args := []string{
		module,
		"--input-file", inputFile,
		"--output-file", "-",
	}

	connectTimeout := strings.TrimSpace(job.Metadata["connect_timeout"])
	targetTimeout := strings.TrimSpace(job.Metadata["target_timeout"])
	if timeout := strings.TrimSpace(job.Metadata["timeout"]); timeout != "" {
		if connectTimeout == "" {
			connectTimeout = timeout
		}
		if targetTimeout == "" {
			targetTimeout = timeout
		}
	}
	if connectTimeout != "" {
		args = append(args, "--connect-timeout", connectTimeout)
	}
	if targetTimeout != "" {
		args = append(args, "--target-timeout", targetTimeout)
	}
	if maxRedirects := strings.TrimSpace(job.Metadata["max_redirects"]); maxRedirects != "" {
		args = append(args, "--max-redirects", maxRedirects)
	}
	if useTLS(job) {
		args = append(args, "--use-https")
	}
	if endpoint := strings.TrimSpace(job.Metadata["endpoint"]); endpoint != "" {
		args = append(args, "--endpoint", endpoint)
	}
	if userAgent := strings.TrimSpace(job.Metadata["user_agent"]); userAgent != "" {
		args = append(args, "--user-agent", userAgent)
	}

	return args
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
			if errors.Is(err, errSkipLine) {
				continue
			}
			return nil, fmt.Errorf("parse zgrab2 json line %d: %w", lineNumber, err)
		}

		recordObservedAt := observedAt
		if timestamp, ok := result.observedAt(); ok {
			recordObservedAt = timestamp
		}

		records = append(records, buildRecord(result, job, recordObservedAt))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan zgrab2 output: %w", err)
	}

	return records, nil
}

func parseLine(line string) (result, error) {
	var payload result
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return result{}, err
	}
	if !payload.hasTarget() && !payload.hasMeaningfulData() {
		return result{}, errSkipLine
	}
	return payload, nil
}

func buildRecord(result result, job jobs.Job, observedAt time.Time) evidence.Record {
	module := strings.TrimSpace(job.Metadata["module"])
	if module == "" {
		module = "http"
	}

	status := ""
	if result.Data.HTTP.Status != "" {
		status = result.Data.HTTP.Status
	} else if result.Data.HTTP.Result.Response.StatusLine != "" {
		status = result.Data.HTTP.Result.Response.StatusLine
	}

	port := result.port()
	if port == 0 && len(job.Ports) > 0 {
		port = job.Ports[0]
	}

	serviceClass := classify.FromPort(port)
	if module == "http" || module == "https" {
		serviceClass = "web"
	}

	target := firstNonEmpty(result.IP, result.Domain, result.inputHost())
	if target == "" && len(job.Targets) == 1 {
		target = job.Targets[0]
	}
	url := buildURL(result, port, module)

	attributes := map[string]string{
		"job_id":                     job.ID,
		"plugin":                     "zgrab2",
		"job_kind":                   string(job.Kind),
		"module":                     module,
		"service_class":              serviceClass,
		"host_primary_service_class": firstNonEmpty(job.Metadata["host_primary_service_class"], job.ServiceClass),
		"host_service_classes":       firstNonEmpty(job.Metadata["host_service_classes"], strings.Join(job.ServiceClasses, ",")),
		"ip":                         result.IP,
		"domain":                     result.Domain,
		"input":                      result.Input,
		"url":                        url,
	}

	if status != "" {
		attributes["status"] = status
	}
	if code := result.Data.HTTP.Result.Response.StatusCode; code != 0 {
		attributes["status_code"] = strconv.Itoa(code)
	}
	if server := result.Data.HTTP.Result.Response.Headers.server(); server != "" {
		attributes["web_server"] = server
	}
	if contentType := result.Data.HTTP.Result.Response.Headers.contentType(); contentType != "" {
		attributes["content_type"] = contentType
	}
	if title := result.Data.HTTP.Result.Response.BodyTitle; title != "" {
		attributes["title"] = title
	}
	if redirect := result.Data.HTTP.Result.Response.Headers.location(); redirect != "" {
		attributes["location"] = redirect
	}
	if tlsVersion := result.Data.HTTP.Result.Response.Request.TLS.Version; tlsVersion != "" {
		attributes["tls_version"] = tlsVersion
	}

	summary := fmt.Sprintf("zgrab2 %s probe for %s", module, target)
	if code := result.Data.HTTP.Result.Response.StatusCode; code != 0 {
		summary = fmt.Sprintf("%s returned HTTP %d", url, code)
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%s:grab", job.ID, firstNonEmpty(target, "unknown-target"), module),
		RunID:      job.Metadata["run_id"],
		Source:     "zgrab2",
		Kind:       "l7_grab",
		Target:     firstNonEmpty(target, "unknown-target"),
		Port:       port,
		Protocol:   "tcp",
		Summary:    summary,
		RawRef:     fmt.Sprintf("stdout:grab:%s", target),
		Attributes: attributes,
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}
}

func buildURL(result result, port int, module string) string {
	scheme := "http"
	if useTLSMetadata(module, port) {
		scheme = "https"
	}

	host := firstNonEmpty(result.Domain, result.IP, result.inputHost())
	if host == "" {
		return ""
	}

	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func useTLS(job jobs.Job) bool {
	if truthy(job.Metadata["use_tls"]) {
		return true
	}

	for _, port := range job.Ports {
		if useTLSMetadata(strings.TrimSpace(job.Metadata["module"]), port) {
			return true
		}
	}

	return false
}

func useTLSMetadata(module string, port int) bool {
	if module == "https" {
		return true
	}

	switch port {
	case 443, 8443, 9443:
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

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func sanitize(value string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")
	return replacer.Replace(value)
}

type result struct {
	IP        string    `json:"ip"`
	Domain    string    `json:"domain"`
	Input     string    `json:"input,omitempty"`
	Data      dataBlock `json:"data"`
	Timestamp string    `json:"timestamp"`
	Port      *int      `json:"port,omitempty"`
}

func (r result) hasTarget() bool {
	return strings.TrimSpace(r.IP) != "" || strings.TrimSpace(r.Domain) != "" || strings.TrimSpace(r.inputHost()) != ""
}

func (r result) hasMeaningfulData() bool {
	return strings.TrimSpace(r.Data.HTTP.Status) != "" ||
		r.Data.HTTP.Port != 0 ||
		r.Data.HTTP.Result.Response.StatusCode != 0 ||
		strings.TrimSpace(r.Data.HTTP.Result.Response.StatusLine) != ""
}

func (r result) inputHost() string {
	input := strings.TrimSpace(r.Input)
	if input == "" {
		return ""
	}

	host, _, found := strings.Cut(input, ":")
	if found {
		return strings.TrimSpace(host)
	}

	return input
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

func (r result) port() int {
	if r.Port != nil {
		return *r.Port
	}
	if r.Data.HTTP.Port != 0 {
		return r.Data.HTTP.Port
	}
	return 0
}

type dataBlock struct {
	HTTP httpModule `json:"http"`
}

type httpModule struct {
	Status string     `json:"status"`
	Port   int        `json:"port"`
	Result httpResult `json:"result"`
}

type httpResult struct {
	Response httpResponse `json:"response"`
}

type httpResponse struct {
	StatusLine string      `json:"status_line"`
	StatusCode int         `json:"status_code"`
	Headers    httpHeaders `json:"headers"`
	BodyTitle  string      `json:"body_title"`
	Request    httpRequest `json:"request"`
}

type httpHeaders map[string]any

func (h httpHeaders) get(key string) string {
	value, ok := h[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		if len(typed) == 0 {
			return ""
		}
		if first, ok := typed[0].(string); ok {
			return first
		}
	}
	return ""
}

func (h httpHeaders) server() string {
	return h.get("server")
}

func (h httpHeaders) contentType() string {
	return h.get("content-type")
}

func (h httpHeaders) location() string {
	return h.get("location")
}

type httpRequest struct {
	TLS tlsBlock `json:"tls"`
}

type tlsBlock struct {
	Version string `json:"version"`
}
