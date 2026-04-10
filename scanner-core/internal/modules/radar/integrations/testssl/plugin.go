package testssl

import (
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

	"github.com/grvtyai/startrace/scanner-core/internal/engine"
	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/platform"
)

type Runner interface {
	Run(ctx context.Context, name string, args []string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if workingDir, env := testSSLEnvironment(name); workingDir != "" {
		cmd.Dir = workingDir
		cmd.Env = append(os.Environ(), env...)
	} else {
		cmd.Env = os.Environ()
	}
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
		binary: "testssl.sh",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "testssl"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindTLSInspect
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("testssl requires at least one target")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "testssl.sh"
	}
	if _, ok := runner.(ExecRunner); ok {
		resolvedBinary, resolveErr := platform.ResolveExecutable(binary)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve testssl.sh binary: %w", resolveErr)
		}
		binary = resolvedBinary
	}

	outputFile, err := os.CreateTemp("", "startrace-testssl-*.json")
	if err != nil {
		return nil, fmt.Errorf("create testssl temp file: %w", err)
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	defer os.Remove(outputPath)

	output, runErr := runner.Run(ctx, binary, BuildArgs(job, outputPath))
	if runErr != nil {
		if shouldIgnoreExecutionError(string(output)) {
			return nil, nil
		}
		if len(output) == 0 {
			return nil, fmt.Errorf("run testssl.sh: %w", runErr)
		}
		return nil, fmt.Errorf("run testssl.sh: %w: %s", runErr, strings.TrimSpace(string(output)))
	}

	fileData, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("read testssl output: %w", err)
	}
	if strings.TrimSpace(string(fileData)) == "" {
		return nil, nil
	}

	return ParseOutput(fileData, job, p.timeNow())
}

func (p *Plugin) timeNow() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}
	return time.Now().UTC()
}

func BuildArgs(job jobs.Job, outputPath string) []string {
	target := strings.TrimSpace(job.Targets[0])
	if len(job.Ports) > 0 && job.Ports[0] > 0 {
		target = fmt.Sprintf("%s:%d", target, job.Ports[0])
	}

	args := []string{"--quiet", "--jsonfile", outputPath}
	args = append(args, target)
	return args
}

func testSSLEnvironment(binary string) (string, []string) {
	trimmed := filepath.Clean(strings.TrimSpace(binary))
	installDir := ""

	switch {
	case strings.HasPrefix(trimmed, filepath.Clean("/usr/local/share/testssl")):
		installDir = filepath.Clean("/usr/local/share/testssl")
	case strings.EqualFold(filepath.Base(trimmed), "testssl.sh"):
		if _, err := os.Stat("/usr/local/share/testssl/etc"); err == nil {
			installDir = filepath.Clean("/usr/local/share/testssl")
		}
	}

	if installDir == "" {
		return "", nil
	}

	return installDir, []string{
		"TESTSSL_INSTALL_DIR=" + installDir,
		"TERM=dumb",
	}
}

func ParseOutput(data []byte, job jobs.Job, observedAt time.Time) ([]evidence.Record, error) {
	items, err := parseFindings(data)
	if err != nil {
		return nil, err
	}

	records := make([]evidence.Record, 0, len(items))
	for index, item := range items {
		record, ok := buildRecord(item, job, observedAt, index)
		if !ok {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

type finding struct {
	ID       string
	IP       string
	Hostname string
	Port     int
	Severity string
	Finding  string
	CVE      string
	CWE      string
	Hint     string
	Service  string
}

func parseFindings(data []byte) ([]finding, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	decoder := func(raw map[string]any) finding {
		port, _ := parseInt(raw["port"])
		return finding{
			ID:       parseString(raw["id"]),
			IP:       parseString(raw["ip"]),
			Hostname: firstNonEmpty(parseString(raw["hostname"]), parseString(raw["fqdn"]), parseString(raw["host"])),
			Port:     port,
			Severity: parseString(raw["severity"]),
			Finding:  firstNonEmpty(parseString(raw["finding"]), parseString(raw["service"])),
			CVE:      parseString(raw["cve"]),
			CWE:      parseString(raw["cwe"]),
			Hint:     parseString(raw["hint"]),
			Service:  parseString(raw["service"]),
		}
	}

	if strings.HasPrefix(trimmed, "[") {
		var payload []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
			return nil, fmt.Errorf("decode testssl json array: %w", err)
		}
		items := make([]finding, 0, len(payload))
		for _, raw := range payload {
			items = append(items, decoder(raw))
		}
		return items, nil
	}

	lines := strings.Split(trimmed, "\n")
	items := make([]finding, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("decode testssl json line: %w", err)
		}
		items = append(items, decoder(raw))
	}
	if len(items) > 0 {
		return items, nil
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, fmt.Errorf("decode testssl json object: %w", err)
	}
	return []finding{decoder(raw)}, nil
}

func buildRecord(item finding, job jobs.Job, observedAt time.Time, index int) (evidence.Record, bool) {
	if strings.TrimSpace(item.Finding) == "" && strings.TrimSpace(item.ID) == "" {
		return evidence.Record{}, false
	}

	target := firstNonEmpty(item.Hostname, item.IP)
	if target == "" && len(job.Targets) > 0 {
		target = strings.TrimSpace(job.Targets[0])
	}

	port := item.Port
	if port <= 0 && len(job.Ports) > 0 {
		port = job.Ports[0]
	}

	summary := firstNonEmpty(item.Finding, item.ID)
	if severity := strings.TrimSpace(item.Severity); severity != "" {
		summary = fmt.Sprintf("%s | %s", severity, summary)
	}

	attributes := map[string]string{
		"job_id":   job.ID,
		"plugin":   "testssl",
		"job_kind": string(job.Kind),
		"severity": item.Severity,
		"finding":  item.Finding,
	}
	if item.ID != "" {
		attributes["check_id"] = item.ID
	}
	if item.CVE != "" {
		attributes["cve"] = item.CVE
	}
	if item.CWE != "" {
		attributes["cwe"] = item.CWE
	}
	if item.Hint != "" {
		attributes["hint"] = item.Hint
	}
	if item.Service != "" {
		attributes["service"] = item.Service
	}

	recordID := firstNonEmpty(item.ID, fmt.Sprintf("finding-%d", index))
	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%d:%s", job.ID, target, port, recordID),
		RunID:      job.Metadata["run_id"],
		Source:     "testssl.sh",
		Kind:       "tls_check",
		Target:     target,
		Port:       port,
		Protocol:   "tcp",
		Summary:    summary,
		RawRef:     fmt.Sprintf("testssl:%s:%d:%s", target, port, recordID),
		Attributes: attributes,
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}, true
}

func shouldIgnoreExecutionError(output string) bool {
	lowered := strings.ToLower(strings.TrimSpace(output))
	for _, marker := range []string{
		"doesn't seem to be a tls",
		"doesn't seem to be an ssl",
		"connection refused",
		"timeout",
		"no route to host",
		"network is unreachable",
		"unable to connect",
		"connection reset",
		"connection timed out",
	} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

func parseString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func parseInt(value any) (int, error) {
	switch typed := value.(type) {
	case float64:
		return int(typed), nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, nil
		}
		return strconv.Atoi(strings.TrimSpace(typed))
	default:
		return 0, nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
