package snmpwalk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
		binary: "snmpwalk",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "snmpwalk"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindSNMPProbe
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("snmpwalk requires at least one target")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "snmpwalk"
	}
	if _, ok := runner.(ExecRunner); ok {
		resolvedBinary, resolveErr := platform.ResolveExecutable(binary)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve snmpwalk binary: %w", resolveErr)
		}
		binary = resolvedBinary
	}

	output, err := runner.Run(ctx, binary, BuildArgs(job))
	if err != nil {
		if shouldIgnoreExecutionError(string(output)) {
			return nil, nil
		}
		if len(output) == 0 {
			return nil, fmt.Errorf("run snmpwalk: %w", err)
		}
		return nil, fmt.Errorf("run snmpwalk: %w: %s", err, strings.TrimSpace(string(output)))
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
	version := firstNonEmpty(strings.TrimSpace(job.Metadata["version"]), "2c")
	community := firstNonEmpty(strings.TrimSpace(job.Metadata["community"]), "public")
	timeout := firstNonEmpty(strings.TrimSpace(job.Metadata["timeout"]), "2")
	retries := firstNonEmpty(strings.TrimSpace(job.Metadata["retries"]), "0")
	target := strings.TrimSpace(job.Targets[0])

	return []string{
		"-v", version,
		"-c", community,
		"-t", timeout,
		"-r", retries,
		"-On",
		"-Oq",
		target,
		".1.3.6.1.2.1.1",
	}
}

func ParseOutput(output []byte, job jobs.Job, observedAt time.Time) ([]evidence.Record, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	records := make([]evidence.Record, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, ".1.3.6.1.2.1.1.") {
			continue
		}

		entry, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse snmpwalk output line %d: %w", lineNumber, err)
		}
		records = append(records, buildRecord(entry, job, observedAt))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan snmpwalk output: %w", err)
	}

	return records, nil
}

type systemValue struct {
	OID   string
	Key   string
	Value string
}

func parseLine(line string) (systemValue, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return systemValue{}, errors.New("unexpected snmpwalk output")
	}
	oid := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(strings.Join(parts[1:], " "))
	key := systemOIDLabel(oid)
	return systemValue{
		OID:   oid,
		Key:   key,
		Value: value,
	}, nil
}

func buildRecord(entry systemValue, job jobs.Job, observedAt time.Time) evidence.Record {
	target := strings.TrimSpace(job.Targets[0])
	summary := fmt.Sprintf("%s | %s", entry.Key, entry.Value)
	attributes := map[string]string{
		"job_id":     job.ID,
		"plugin":     "snmpwalk",
		"job_kind":   string(job.Kind),
		"snmp_oid":   entry.OID,
		"snmp_field": entry.Key,
		"snmp_value": entry.Value,
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%s", job.ID, target, entry.Key),
		RunID:      job.Metadata["run_id"],
		Source:     "snmpwalk",
		Kind:       "snmp_system",
		Target:     target,
		Port:       161,
		Protocol:   "udp",
		Summary:    summary,
		RawRef:     fmt.Sprintf("snmp:%s:%s", target, entry.OID),
		Attributes: attributes,
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}
}

func systemOIDLabel(oid string) string {
	switch strings.TrimSpace(oid) {
	case ".1.3.6.1.2.1.1.1.0":
		return "sysDescr"
	case ".1.3.6.1.2.1.1.2.0":
		return "sysObjectID"
	case ".1.3.6.1.2.1.1.3.0":
		return "sysUpTime"
	case ".1.3.6.1.2.1.1.4.0":
		return "sysContact"
	case ".1.3.6.1.2.1.1.5.0":
		return "sysName"
	case ".1.3.6.1.2.1.1.6.0":
		return "sysLocation"
	default:
		return oid
	}
}

func shouldIgnoreExecutionError(output string) bool {
	lowered := strings.ToLower(strings.TrimSpace(output))
	for _, marker := range []string{
		"timeout",
		"no response",
		"unknown user name",
		"authentication failure",
		"no such object available",
		"failed to connect",
		"network is unreachable",
		"no route to host",
	} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
