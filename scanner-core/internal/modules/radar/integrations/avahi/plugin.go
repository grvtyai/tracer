package avahi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
		binary: "avahi-browse",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "avahi"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindLocalService
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "avahi-browse"
	}
	if _, ok := runner.(ExecRunner); ok {
		resolvedBinary, resolveErr := platform.ResolveExecutable(binary)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve avahi-browse binary: %w", resolveErr)
		}
		binary = resolvedBinary
	}

	output, err := runner.Run(ctx, binary, BuildArgs(job))
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("run avahi-browse: %w", err)
		}
		return nil, fmt.Errorf("run avahi-browse: %w: %s", err, strings.TrimSpace(string(output)))
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
	args := []string{"-a", "-p", "-t"}
	if truthy(job.Metadata["resolve"]) {
		args = append(args, "-r")
	}
	if truthy(job.Metadata["ignore_local"]) {
		args = append(args, "-l")
	}
	args = append(args, "-k")
	return args
}

func ParseOutput(output []byte, job jobs.Job, observedAt time.Time) ([]evidence.Record, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	records := make([]evidence.Record, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "=") {
			continue
		}

		service, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse avahi output line %d: %w", lineNumber, err)
		}
		records = append(records, buildRecord(service, job, observedAt))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan avahi output: %w", err)
	}

	return records, nil
}

type serviceRecord struct {
	Interface string
	Protocol  string
	Name      string
	Type      string
	Domain    string
	Hostname  string
	Address   string
	Port      int
	TXT       string
}

func parseLine(line string) (serviceRecord, error) {
	fields := strings.Split(line, ";")
	if len(fields) < 9 {
		return serviceRecord{}, errors.New("unexpected avahi parsable output")
	}

	port, err := strconv.Atoi(strings.TrimSpace(fields[8]))
	if err != nil {
		return serviceRecord{}, fmt.Errorf("parse port: %w", err)
	}

	txt := ""
	if len(fields) > 9 {
		txt = strings.TrimSpace(strings.Join(fields[9:], ";"))
	}

	return serviceRecord{
		Interface: strings.TrimSpace(fields[1]),
		Protocol:  normalizeProtocol(fields[2]),
		Name:      strings.TrimSpace(fields[3]),
		Type:      strings.TrimSpace(fields[4]),
		Domain:    strings.TrimSpace(fields[5]),
		Hostname:  strings.TrimSpace(fields[6]),
		Address:   strings.TrimSpace(fields[7]),
		Port:      port,
		TXT:       txt,
	}, nil
}

func buildRecord(service serviceRecord, job jobs.Job, observedAt time.Time) evidence.Record {
	target := firstNonEmpty(service.Address, service.Hostname)
	summary := fmt.Sprintf("%s announced %s on port %d", firstNonEmpty(service.Name, target), service.Type, service.Port)
	attributes := map[string]string{
		"job_id":       job.ID,
		"plugin":       "avahi",
		"job_kind":     string(job.Kind),
		"service":      service.Name,
		"service_type": service.Type,
		"domain":       service.Domain,
		"hostname":     service.Hostname,
		"interface":    service.Interface,
	}
	if service.TXT != "" {
		attributes["txt"] = service.TXT
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%d:%s", job.ID, target, service.Port, service.Type),
		RunID:      job.Metadata["run_id"],
		Source:     "avahi",
		Kind:       "service_advertisement",
		Target:     target,
		Port:       service.Port,
		Protocol:   service.Protocol,
		Summary:    summary,
		RawRef:     fmt.Sprintf("avahi:%s:%d", target, service.Port),
		Attributes: attributes,
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}
}

func normalizeProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ipv6":
		return "tcp6"
	default:
		return "tcp"
	}
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
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
