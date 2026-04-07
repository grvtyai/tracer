package zeek

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
	runner Runner
	now    func() time.Time
}

var _ engine.Plugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (Plugin) Name() string {
	return "zeek"
}

func (Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindPassiveIngest
}

func (p Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	mode := normalizeMode(job.Metadata["zeek_mode"])
	autoStart := isTrue(job.Metadata["zeek_auto_start"])
	logDir := strings.TrimSpace(job.Metadata["zeek_log_dir"])
	if logDir == "" {
		if mode == "auto" {
			return nil, nil
		}
		return nil, errors.New("zeek requires zeek_log_dir metadata")
	}

	if autoStart {
		if err := p.ensureLogDir(ctx, logDir, firstNonEmpty(job.Metadata["zeekctl_binary"], "zeekctl")); err != nil && mode == "always" {
			return nil, err
		}
	}

	matcher := makeTargetMatcher(job.Targets)
	observedAfter := parseCutoff(job.Metadata["run_started_at"])
	files := []struct {
		path    string
		builder func(zeekRow, jobs.Job, string, int) (evidence.Record, bool, error)
	}{
		{path: firstNonEmpty(job.Metadata["conn_log"], filepath.Join(logDir, "conn.log")), builder: buildConnRecord},
		{path: firstNonEmpty(job.Metadata["http_log"], filepath.Join(logDir, "http.log")), builder: buildHTTPRecord},
	}

	records := make([]evidence.Record, 0)
	parsedFiles := 0
	for _, file := range files {
		if _, err := os.Stat(file.path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("stat zeek log %s: %w", file.path, err)
		}

		fileRecords, err := parseLogFile(file.path, job, matcher, observedAfter, file.builder)
		if err != nil {
			return nil, err
		}
		parsedFiles++
		records = append(records, fileRecords...)
	}

	if parsedFiles == 0 {
		if mode == "auto" {
			return nil, nil
		}
		return nil, fmt.Errorf("no zeek logs found in %s", logDir)
	}

	return records, nil
}

func (p Plugin) ensureLogDir(ctx context.Context, logDir string, zeekctlBinary string) error {
	if hasAnyZeekLogs(logDir) {
		return nil
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}
	if _, ok := runner.(ExecRunner); ok {
		resolved, err := platform.ResolveExecutable(zeekctlBinary)
		if err != nil {
			return fmt.Errorf("resolve zeekctl binary: %w", err)
		}
		zeekctlBinary = resolved
	}

	output, err := runner.Run(ctx, zeekctlBinary, []string{"deploy"})
	if err != nil {
		if len(output) == 0 {
			return fmt.Errorf("start zeek via %s deploy: %w", zeekctlBinary, err)
		}
		return fmt.Errorf("start zeek via %s deploy: %w: %s", zeekctlBinary, err, strings.TrimSpace(string(output)))
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hasAnyZeekLogs(logDir) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return nil
}

func (p Plugin) timeNow() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}
	return time.Now().UTC()
}

func hasAnyZeekLogs(logDir string) bool {
	for _, name := range []string{"conn.log", "http.log"} {
		if _, err := os.Stat(filepath.Join(logDir, name)); err == nil {
			return true
		}
	}
	return false
}

type zeekFormat struct {
	separator  string
	emptyField string
	unsetField string
	fields     []string
	path       string
}

type zeekRow struct {
	values     map[string]string
	observedAt time.Time
}

type targetMatcher struct {
	exact    map[string]struct{}
	prefixes []netip.Prefix
}

func parseLogFile(path string, job jobs.Job, matcher targetMatcher, observedAfter time.Time, builder func(zeekRow, jobs.Job, string, int) (evidence.Record, bool, error)) ([]evidence.Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open zeek log %s: %w", path, err)
	}
	defer file.Close()

	format := zeekFormat{
		separator:  "\t",
		emptyField: "(empty)",
		unsetField: "-",
		path:       strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
	}

	scanner := bufio.NewScanner(file)
	records := make([]evidence.Record, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			updateFormat(&format, line)
			continue
		}

		row := parseRow(line, format)
		if !observedAfter.IsZero() && !row.observedAt.IsZero() && row.observedAt.Before(observedAfter) {
			continue
		}

		target := strings.TrimSpace(row.values["id.resp_h"])
		if !matcher.match(target) {
			continue
		}

		record, ok, err := builder(row, job, path, lineNumber)
		if err != nil {
			return nil, fmt.Errorf("parse zeek log %s line %d: %w", path, lineNumber, err)
		}
		if !ok {
			continue
		}
		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan zeek log %s: %w", path, err)
	}

	return records, nil
}

func updateFormat(format *zeekFormat, line string) {
	switch {
	case strings.HasPrefix(line, "#separator "):
		format.separator = decodeSeparator(strings.TrimSpace(strings.TrimPrefix(line, "#separator ")))
	case strings.HasPrefix(line, "#empty_field"):
		format.emptyField = parseDirectiveValue(line, format.separator)
	case strings.HasPrefix(line, "#unset_field"):
		format.unsetField = parseDirectiveValue(line, format.separator)
	case strings.HasPrefix(line, "#path"):
		format.path = parseDirectiveValue(line, format.separator)
	case strings.HasPrefix(line, "#fields"):
		value := strings.TrimPrefix(line, "#fields")
		value = strings.TrimPrefix(value, format.separator)
		format.fields = strings.Split(value, format.separator)
	}
}

func parseDirectiveValue(line string, separator string) string {
	parts := strings.SplitN(line, separator, 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return strings.TrimSpace(fields[1])
	}

	return ""
}

func decodeSeparator(raw string) string {
	switch strings.TrimSpace(raw) {
	case `\x09`:
		return "\t"
	case `\x20`:
		return " "
	default:
		return strings.TrimSpace(raw)
	}
}

func parseRow(line string, format zeekFormat) zeekRow {
	parts := strings.Split(line, format.separator)
	values := make(map[string]string, len(format.fields))
	for i, field := range format.fields {
		value := ""
		if i < len(parts) {
			value = normalizeValue(parts[i], format.emptyField, format.unsetField)
		}
		values[field] = value
	}

	return zeekRow{
		values:     values,
		observedAt: parseTimestamp(values["ts"]),
	}
}

func normalizeValue(value string, emptyField string, unsetField string) string {
	trimmed := strings.TrimSpace(value)
	switch trimmed {
	case emptyField:
		return ""
	case unsetField:
		return ""
	default:
		return trimmed
	}
}

func parseTimestamp(raw string) time.Time {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}
	}

	seconds, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return time.Time{}
	}

	whole, frac := mathModf(seconds)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC()
}

func buildConnRecord(row zeekRow, job jobs.Job, path string, lineNumber int) (evidence.Record, bool, error) {
	target := strings.TrimSpace(row.values["id.resp_h"])
	if target == "" {
		return evidence.Record{}, false, nil
	}

	port, err := parsePort(row.values["id.resp_p"])
	if err != nil {
		return evidence.Record{}, false, err
	}

	protocol := firstNonEmpty(row.values["proto"], "tcp")
	state := row.values["conn_state"]
	service := row.values["service"]
	summary := fmt.Sprintf("zeek observed %s connection to %s:%d", protocol, target, port)
	if state != "" {
		summary = fmt.Sprintf("%s (state %s)", summary, state)
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%d:conn:%d", job.ID, target, port, lineNumber),
		RunID:      job.Metadata["run_id"],
		Source:     "zeek",
		Kind:       "passive_conn",
		Target:     target,
		Port:       port,
		Protocol:   protocol,
		Summary:    summary,
		RawRef:     fmt.Sprintf("%s:line:%d", filepath.Base(path), lineNumber),
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: row.observedAt,
		Attributes: map[string]string{
			"job_id":     job.ID,
			"job_kind":   string(job.Kind),
			"plugin":     "zeek",
			"zeek_path":  "conn",
			"uid":        row.values["uid"],
			"orig_h":     row.values["id.orig_h"],
			"orig_p":     row.values["id.orig_p"],
			"service":    service,
			"conn_state": state,
			"history":    row.values["history"],
			"duration":   row.values["duration"],
			"orig_bytes": row.values["orig_bytes"],
			"resp_bytes": row.values["resp_bytes"],
			"local_orig": row.values["local_orig"],
			"local_resp": row.values["local_resp"],
		},
	}, true, nil
}

func buildHTTPRecord(row zeekRow, job jobs.Job, path string, lineNumber int) (evidence.Record, bool, error) {
	target := strings.TrimSpace(row.values["id.resp_h"])
	if target == "" {
		return evidence.Record{}, false, nil
	}

	port, err := parsePort(row.values["id.resp_p"])
	if err != nil {
		return evidence.Record{}, false, err
	}

	protocol := "tcp"
	statusCode := row.values["status_code"]
	host := row.values["host"]
	uri := row.values["uri"]
	url := buildPassiveURL(host, target, port, uri)
	summary := fmt.Sprintf("zeek observed HTTP traffic to %s", target)
	if statusCode != "" {
		summary = fmt.Sprintf("%s with status %s", url, statusCode)
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%d:http:%d", job.ID, target, port, lineNumber),
		RunID:      job.Metadata["run_id"],
		Source:     "zeek",
		Kind:       "passive_http",
		Target:     target,
		Port:       port,
		Protocol:   protocol,
		Summary:    summary,
		RawRef:     fmt.Sprintf("%s:line:%d", filepath.Base(path), lineNumber),
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: row.observedAt,
		Attributes: map[string]string{
			"job_id":      job.ID,
			"job_kind":    string(job.Kind),
			"plugin":      "zeek",
			"zeek_path":   "http",
			"uid":         row.values["uid"],
			"orig_h":      row.values["id.orig_h"],
			"orig_p":      row.values["id.orig_p"],
			"method":      row.values["method"],
			"host":        host,
			"uri":         uri,
			"status_code": statusCode,
			"status_msg":  row.values["status_msg"],
			"user_agent":  row.values["user_agent"],
			"url":         url,
		},
	}, true, nil
}

func parsePort(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}

	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", raw, err)
	}

	return port, nil
}

func buildPassiveURL(host string, target string, port int, uri string) string {
	base := firstNonEmpty(host, target)
	if base == "" {
		return ""
	}

	if uri == "" {
		uri = "/"
	}

	return fmt.Sprintf("http://%s:%d%s", base, port, uri)
}

func makeTargetMatcher(targets []string) targetMatcher {
	matcher := targetMatcher{
		exact:    make(map[string]struct{}),
		prefixes: make([]netip.Prefix, 0),
	}

	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if trimmed == "" {
			continue
		}

		if prefix, err := netip.ParsePrefix(trimmed); err == nil {
			matcher.prefixes = append(matcher.prefixes, prefix)
			continue
		}

		matcher.exact[trimmed] = struct{}{}
	}

	return matcher
}

func (m targetMatcher) match(target string) bool {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return false
	}

	if len(m.exact) == 0 && len(m.prefixes) == 0 {
		return true
	}

	if _, ok := m.exact[trimmed]; ok {
		return true
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return false
	}

	for _, prefix := range m.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func parseCutoff(raw string) time.Time {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}
	}

	cutoff, err := time.Parse(time.RFC3339Nano, trimmed)
	if err != nil {
		return time.Time{}
	}

	return cutoff.UTC()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func mathModf(value float64) (float64, float64) {
	whole := float64(int64(value))
	return whole, value - whole
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return "auto"
	case "always", "force", "on":
		return "always"
	default:
		return "off"
	}
}

func isTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
