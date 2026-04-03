package zeek

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

type Plugin struct{}

var _ engine.Plugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{}
}

func (Plugin) Name() string {
	return "zeek"
}

func (Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindPassiveIngest
}

func (Plugin) Run(_ context.Context, job jobs.Job) ([]evidence.Record, error) {
	logDir := strings.TrimSpace(job.Metadata["zeek_log_dir"])
	if logDir == "" {
		return nil, errors.New("zeek requires zeek_log_dir metadata")
	}

	targets := makeTargetSet(job.Targets)
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

		fileRecords, err := parseLogFile(file.path, job, targets, file.builder)
		if err != nil {
			return nil, err
		}
		parsedFiles++
		records = append(records, fileRecords...)
	}

	if parsedFiles == 0 {
		return nil, fmt.Errorf("no zeek logs found in %s", logDir)
	}

	return records, nil
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

func parseLogFile(path string, job jobs.Job, targets map[string]struct{}, builder func(zeekRow, jobs.Job, string, int) (evidence.Record, bool, error)) ([]evidence.Record, error) {
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
		target := strings.TrimSpace(row.values["id.resp_h"])
		if len(targets) > 0 && target != "" {
			if _, ok := targets[target]; !ok {
				continue
			}
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

func makeTargetSet(targets []string) map[string]struct{} {
	if len(targets) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if strings.TrimSpace(target) == "" {
			continue
		}
		set[strings.TrimSpace(target)] = struct{}{}
	}

	return set
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
