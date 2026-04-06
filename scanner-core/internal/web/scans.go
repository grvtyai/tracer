package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/app"
	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
	"github.com/grvtyai/tracer/scanner-core/internal/templates"
)

type preflightCheck struct {
	Name     string
	Status   string
	Detail   string
	Required bool
}

type scanFormData struct {
	ProjectID               string
	ScanName                string
	ScopeInput              string
	PortTemplate            string
	ActiveInterface         string
	PassiveInterface        string
	DetectedActiveInterface string
	StartTimeDisplay        string
	PassiveMode             string
	ZeekAutoStart           bool
	ZeekLogDir              string
	ContinueOnError         bool
	RetainPartialResults    bool
	ReevaluateAmbiguous     bool
	ReevaluatePreset        string
	ReevaluateAfter         string
	ReevaluateCustom        string
	EnableRouteSampling     bool
	EnableServiceScan       bool
	EnablePassiveIngest     bool
	EnableOSDetection       bool
	EnableLayer2            bool
	UseLargeRangeStrategy   bool
	ScanTag                 string
}

func (s *Server) handleScanNew(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderScanNew(w, r)
	case http.MethodPost:
		s.handleScanStart(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderScanNew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject == nil {
		http.Redirect(w, r, "/projects/new?notice=create-first-project", http.StatusSeeOther)
		return
	}

	form := defaultScanForm(currentProject)
	if value := strings.TrimSpace(r.URL.Query().Get("scope")); value != "" {
		form.ScopeInput = value
	}
	if value := strings.TrimSpace(r.URL.Query().Get("scan_name")); value != "" {
		form.ScanName = value
	}
	if value := strings.TrimSpace(r.URL.Query().Get("reevaluate_after")); value != "" {
		form.ReevaluatePreset, form.ReevaluateCustom, form.ReevaluateAmbiguous = reevaluatePreset(value)
		form.ReevaluateAfter = value
	}

	preflightChecks := collectPreflightChecks(s.options.DBPath)
	data := pageData{
		Title:             "Start Scan",
		AppName:           s.options.AppName,
		ActiveNav:         "discovery",
		ActiveSection:     "discovery-launch",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Configure and launch a Discovery run from the suite shell",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/scans/new",
		Project:           currentProject,
		Settings:          appSettings,
		PreflightChecks:   preflightChecks,
		ScanForm:          form,
	}
	s.render(w, "scan_new.html", data)
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	projectID := strings.TrimSpace(r.FormValue("project_id"))
	if projectID == "" {
		s.writeError(w, http.StatusBadRequest, fmt.Errorf("project_id is required"))
		return
	}

	project, err := s.repo.GetProject(r.Context(), projectID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	form := scanFormData{
		ProjectID:             projectID,
		ScanName:              firstNonEmptyWeb(strings.TrimSpace(r.FormValue("scan_name")), "Browser Scan"),
		ScopeInput:            strings.TrimSpace(r.FormValue("scope_input")),
		PortTemplate:          firstNonEmptyWeb(strings.TrimSpace(r.FormValue("port_template")), "all-default-ports"),
		ActiveInterface:       strings.TrimSpace(r.FormValue("active_interface")),
		PassiveInterface:      strings.TrimSpace(r.FormValue("passive_interface")),
		PassiveMode:           firstNonEmptyWeb(strings.TrimSpace(r.FormValue("passive_mode")), "auto"),
		ZeekLogDir:            strings.TrimSpace(r.FormValue("zeek_log_dir")),
		ScanTag:               firstNonEmptyWeb(strings.TrimSpace(r.FormValue("scan_tag")), "internal"),
		ContinueOnError:       isChecked(r.FormValue("continue_on_error")),
		RetainPartialResults:  isChecked(r.FormValue("retain_partial_results")),
		EnableRouteSampling:   isChecked(r.FormValue("enable_route_sampling")),
		EnableServiceScan:     isChecked(r.FormValue("enable_service_scan")),
		EnablePassiveIngest:   isChecked(r.FormValue("enable_passive_ingest")),
		EnableOSDetection:     isChecked(r.FormValue("enable_os_detection")),
		EnableLayer2:          isChecked(r.FormValue("enable_layer2")),
		UseLargeRangeStrategy: isChecked(r.FormValue("use_large_range_strategy")),
		ZeekAutoStart:         isChecked(r.FormValue("zeek_auto_start")),
	}
	form.ReevaluatePreset = firstNonEmptyWeb(strings.TrimSpace(r.FormValue("reevaluate_after_preset")), "off")
	form.ReevaluateCustom = strings.TrimSpace(r.FormValue("reevaluate_after_custom"))
	form.ReevaluateAmbiguous = form.ReevaluatePreset != "off"
	form.ReevaluateAfter = resolveReevaluateAfter(form.ReevaluatePreset, form.ReevaluateCustom)

	template, effectiveOptions, err := buildTemplateFromForm(form, project, s.options)
	if err != nil {
		http.Redirect(w, r, "/scans/new?project="+projectID+"&notice=scan-create-failed", http.StatusSeeOther)
		return
	}

	runRecord, runStore, err := s.repo.StartRun(r.Context(), project.ID, storage.RunSpec{
		TemplateName: template.Name,
		TemplatePath: "gui://scan-config",
		Mode:         "run",
		Scope:        template.Scope,
		Profile:      template.Profile,
		Options:      effectiveOptions,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	go s.executeScanAsync(project, runRecord, runStore, template, effectiveOptions)

	http.Redirect(w, r, "/runs?project="+project.ID+"&notice=scan-started", http.StatusSeeOther)
}

func (s *Server) executeScanAsync(project storage.ProjectSummary, runRecord storage.RunRecord, runStore *storage.SQLiteRunStore, template templates.Template, effective options.EffectiveOptions) {
	ctx := context.Background()
	templatePath, err := writeTemporaryTemplate(template)
	if err != nil {
		s.markRunLaunchFailed(ctx, runRecord.ID, runStore, template, fmt.Errorf("prepare scan template: %w", err))
		return
	}
	defer os.Remove(templatePath)

	cmd, err := buildScanWorkerCommand(runRecord.ID, project.Name, templatePath, effective)
	if err != nil {
		s.markRunLaunchFailed(ctx, runRecord.ID, runStore, template, err)
		return
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if runStillRunning, stateErr := s.runStillRunning(ctx, runRecord.ID); stateErr == nil && runStillRunning {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			s.markRunLaunchFailed(ctx, runRecord.ID, runStore, template, fmt.Errorf("launch root worker: %s", message))
		}
		return
	}

	if runStillRunning, err := s.runStillRunning(ctx, runRecord.ID); err == nil && runStillRunning {
		s.markRunLaunchFailed(ctx, runRecord.ID, runStore, template, fmt.Errorf("scan worker exited without finalizing the run"))
	}
}

func (s *Server) handlePreflightAPI(w http.ResponseWriter, r *http.Request) {
	checks := collectPreflightChecks(s.options.DBPath)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"checks":  checks,
		"healthy": preflightHealthy(checks),
		"state":   preflightState(checks),
	})
}

func collectPreflightChecks(dbPath string) []preflightCheck {
	checks := []preflightCheck{
		commandCheck("naabu", true),
		commandCheck("nmap", true),
		commandCheck("httpx", true),
		commandCheck("zgrab2", true),
		commandCheck("scamper", false),
		commandCheck("arp-scan", false),
		commandCheck("zeekctl", false),
		dbPathCheck(dbPath),
	}
	return checks
}

func commandCheck(name string, required bool) preflightCheck {
	if _, err := exec.LookPath(name); err != nil {
		status := "warning"
		if required {
			status = "error"
		}
		return preflightCheck{
			Name:     name,
			Status:   status,
			Detail:   "not found in PATH",
			Required: required,
		}
	}
	return preflightCheck{
		Name:     name,
		Status:   "ok",
		Detail:   "available",
		Required: required,
	}
}

func writeTemporaryTemplate(template templates.Template) (string, error) {
	file, err := os.CreateTemp("", "startrace-run-*.json")
	if err != nil {
		return "", err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(template); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func buildScanWorkerCommand(runID string, projectName string, templatePath string, effective options.EffectiveOptions) (*exec.Cmd, error) {
	tracerBinary, err := resolveTracerBinaryPath()
	if err != nil {
		return nil, err
	}

	args := []string{
		tracerBinary,
		"-mode", "execute-run",
		"-run-id", runID,
		"-template", templatePath,
		"-project", projectName,
		"-db-path", effective.DBPath,
		"-data-dir", effective.DataDir,
		"-continue-on-error", fmt.Sprintf("%t", effective.ContinueOnError),
		"-retain-partial-results", fmt.Sprintf("%t", effective.RetainPartialResults),
		"-reevaluate-ambiguous", fmt.Sprintf("%t", effective.ReevaluateAmbiguous),
		"-auto-start-zeek", fmt.Sprintf("%t", effective.AutoStartZeek),
	}
	if trimmed := strings.TrimSpace(effective.ActiveInterface); trimmed != "" {
		args = append(args, "-active-interface", trimmed)
	}
	if trimmed := strings.TrimSpace(effective.PassiveInterface); trimmed != "" {
		args = append(args, "-passive-interface", trimmed)
	}
	if trimmed := strings.TrimSpace(effective.PortTemplate); trimmed != "" {
		args = append(args, "-port-template", trimmed)
	}
	if trimmed := strings.TrimSpace(effective.PassiveMode); trimmed != "" {
		args = append(args, "-passive-mode", trimmed)
	}
	if trimmed := strings.TrimSpace(effective.ZeekLogDir); trimmed != "" {
		args = append(args, "-zeek-log-dir", trimmed)
	}
	if trimmed := strings.TrimSpace(effective.ReevaluateAfter); trimmed != "" {
		args = append(args, "-reevaluate-after", trimmed)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "linux" && !processRunsAsRoot() {
		sudoArgs := []string{"-n", "env", "PATH=" + os.Getenv("PATH")}
		sudoArgs = append(sudoArgs, args...)
		cmd = exec.Command("sudo", sudoArgs...)
	} else {
		cmd = exec.Command(args[0], args[1:]...)
		cmd.Env = os.Environ()
	}
	return cmd, nil
}

func resolveTracerBinaryPath() (string, error) {
	if executable, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(executable), "tracer")
		if runtime.GOOS == "windows" {
			sibling += ".exe"
		}
		if _, err := os.Stat(sibling); err == nil {
			return sibling, nil
		}
	}

	tracerBinary, err := exec.LookPath("tracer")
	if err != nil {
		return "", fmt.Errorf("locate tracer worker binary: %w", err)
	}
	return tracerBinary, nil
}

func processRunsAsRoot() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	output, err := exec.Command("id", "-u").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "0"
}

func (s *Server) runStillRunning(ctx context.Context, runID string) (bool, error) {
	run, err := s.repo.GetRun(ctx, runID)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(run.Run.Status), "running"), nil
}

func (s *Server) markRunLaunchFailed(ctx context.Context, runID string, runStore *storage.SQLiteRunStore, template templates.Template, err error) {
	now := time.Now().UTC()
	_ = runStore.WriteJobResults(ctx, []jobs.ExecutionResult{
		{
			JobID:      "scan-launch",
			Kind:       jobs.KindAnalyze,
			Plugin:     "launcher",
			Targets:    append(append([]string{}, template.Scope.Targets...), template.Scope.CIDRs...),
			Status:     jobs.StatusFailed,
			Error:      err.Error(),
			StartedAt:  now,
			FinishedAt: now,
		},
	})
	_ = s.repo.CompleteRun(ctx, runID, storage.RunCompletion{
		Status: "failed",
		Plan:   []jobs.Job{{ID: "scan-launch", Kind: jobs.KindAnalyze, Plugin: "launcher"}},
	})
}

func dbPathCheck(dbPath string) preflightCheck {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return preflightCheck{Name: "sqlite-store", Status: "error", Detail: err.Error(), Required: true}
	}
	file, err := os.CreateTemp(dir, "write-check-*")
	if err != nil {
		return preflightCheck{Name: "sqlite-store", Status: "error", Detail: "database directory is not writable", Required: true}
	}
	_ = file.Close()
	_ = os.Remove(file.Name())
	return preflightCheck{Name: "sqlite-store", Status: "ok", Detail: dbPath, Required: true}
}

func preflightHealthy(checks []preflightCheck) bool {
	for _, check := range checks {
		if check.Required && check.Status != "ok" {
			return false
		}
	}
	return true
}

func preflightState(checks []preflightCheck) string {
	for _, check := range checks {
		if check.Required && check.Status != "ok" {
			return "error"
		}
	}
	for _, check := range checks {
		if check.Status != "ok" {
			return "warning"
		}
	}
	return "ok"
}

func defaultScanForm(project *storage.ProjectSummary) scanFormData {
	scope := ""
	if project != nil && strings.TrimSpace(project.Notes) != "" {
		scope = ""
	}
	return scanFormData{
		ProjectID:               project.ID,
		ScanName:                "Quick Sweep",
		ScopeInput:              scope,
		PortTemplate:            "all-default-ports",
		ActiveInterface:         detectActiveInterface(),
		DetectedActiveInterface: detectActiveInterface(),
		StartTimeDisplay:        time.Now().Format("2006-01-02 15:04"),
		PassiveMode:             "auto",
		ZeekAutoStart:           true,
		ZeekLogDir:              "/opt/zeek/logs/current",
		ContinueOnError:         true,
		RetainPartialResults:    true,
		ReevaluateAmbiguous:     false,
		ReevaluatePreset:        "off",
		ReevaluateAfter:         "",
		ReevaluateCustom:        "",
		EnableRouteSampling:     true,
		EnableServiceScan:       true,
		EnablePassiveIngest:     true,
		EnableOSDetection:       true,
		ScanTag:                 "internal",
	}
}

func buildTemplateFromForm(form scanFormData, project storage.ProjectSummary, serverOptions Options) (templates.Template, options.EffectiveOptions, error) {
	scopeTargets, scopeCIDRs := splitScopeEntries(form.ScopeInput)
	if len(scopeTargets) == 0 && len(scopeCIDRs) == 0 {
		return templates.Template{}, options.EffectiveOptions{}, fmt.Errorf("scope is required")
	}

	templateName := form.ScanName
	if strings.TrimSpace(form.ScanTag) != "" {
		templateName = templateName + " [" + form.ScanTag + "]"
	}

	template := templates.Template{
		Name:        templateName,
		Description: "Browser-started scan",
		Scope: ingest.Scope{
			Name:    strings.TrimSpace(form.ScanName),
			Targets: scopeTargets,
			CIDRs:   scopeCIDRs,
			Labels: map[string]string{
				"scan_tag": form.ScanTag,
				"origin":   "browser",
			},
		},
		Profile: ingest.RunProfile{
			Name:                  "browser-default",
			EnableLayer2:          form.EnableLayer2,
			UseLargeRangeStrategy: form.UseLargeRangeStrategy,
			EnableRouteSampling:   form.EnableRouteSampling,
			EnableServiceScan:     form.EnableServiceScan,
			EnableOSDetection:     form.EnableOSDetection,
			EnablePassiveIngest:   form.EnablePassiveIngest,
			ZeekLogDir:            form.ZeekLogDir,
		},
		Options: options.TemplateOptions{
			Execution: options.ExecutionOptions{
				ContinueOnError:      boolPtr(form.ContinueOnError),
				RetainPartialResults: boolPtr(form.RetainPartialResults),
				ReevaluateAmbiguous:  boolPtr(form.ReevaluateAmbiguous),
				ReevaluateAfter:      resolveReevaluateAfter(form.ReevaluatePreset, form.ReevaluateCustom),
			},
			Network: options.NetworkOptions{
				ActiveInterface:  form.ActiveInterface,
				PassiveInterface: form.PassiveInterface,
			},
			Scan: options.ScanOptions{
				PortTemplate: form.PortTemplate,
			},
			Sensors: options.SensorOptions{
				PassiveMode:   form.PassiveMode,
				AutoStartZeek: boolPtr(form.ZeekAutoStart),
				ZeekLogDir:    form.ZeekLogDir,
			},
			Storage: options.StorageOptions{
				Project: project.Name,
				DataDir: serverOptions.DataDir,
				DBPath:  serverOptions.DBPath,
			},
		},
	}

	effective := app.ResolveOptions(template, options.TemplateOptions{})
	if !form.ReevaluateAmbiguous {
		effective.ReevaluateAfter = ""
	}
	effective.Project = project.Name
	effective.DataDir = serverOptions.DataDir
	effective.DBPath = serverOptions.DBPath
	if effective.ZeekLogDir == "" {
		effective.ZeekLogDir = "/opt/zeek/logs/current"
	}

	return template, effective, nil
}

func splitScopeEntries(raw string) ([]string, []string) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';' || r == ' '
	})
	targets := make([]string, 0)
	cidrs := make([]string, 0)
	seenTargets := make(map[string]struct{})
	seenCIDRs := make(map[string]struct{})
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			if _, ok := seenCIDRs[trimmed]; ok {
				continue
			}
			seenCIDRs[trimmed] = struct{}{}
			cidrs = append(cidrs, trimmed)
			continue
		}
		if _, ok := seenTargets[trimmed]; ok {
			continue
		}
		seenTargets[trimmed] = struct{}{}
		targets = append(targets, trimmed)
	}
	return targets, cidrs
}

func summarizeRunStatusWeb(results []jobs.ExecutionResult) string {
	for _, result := range results {
		if result.Status == jobs.StatusFailed {
			return "partial"
		}
	}
	return "completed"
}

func resolveReevaluateAfter(preset string, custom string) string {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "", "off":
		return ""
	case "15m":
		return "15m"
	case "30m":
		return "30m"
	case "1h":
		return "1h"
	case "custom":
		return strings.TrimSpace(custom)
	default:
		return strings.TrimSpace(preset)
	}
}

func reevaluatePreset(value string) (string, string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off":
		return "off", "", false
	case "15m":
		return "15m", "", true
	case "30m":
		return "30m", "", true
	case "1h":
		return "1h", "", true
	default:
		return "custom", strings.TrimSpace(value), true
	}
}

func detectActiveInterface() string {
	if runtimeValue := detectLinuxDefaultRouteInterface(); runtimeValue != "" {
		return runtimeValue
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return iface.Name
	}
	return ""
}

func detectLinuxDefaultRouteInterface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	firstLine := true
	for scanner.Scan() {
		if firstLine {
			firstLine = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return strings.TrimSpace(fields[0])
		}
	}
	return ""
}

func boolPtr(value bool) *bool {
	v := value
	return &v
}

func isChecked(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

func firstNonEmptyWeb(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
