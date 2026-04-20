package suite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/controller/runnerclient"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/platform"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

func (s *Server) handleMonitoring(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/monitoring" {
		http.NotFound(w, r)
		return
	}
	s.renderSuitePlaceholder(w, r, "Monitoring", "Monitoring is the home for Satelites, runtime health and later distributed job execution across the wider Startrace environment.", []string{
		"The local Startrace Nexus is already exposed as the first execution target.",
		"Monitoring gives future remote Satelites a clear place in the product before the runner protocol is wired in.",
		"Health and Jobs can grow here without overloading Radar itself.",
	}, []string{
		"Track registered Satelites and show their runtime status.",
		"Surface Nexus and later remote Satelite health from one place.",
		"Prepare job visibility before distributed execution goes live.",
	}, &pageAction{Label: "Open Satelites", URL: buildProjectPath("/monitoring/satellites", nil), Variant: "button-secondary"}, false)
}

func (s *Server) handleMonitoringSatellites(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/monitoring/satellites" {
		http.NotFound(w, r)
		return
	}

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

	preflightChecks := collectPreflightChecks(s.options.DBPath)
	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	monitoringSatelliteList, nexus, err := s.monitoringSatellites(ctx, preflightChecks, runs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	data := pageData{
		Title:                "Monitoring - Satelites",
		AppName:              s.options.AppName,
		ActiveNav:            "monitoring",
		ActiveSection:        "monitoring-satellites",
		BasePath:             s.options.BasePath,
		DBPath:               s.options.DBPath,
		DataDir:              s.options.DataDir,
		HeroNote:             "Execution targets for local and later remote jobs",
		Projects:             projects,
		CurrentProject:       currentProject,
		ProjectSwitchPath:    "/monitoring/satellites",
		Project:              currentProject,
		PreflightChecks:      preflightChecks,
		Notice:               noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Settings:             appSettings,
		MonitoringSatellites: filterRegisteredSatellites(monitoringSatelliteList),
		MonitoringNexus:      &nexus,
		MonitoringStats:      buildMonitoringSatelliteStats(nexus, monitoringSatelliteList, mustListAssets(ctx, s.repo, currentProject.ID)),
		PrimaryAction: &pageAction{
			Label:   "Register new Satelite",
			URL:     buildProjectPath("/monitoring/satellites/register", currentProject),
			Variant: "button-primary",
		},
		SecondaryAction: &pageAction{
			Label:   "Open Health",
			URL:     buildProjectPath("/monitoring/health", currentProject),
			Variant: "button-secondary",
		},
	}
	s.render(w, "monitoring_satellites.html", data)
}

func (s *Server) handleMonitoringSatelliteRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderMonitoringSatelliteRegister(w, r, satelliteRegisterFormData{})
	case http.MethodPost:
		s.handleMonitoringSatelliteRegisterSave(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderMonitoringSatelliteRegister(w http.ResponseWriter, r *http.Request, form satelliteRegisterFormData) {
	if r.URL.Path != "/monitoring/satellites/register" {
		http.NotFound(w, r)
		return
	}

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

	if strings.TrimSpace(form.Name) == "" {
		form = defaultSatelliteRegisterForm()
	}
	preflightChecks := collectPreflightChecks(s.options.DBPath)
	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	_, nexus, err := s.monitoringSatellites(ctx, preflightChecks, runs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	data := pageData{
		Title:                 "Register Satelite",
		AppName:               s.options.AppName,
		ActiveNav:             "monitoring",
		ActiveSection:         "monitoring-satellites",
		BasePath:              s.options.BasePath,
		DBPath:                s.options.DBPath,
		DataDir:               s.options.DataDir,
		HeroNote:              "Prepared registration flow for future remote Satelites",
		Projects:              projects,
		CurrentProject:        currentProject,
		ProjectSwitchPath:     "/monitoring/satellites/register",
		Project:               currentProject,
		PreflightChecks:       preflightChecks,
		Notice:                noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Settings:              appSettings,
		MonitoringNexus:       &nexus,
		SatelliteRegisterForm: form,
		PrimaryAction: &pageAction{
			Label:   "Back to Satelites",
			URL:     buildProjectPath("/monitoring/satellites", currentProject),
			Variant: "button-secondary",
		},
	}
	s.render(w, "monitoring_satellite_register.html", data)
}

func (s *Server) handleMonitoringSatelliteRegisterSave(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/monitoring/satellites/register" {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	ctx := r.Context()
	_, currentProject, _, err := s.loadShellContext(ctx, strings.TrimSpace(r.FormValue("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject == nil {
		http.Redirect(w, r, "/projects/new?notice=create-first-project", http.StatusSeeOther)
		return
	}

	form := satelliteRegisterFormData{
		Name:              strings.TrimSpace(r.FormValue("name")),
		Address:           strings.TrimSpace(r.FormValue("address")),
		Role:              firstNonEmptyWeb(strings.TrimSpace(r.FormValue("role")), "Remote Satelite"),
		RegistrationToken: strings.TrimSpace(r.FormValue("registration_token")),
	}

	if strings.TrimSpace(form.Name) == "" || strings.TrimSpace(form.Address) == "" {
		redirectURL := buildProjectPath("/monitoring/satellites/register", currentProject)
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&notice=satellite-register-failed"
		} else {
			redirectURL += "?notice=satellite-register-failed"
		}
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(form.RegistrationToken) == "" {
		form.RegistrationToken = generateRegistrationToken()
	}

	satelliteID := "satellite-" + slugifySatelliteName(form.Name) + "-" + time.Now().UTC().Format("20060102150405")
	stored, err := s.repo.UpsertSatellite(ctx, storage.SatelliteUpsertInput{
		ID:                    satelliteID,
		Name:                  form.Name,
		Kind:                  "satellite",
		Role:                  form.Role,
		Status:                "Awaiting heartbeat",
		Address:               form.Address,
		Hostname:              "",
		Platform:              "Pending registration",
		Executor:              "Remote runner",
		LastSeenAt:            time.Time{},
		RegistrationTokenHint: form.RegistrationToken,
		Capabilities:          nil,
	})
	if err != nil {
		s.renderMonitoringSatelliteRegister(w, r, form)
		return
	}

	// Best-effort probe — updates status, capabilities and TLS fingerprint if
	// the satellite is already running. Silently skipped when not yet reachable.
	if probe := probeSatellite(ctx, form.Address, form.RegistrationToken); probe.Online {
		_, _ = s.repo.UpsertSatellite(ctx, storage.SatelliteUpsertInput{
			ID:                    stored.ID,
			Name:                  stored.Name,
			Kind:                  stored.Kind,
			Role:                  stored.Role,
			Status:                "Online",
			Address:               stored.Address,
			Hostname:              stored.Hostname,
			Platform:              "Satellite " + probe.Version,
			Executor:              stored.Executor,
			LastSeenAt:            time.Now().UTC(),
			RegistrationTokenHint: stored.RegistrationTokenHint,
			TLSFingerprint:        probe.TLSFingerprint,
			Capabilities:          probe.Capabilities,
		})
	}

	redirectURL := buildProjectPath("/monitoring/satellites", currentProject)
	if strings.Contains(redirectURL, "?") {
		redirectURL += "&notice=satellite-registered"
	} else {
		redirectURL += "?notice=satellite-registered"
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (s *Server) handleMonitoringSatelliteRefresh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/monitoring/satellites/refresh" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	satelliteID := strings.TrimSpace(r.URL.Query().Get("id"))
	projectParam := strings.TrimSpace(r.URL.Query().Get("project"))

	if satelliteID == "" {
		http.Redirect(w, r, "/monitoring/satellites", http.StatusSeeOther)
		return
	}

	satellites, err := s.repo.ListSatellites(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	var sat *storage.Satellite
	for i := range satellites {
		if satellites[i].ID == satelliteID {
			sat = &satellites[i]
			break
		}
	}
	if sat == nil {
		http.Redirect(w, r, "/monitoring/satellites", http.StatusSeeOther)
		return
	}

	if probe := probeSatellite(ctx, sat.Address, sat.RegistrationTokenHint); probe.Online {
		_, _ = s.repo.UpsertSatellite(ctx, storage.SatelliteUpsertInput{
			ID:                    sat.ID,
			Name:                  sat.Name,
			Kind:                  sat.Kind,
			Role:                  sat.Role,
			Status:                "Online",
			Address:               sat.Address,
			Hostname:              sat.Hostname,
			Platform:              "Satellite " + probe.Version,
			Executor:              sat.Executor,
			LastSeenAt:            time.Now().UTC(),
			RegistrationTokenHint: sat.RegistrationTokenHint,
			Capabilities:          probe.Capabilities,
		})
	} else {
		_, _ = s.repo.UpsertSatellite(ctx, storage.SatelliteUpsertInput{
			ID:                    sat.ID,
			Name:                  sat.Name,
			Kind:                  sat.Kind,
			Role:                  sat.Role,
			Status:                "Offline",
			Address:               sat.Address,
			Hostname:              sat.Hostname,
			Platform:              sat.Platform,
			Executor:              sat.Executor,
			LastSeenAt:            sat.LastSeenAt,
			RegistrationTokenHint: sat.RegistrationTokenHint,
			Capabilities:          sat.Capabilities,
		})
	}

	redirectURL := "/monitoring/satellites"
	sep := "?"
	if projectParam != "" {
		redirectURL += sep + "project=" + projectParam
		sep = "&"
	}
	redirectURL += sep + "notice=satellite-refreshed"
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (s *Server) handleMonitoringHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/monitoring/health" {
		http.NotFound(w, r)
		return
	}

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

	preflightChecks := collectPreflightChecks(s.options.DBPath)
	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	monitoringSatelliteList, nexus, err := s.monitoringSatellites(ctx, preflightChecks, runs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	data := pageData{
		Title:             "Monitoring - Health",
		AppName:           s.options.AppName,
		ActiveNav:         "monitoring",
		ActiveSection:     "monitoring-health",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Current health of the local Startrace execution node",
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/monitoring/health",
		Project:           currentProject,
		PreflightChecks:   preflightChecks,
		Settings:          appSettings,
		MonitoringNexus:   &nexus,
		MonitoringStats:   buildMonitoringHealthStats(monitoringSatelliteList, preflightChecks, runs),
		MonitoringFacts:   s.buildMonitoringHealthFacts(preflightChecks, runs),
		MonitoringTooling: buildMonitoringTooling(preflightChecks),
		MonitoringChecks:  buildMonitoringChecks(preflightChecks, runs, currentProject, s.options),
		PrimaryAction: &pageAction{
			Label:   "Open Satelites",
			URL:     buildProjectPath("/monitoring/satellites", currentProject),
			Variant: "button-primary",
		},
		SecondaryAction: &pageAction{
			Label:   "Open Jobs",
			URL:     buildProjectPath("/monitoring/jobs", currentProject),
			Variant: "button-secondary",
		},
	}
	s.render(w, "monitoring_health.html", data)
}

func (s *Server) handleMonitoringJobs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/monitoring/jobs" {
		http.NotFound(w, r)
		return
	}

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

	preflightChecks := collectPreflightChecks(s.options.DBPath)
	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	monitoringSatelliteList, nexus, err := s.monitoringSatellites(ctx, preflightChecks, runs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	monitoringJobQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	monitoringJobStatus := firstNonEmptyWeb(strings.TrimSpace(r.URL.Query().Get("status")), "all")
	monitoringJobList := filterMonitoringJobs(s.buildMonitoringJobs(ctx, currentProject, runs), monitoringJobQuery, monitoringJobStatus)
	data := pageData{
		Title:               "Monitoring - Jobs",
		AppName:             s.options.AppName,
		ActiveNav:           "monitoring",
		ActiveSection:       "monitoring-jobs",
		BasePath:            s.options.BasePath,
		DBPath:              s.options.DBPath,
		DataDir:             s.options.DataDir,
		HeroNote:            "Planned execution visibility for local and later remote jobs",
		Projects:            projects,
		CurrentProject:      currentProject,
		ProjectSwitchPath:   "/monitoring/jobs",
		Project:             currentProject,
		PreflightChecks:     preflightChecks,
		Settings:            appSettings,
		MonitoringNexus:     &nexus,
		MonitoringJobs:      monitoringJobList,
		MonitoringStats:     buildMonitoringJobStats(monitoringSatelliteList, monitoringJobList),
		MonitoringJobQuery:  monitoringJobQuery,
		MonitoringJobStatus: monitoringJobStatus,
		PrimaryAction: &pageAction{
			Label:   "Open Satelites",
			URL:     buildProjectPath("/monitoring/satellites", currentProject),
			Variant: "button-primary",
		},
		SecondaryAction: &pageAction{
			Label:   "Open Health",
			URL:     buildProjectPath("/monitoring/health", currentProject),
			Variant: "button-secondary",
		},
	}
	s.render(w, "monitoring_jobs.html", data)
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/security" {
		http.NotFound(w, r)
		return
	}
	s.renderSuitePlaceholder(w, r, "Security", "Shared findings, checks and security-focused workflows for every project.", []string{
		"Security should consume the same assets, runs and future artifacts as the other modules.",
		"Discovery output will become one source of findings here, not the whole story.",
		"This area is the right home for lightweight checks before heavier scanners ever show up.",
	}, []string{
		"Introduce a shared findings model above raw scan evidence.",
		"Add first security summaries that correlate assets, open services and future checks.",
		"Prepare the UI for module-owned reports and remediation guidance.",
	}, &pageAction{Label: "Open Discovery", URL: buildProjectPath("/discovery", nil), Variant: "button-secondary"}, true)
}

func (s *Server) handleWorkbench(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/workbench" {
		http.NotFound(w, r)
		return
	}
	s.renderSuitePlaceholder(w, r, "Workbench", "Operator-driven tools such as an HTTP repeater or request lab belong here, while still sharing project context with the suite.", []string{
		"Workbench is the best place for hands-on utilities that do not fit the scheduled scan model.",
		"Artifacts from here should still be linkable to assets, hosts and later security findings.",
		"Starting with a focused HTTP tool is a good architectural test because it forces the suite to support more than discovery.",
	}, []string{
		"Add a shared artifact model for requests, responses and notes.",
		"Build a first HTTP workbench instead of a full Burp-style proxy stack.",
		"Verify that non-scanner tools can live cleanly inside the same product shell.",
	}, &pageAction{Label: "Open Inventory", URL: buildProjectPath("/inventory", nil), Variant: "button-secondary"}, true)
}

func (s *Server) handleAutomation(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/automation" {
		http.NotFound(w, r)
		return
	}
	s.renderSuitePlaceholder(w, r, "Automation", "Automation will own scheduled and repeatable module tasks across the suite, not only discovery reevaluations.", []string{
		"Stored reevaluation records already exist, but they still need a generic executor to become real platform automation.",
		"Discovery is the first consumer, but the scheduler should be module-agnostic from the beginning.",
		"Later notifications, recurring jobs and maintenance tasks should all land here.",
	}, []string{
		"Promote scheduled scans into a generic task scheduler and runner.",
		"Track pending, running, completed and failed automation runs independently from discovery runs.",
		"Expose a UI for module-owned schedules instead of special-case scanner forms.",
	}, &pageAction{Label: "Open Discovery", URL: buildProjectPath("/discovery", nil), Variant: "button-secondary"}, true)
}

func (s *Server) satelliteOptions(ctx context.Context) []satelliteOption {
	preflightChecks := collectPreflightChecks(s.options.DBPath)
	nexus := s.buildMonitoringNexus(preflightChecks, nil)
	if _, err := s.ensureBuiltinMonitoringSatellite(ctx, preflightChecks, nil); err != nil {
		return []satelliteOption{{
			ID:     nexus.ID,
			Label:  fmt.Sprintf("Startrace Nexus - %s", nexus.Address),
			Detail: "Built-in local execution target",
		}}
	}

	storedSatellites, err := s.repo.ListSatellites(ctx)
	if err != nil || len(storedSatellites) == 0 {
		return []satelliteOption{{
			ID:     nexus.ID,
			Label:  fmt.Sprintf("Startrace Nexus - %s", nexus.Address),
			Detail: "Built-in local execution target",
		}}
	}

	opts := make([]satelliteOption, 0, len(storedSatellites))
	for _, satellite := range storedSatellites {
		opts = append(opts, satelliteOption{
			ID:     satellite.ID,
			Label:  firstNonEmptyWeb(strings.TrimSpace(satellite.Name), satellite.ID) + " - " + firstNonEmptyWeb(strings.TrimSpace(satellite.Address), "no-address"),
			Detail: firstNonEmptyWeb(strings.TrimSpace(satellite.Role), "Execution target"),
		})
	}
	return opts
}

func resolveSatelliteSelection(selectedID string, opts []satelliteOption) satelliteOption {
	for _, option := range opts {
		if strings.TrimSpace(selectedID) != "" && option.ID == selectedID {
			return option
		}
	}
	if len(opts) > 0 {
		return opts[0]
	}
	return satelliteOption{
		ID:     "nexus",
		Label:  "Startrace Nexus - 127.0.0.1",
		Detail: "Built-in local execution target",
	}
}

func (s *Server) monitoringSatellites(ctx context.Context, checks []preflightCheck, runs []storage.RunSummary) ([]monitoringSatellite, monitoringSatellite, error) {
	nexusStored, err := s.ensureBuiltinMonitoringSatellite(ctx, checks, runs)
	if err != nil {
		return nil, monitoringSatellite{}, err
	}

	storedSatellites, err := s.repo.ListSatellites(ctx)
	if err != nil {
		return nil, monitoringSatellite{}, err
	}

	result := make([]monitoringSatellite, 0, len(storedSatellites))
	nexusView := s.buildMonitoringNexus(checks, runs)
	nexusView.FirstSeen = formatMonitoringTimestamp(nexusStored.CreatedAt)
	if len(storedSatellites) == 0 {
		return []monitoringSatellite{nexusView}, nexusView, nil
	}

	for _, satellite := range storedSatellites {
		view := s.monitoringSatelliteFromStored(satellite)
		if satellite.ID == nexusStored.ID {
			view = nexusView
		}
		result = append(result, view)
	}
	return result, nexusView, nil
}

func (s *Server) ensureBuiltinMonitoringSatellite(ctx context.Context, checks []preflightCheck, runs []storage.RunSummary) (storage.Satellite, error) {
	nexus := s.buildMonitoringNexus(checks, runs)
	return s.repo.UpsertSatellite(ctx, storage.SatelliteUpsertInput{
		ID:                    nexus.ID,
		Name:                  nexus.Name,
		Kind:                  "nexus",
		Role:                  nexus.Role,
		Status:                nexus.Status,
		Address:               nexus.Address,
		Hostname:              nexus.Hostname,
		Platform:              nexus.Platform,
		Executor:              nexus.Executor,
		LastSeenAt:            time.Now().UTC(),
		RegistrationTokenHint: "Built-in local node",
		Capabilities:          monitoringCapabilities(checks),
	})
}

func (s *Server) monitoringSatelliteFromStored(satellite storage.Satellite) monitoringSatellite {
	statusClass := "status-neutral"
	switch strings.ToLower(strings.TrimSpace(satellite.Status)) {
	case "healthy", "online":
		statusClass = "status-success"
	case "needs attention", "warning", "awaiting heartbeat", "registered":
		statusClass = "status-warning"
	case "degraded", "offline", "error":
		statusClass = "status-danger"
	}

	lastSeen := "No heartbeat yet"
	if !satellite.LastSeenAt.IsZero() {
		lastSeen = formatMonitoringTimestamp(satellite.LastSeenAt)
	}

	summary := "Prepared execution target"
	if len(satellite.Capabilities) > 0 {
		summary = strings.Join(satellite.Capabilities, ", ")
	}

	return monitoringSatellite{
		ID:          satellite.ID,
		Name:        satellite.Name,
		Role:        satellite.Role,
		Status:      firstNonEmptyWeb(strings.TrimSpace(satellite.Status), "Unknown"),
		StatusClass: statusClass,
		Address:     satellite.Address,
		Hostname:    satellite.Hostname,
		Platform:    satellite.Platform,
		Executor:    satellite.Executor,
		LastSeen:    lastSeen,
		FirstSeen:   formatMonitoringTimestamp(satellite.CreatedAt),
		Summary:     summary,
	}
}

func filterRegisteredSatellites(satellites []monitoringSatellite) []monitoringSatellite {
	filtered := make([]monitoringSatellite, 0, len(satellites))
	for _, satellite := range satellites {
		if strings.EqualFold(strings.TrimSpace(satellite.ID), "nexus") {
			continue
		}
		filtered = append(filtered, satellite)
	}
	return filtered
}

func defaultSatelliteRegisterForm() satelliteRegisterFormData {
	return satelliteRegisterFormData{
		Name:              "Branch Office Satelite",
		Address:           "10.20.30.40:8765",
		Role:              "Remote Satelite",
		RegistrationToken: generateRegistrationToken(),
	}
}

func slugifySatelliteName(name string) string {
	lowered := strings.ToLower(strings.TrimSpace(name))
	if lowered == "" {
		return "node"
	}
	var builder strings.Builder
	lastDash := false
	for _, r := range lowered {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				builder.WriteRune('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

type satelliteProbeResult struct {
	Online         bool
	Version        string
	Capabilities   []string
	TLSFingerprint string
}

// probeSatellite contacts the satellite at address using token and returns live
// status. address may be "host:port" or a full "https://host:port" URL.
// For HTTPS (the default), the first contact is a TOFU probe: the cert is
// accepted regardless of CA and the SHA-256 fingerprint is captured for
// future pinning. Returns an empty result (Online=false) on any error.
func probeSatellite(ctx context.Context, address, token string) satelliteProbeResult {
	baseURL := address
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	var capturedFingerprint string
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // TOFU: fingerprint captured and stored
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) > 0 && capturedFingerprint == "" {
						sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
						capturedFingerprint = hex.EncodeToString(sum[:])
					}
					return nil
				},
			},
		},
	}

	client, err := runnerclient.New(runnerclient.Config{
		BaseURL:    baseURL,
		AuthToken:  token,
		HTTPClient: httpClient,
	})
	if err != nil {
		return satelliteProbeResult{}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	health, err := client.Health(probeCtx)
	if err != nil {
		return satelliteProbeResult{}
	}

	caps, err := client.Capabilities(probeCtx)
	if err != nil {
		return satelliteProbeResult{Online: true, Version: health.Version, TLSFingerprint: capturedFingerprint}
	}

	pluginNames := make([]string, 0, len(caps.Plugins))
	for _, p := range caps.Plugins {
		pluginNames = append(pluginNames, p.Name)
	}
	return satelliteProbeResult{
		Online:         true,
		Version:        health.Version,
		Capabilities:   pluginNames,
		TLSFingerprint: capturedFingerprint,
	}
}

func generateRegistrationToken() string {
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return "STRC-REG-PENDING"
	}
	encoded := strings.ToUpper(hex.EncodeToString(randomBytes))
	return "STRC-REG-" + encoded[:4] + "-" + encoded[4:8] + "-" + encoded[8:12]
}

func (s *Server) buildMonitoringNexus(checks []preflightCheck, runs []storage.RunSummary) monitoringSatellite {
	nexus := s.monitoringNexus()
	switch preflightState(checks) {
	case "ok":
		nexus.Status = "Healthy"
		nexus.StatusClass = "status-success"
		nexus.LastSeen = "Heartbeat healthy"
	case "warning":
		nexus.Status = "Needs attention"
		nexus.StatusClass = "status-warning"
		nexus.LastSeen = "Heartbeat active"
	default:
		nexus.Status = "Degraded"
		nexus.StatusClass = "status-danger"
		nexus.LastSeen = "Heartbeat degraded"
	}

	readyTools, totalTools := monitoringToolingCounts(checks)
	summaryParts := []string{
		fmt.Sprintf("%d/%d toolkit checks ready", readyTools, totalTools),
		fmt.Sprintf("%d local run(s)", len(runs)),
	}
	if lastSuccessful := latestRunMatching(runs, func(run storage.RunSummary) bool {
		return strings.EqualFold(strings.TrimSpace(run.Status), "completed")
	}); lastSuccessful != nil {
		summaryParts = append(summaryParts, "last successful run: "+firstNonEmptyWeb(strings.TrimSpace(lastSuccessful.TemplateName), "Radar run"))
	}
	nexus.Summary = strings.Join(summaryParts, " | ")
	return nexus
}

func buildMonitoringSatelliteStats(nexus monitoringSatellite, satellites []monitoringSatellite, assets []storage.AssetSummary) []monitoringStat {
	registeredSatellites := len(filterRegisteredSatellites(satellites))
	nexusStatus := "Online - Stable"
	statusClass := "status-success"
	switch nexus.StatusClass {
	case "status-warning":
		nexusStatus = "Online - Warning"
		statusClass = "status-warning"
	case "status-danger":
		nexusStatus = "Offline"
		statusClass = "status-danger"
	}

	return []monitoringStat{
		{Label: "Registered Satelites", Value: fmt.Sprintf("%d", registeredSatellites)},
		{Label: "Nexus Status", Value: nexusStatus, StatusClass: statusClass},
		{Label: "Inventory", Value: fmt.Sprintf("%d", len(assets))},
		{Label: "Subnets", Value: fmt.Sprintf("%d", countUniqueSubnets(assets))},
	}
}

func buildMonitoringHealthStats(satellites []monitoringSatellite, checks []preflightCheck, runs []storage.RunSummary) []monitoringStat {
	statusValue := "Healthy"
	switch preflightState(checks) {
	case "warning":
		statusValue = "Needs attention"
	case "error":
		statusValue = "Degraded"
	}

	readyTools, totalTools := monitoringToolingCounts(checks)
	lastSuccessfulLabel := "No successful run yet"
	if latestSuccessful := latestRunMatching(runs, func(run storage.RunSummary) bool {
		return strings.EqualFold(strings.TrimSpace(run.Status), "completed")
	}); latestSuccessful != nil {
		lastSuccessfulLabel = firstNonEmptyWeb(strings.TrimSpace(latestSuccessful.TemplateName), "Radar run")
	}

	statusClass := ""
	switch statusValue {
	case "Healthy":
		statusClass = "status-success"
	case "Needs attention":
		statusClass = "status-warning"
	case "Degraded":
		statusClass = "status-danger"
	}

	return []monitoringStat{
		{Label: "Nexus", Value: statusValue, StatusClass: statusClass},
		{Label: "Registered nodes", Value: fmt.Sprintf("%d", len(satellites))},
		{Label: "Tooling", Value: fmt.Sprintf("%d / %d ready", readyTools, totalTools)},
		{Label: "Last success", Value: lastSuccessfulLabel},
	}
}

func buildMonitoringJobStats(satellites []monitoringSatellite, jobList []monitoringJob) []monitoringStat {
	completed := 0
	running := 0
	attention := 0
	for _, job := range jobList {
		switch job.StatusClass {
		case "status-success":
			completed++
		case "status-info":
			running++
		case "status-warning", "status-danger":
			attention++
		}
	}

	return []monitoringStat{
		{Label: "Visible jobs", Value: fmt.Sprintf("%d", len(jobList))},
		{Label: "Execution nodes", Value: fmt.Sprintf("%d", len(satellites))},
		{Label: "Running", Value: fmt.Sprintf("%d", running)},
		{Label: "Completed", Value: fmt.Sprintf("%d", completed)},
		{Label: "Needs attention", Value: fmt.Sprintf("%d", attention)},
	}
}

func (s *Server) buildMonitoringHealthFacts(checks []preflightCheck, runs []storage.RunSummary) []monitoringFact {
	dataDir := firstNonEmptyWeb(s.options.DataDir, storage.DefaultDataDir())
	facts := []monitoringFact{
		{Key: "Hostname", Value: inventoryOriginHostname()},
		{Key: "Primary address", Value: detectNexusAddress()},
		{Key: "Active interface", Value: firstNonEmptyWeb(detectActiveInterface(), "-")},
		{Key: "Platform", Value: runtime.GOOS + "/" + runtime.GOARCH},
		{Key: "Startrace process uptime", Value: formatMonitoringDuration(time.Since(s.started))},
		{Key: "Host uptime", Value: monitoringHostUptimeSummary()},
		{Key: "CPU", Value: monitoringCPUSummary()},
		{Key: "Memory", Value: monitoringMemorySummary()},
		{Key: "Data dir usage", Value: monitoringFilesystemUsage(dataDir)},
		{Key: "Zeek runtime", Value: monitoringZeekRuntime()},
		{Key: "Privileges", Value: firstNonEmptyWeb(preflightCheckDetail(checks, "process-privileges"), "Unknown")},
		{Key: "SQLite write test", Value: firstNonEmptyWeb(preflightCheckDetail(checks, "sqlite-store"), "Unknown")},
		{Key: "SQLite store", Value: firstNonEmptyWeb(s.options.DBPath, "-")},
		{Key: "Data directory", Value: dataDir},
	}

	if latestSuccessful := latestRunMatching(runs, func(run storage.RunSummary) bool {
		return strings.EqualFold(strings.TrimSpace(run.Status), "completed")
	}); latestSuccessful != nil {
		facts = append(facts,
			monitoringFact{Key: "Last successful run", Value: firstNonEmptyWeb(strings.TrimSpace(latestSuccessful.TemplateName), "Radar run")},
			monitoringFact{Key: "Finished at", Value: formatMonitoringTimestamp(latestSuccessful.FinishedAt)},
		)
	}

	return facts
}

func buildMonitoringTooling(checks []preflightCheck) []monitoringTool {
	tools := make([]monitoringTool, 0)
	for _, check := range checks {
		if !isMonitoringToolCheck(check.Name) {
			continue
		}
		path := "-"
		if resolved, err := platform.ResolveExecutable(check.Name); err == nil {
			path = resolved
		}
		tool := monitoringTool{
			Name:        check.Name,
			Required:    check.Required,
			Status:      monitoringToolStatusLabel(check.Status),
			StatusClass: monitoringToolStatusClass(check.Status),
			Path:        path,
			Version:     monitoringToolVersion(check.Name, check.Status),
			Runtime:     monitoringToolRuntime(check.Name, check.Status),
		}
		tools = append(tools, tool)
	}
	return tools
}

func buildMonitoringChecks(checks []preflightCheck, runs []storage.RunSummary, currentProject *storage.ProjectSummary, opts Options) []monitoringCheck {
	monitoring := make([]monitoringCheck, 0, 5)

	sqliteStatus := "Healthy"
	sqliteClass := "status-success"
	sqliteDetail := firstNonEmptyWeb(preflightCheckDetail(checks, "sqlite-store"), firstNonEmptyWeb(opts.DBPath, "-"))
	if sqliteDetail == "" || strings.Contains(strings.ToLower(sqliteDetail), "not writable") {
		sqliteStatus = "Failed"
		sqliteClass = "status-danger"
	}
	monitoring = append(monitoring, monitoringCheck{
		Name:        "SQLite store",
		Status:      sqliteStatus,
		StatusClass: sqliteClass,
		Detail:      sqliteDetail,
	})

	readyTools, totalTools := monitoringToolingCounts(checks)
	toolkitStatus := "Healthy"
	toolkitClass := "status-success"
	if readyTools < totalTools {
		toolkitStatus = "Degraded"
		toolkitClass = "status-warning"
	}
	requiredMissing := false
	for _, check := range checks {
		if check.Required && check.Status != "ok" {
			requiredMissing = true
			break
		}
	}
	if requiredMissing {
		toolkitStatus = "Failed"
		toolkitClass = "status-danger"
	}
	monitoring = append(monitoring, monitoringCheck{
		Name:        "Toolkit readiness",
		Status:      toolkitStatus,
		StatusClass: toolkitClass,
		Detail:      fmt.Sprintf("%d / %d tools ready", readyTools, totalTools),
	})

	usagePercent, usageDetail := monitoringFilesystemMetrics(firstNonEmptyWeb(opts.DataDir, storage.DefaultDataDir()))
	storageStatus := "Healthy"
	storageClass := "status-success"
	switch {
	case usagePercent >= 95:
		storageStatus = "Critical"
		storageClass = "status-danger"
	case usagePercent >= 85:
		storageStatus = "Warning"
		storageClass = "status-warning"
	case usagePercent < 0:
		storageStatus = "Unknown"
		storageClass = "status-neutral"
	}
	monitoring = append(monitoring, monitoringCheck{
		Name:        "Storage headroom",
		Status:      storageStatus,
		StatusClass: storageClass,
		Detail:      usageDetail,
	})

	runFreshnessStatus := "No runs"
	runFreshnessClass := "status-warning"
	runFreshnessDetail := "No successful Radar run recorded yet."
	if latestSuccessful := latestRunMatching(runs, func(run storage.RunSummary) bool {
		return strings.EqualFold(strings.TrimSpace(run.Status), "completed")
	}); latestSuccessful != nil {
		age := time.Since(latestSuccessful.FinishedAt)
		runFreshnessStatus = "Fresh"
		runFreshnessClass = "status-success"
		if age > 24*time.Hour {
			runFreshnessStatus = "Stale"
			runFreshnessClass = "status-warning"
		}
		if age > 7*24*time.Hour {
			runFreshnessStatus = "Old"
			runFreshnessClass = "status-danger"
		}
		runFreshnessDetail = fmt.Sprintf("%s | %s", firstNonEmptyWeb(strings.TrimSpace(latestSuccessful.TemplateName), "Radar run"), formatMonitoringTimestamp(latestSuccessful.FinishedAt))
	}
	monitoring = append(monitoring, monitoringCheck{
		Name:        "Run freshness",
		Status:      runFreshnessStatus,
		StatusClass: runFreshnessClass,
		Detail:      runFreshnessDetail,
	})

	registryCount := 0
	if currentProject != nil {
		registryCount = currentProject.RunCount
	}
	registryDetail := "Nexus only"
	if registryCount > 0 {
		registryDetail = fmt.Sprintf("%d project runs tracked", registryCount)
	}
	monitoring = append(monitoring, monitoringCheck{
		Name:        "Registry state",
		Status:      "Ready",
		StatusClass: "status-success",
		Detail:      registryDetail,
	})

	return monitoring
}

func filterMonitoringJobs(items []monitoringJob, query string, status string) []monitoringJob {
	filtered := make([]monitoringJob, 0, len(items))
	needle := strings.ToLower(strings.TrimSpace(query))
	for _, item := range items {
		if !monitoringJobMatchesStatus(item, status) {
			continue
		}
		if needle != "" {
			haystack := strings.ToLower(strings.Join([]string{
				item.Name,
				item.Project,
				item.Target,
				item.Execution,
				item.Status,
				item.Summary,
			}, " "))
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func monitoringJobMatchesStatus(item monitoringJob, status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "all":
		return true
	case "running":
		return item.Running || item.StatusClass == "status-info"
	case "completed":
		return item.StatusClass == "status-success"
	case "attention":
		return item.StatusClass == "status-warning" || item.StatusClass == "status-danger"
	default:
		return true
	}
}

func (s *Server) buildMonitoringJobs(ctx context.Context, currentProject *storage.ProjectSummary, runs []storage.RunSummary) []monitoringJob {
	if len(runs) == 0 {
		return nil
	}

	sortedRuns := append([]storage.RunSummary(nil), runs...)
	sort.SliceStable(sortedRuns, func(i, j int) bool {
		return sortedRuns[i].StartedAt.After(sortedRuns[j].StartedAt)
	})
	if len(sortedRuns) > 12 {
		sortedRuns = sortedRuns[:12]
	}

	jobsOut := make([]monitoringJob, 0, len(sortedRuns))
	defaultExecution := fmt.Sprintf("Startrace Nexus - %s", detectNexusAddress())
	for _, runSummary := range sortedRuns {
		targetSummary := "No scope stored"
		executionTarget := defaultExecution
		summaryParts := []string{
			fmt.Sprintf("%d step(s)", runSummary.JobCount),
			fmt.Sprintf("%d evidence", runSummary.EvidenceCount),
		}

		if details, err := s.repo.GetRun(ctx, runSummary.ID); err == nil {
			targetSummary = summarizeMonitoringScope(details)
			if value := strings.TrimSpace(details.Scope.Labels["execution_satellite_name"]); value != "" {
				executionTarget = value
			}

			failedJobs := 0
			for _, result := range details.JobResults {
				if result.Status == jobs.StatusFailed {
					failedJobs++
				}
			}
			if failedJobs > 0 {
				summaryParts = append(summaryParts, fmt.Sprintf("%d failed step(s)", failedJobs))
			}
			if len(details.Reevaluation) > 0 {
				summaryParts = append(summaryParts, fmt.Sprintf("%d reevaluation hint(s)", len(details.Reevaluation)))
			}
		}

		jobsOut = append(jobsOut, monitoringJob{
			ID:          runSummary.ID,
			URL:         buildProjectPath("/runs/"+runSummary.ID, currentProject),
			Name:        firstNonEmptyWeb(strings.TrimSpace(runSummary.TemplateName), "Radar run"),
			Project:     firstNonEmptyWeb(strings.TrimSpace(runSummary.ProjectName), currentProjectName(currentProject)),
			Target:      targetSummary,
			Execution:   executionTarget,
			Status:      runStatusLabel(runSummary.Status),
			StatusClass: runStatusClass(runSummary.Status),
			StartedAt:   formatMonitoringTimestamp(runSummary.StartedAt),
			FinishedAt:  formatMonitoringTimestamp(runSummary.FinishedAt),
			JobCount:    runSummary.JobCount,
			Evidence:    runSummary.EvidenceCount,
			Running:     strings.EqualFold(strings.TrimSpace(runSummary.Status), "running"),
			Summary:     strings.Join(summaryParts, " | "),
		})
	}
	return jobsOut
}

func (s *Server) monitoringNexus() monitoringSatellite {
	address := detectNexusAddress()
	return monitoringSatellite{
		ID:          "nexus",
		Name:        "Startrace - Nexus",
		Role:        "Local Nexus",
		Status:      "Online",
		StatusClass: "status-success",
		Address:     address,
		Hostname:    inventoryOriginHostname(),
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		Executor:    "Built-in local executor",
		LastSeen:    "Active in this process",
		Summary:     "Default execution target for Radar runs until additional Satelites are registered.",
	}
}

func summarizeMonitoringScope(details storage.RunDetails) string {
	entries := make([]string, 0, len(details.Scope.Targets)+len(details.Scope.CIDRs))
	entries = append(entries, details.Scope.Targets...)
	entries = append(entries, details.Scope.CIDRs...)
	switch len(entries) {
	case 0:
		return "No scope stored"
	case 1:
		return entries[0]
	case 2:
		return entries[0] + ", " + entries[1]
	default:
		return fmt.Sprintf("%s, %s +%d more", entries[0], entries[1], len(entries)-2)
	}
}

func monitoringToolingCounts(checks []preflightCheck) (int, int) {
	ready := 0
	total := 0
	for _, check := range checks {
		if !isMonitoringToolCheck(check.Name) {
			continue
		}
		total++
		if check.Status == "ok" {
			ready++
		}
	}
	return ready, total
}

func monitoringCapabilities(checks []preflightCheck) []string {
	capabilities := make([]string, 0)
	for _, check := range checks {
		if !isMonitoringToolCheck(check.Name) || check.Status != "ok" {
			continue
		}
		capabilities = append(capabilities, check.Name)
	}
	return capabilities
}

func isMonitoringToolCheck(name string) bool {
	switch strings.TrimSpace(name) {
	case "process-privileges", "sqlite-store":
		return false
	default:
		return true
	}
}

func latestRun(runs []storage.RunSummary) *storage.RunSummary {
	return latestRunMatching(runs, func(storage.RunSummary) bool { return true })
}

func latestRunMatching(runs []storage.RunSummary, match func(storage.RunSummary) bool) *storage.RunSummary {
	var latest *storage.RunSummary
	for idx := range runs {
		run := runs[idx]
		if !match(run) {
			continue
		}
		if latest == nil || run.StartedAt.After(latest.StartedAt) {
			copyRun := run
			latest = &copyRun
		}
	}
	return latest
}

func preflightCheckDetail(checks []preflightCheck, name string) string {
	for _, check := range checks {
		if check.Name == name {
			return check.Detail
		}
	}
	return ""
}

func currentProjectName(project *storage.ProjectSummary) string {
	if project == nil {
		return ""
	}
	return strings.TrimSpace(project.Name)
}

func formatMonitoringTimestamp(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Local().Format("2006-01-02 15:04")
}

func formatMonitoringDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	seconds := int(value.Round(time.Second).Seconds())
	days := seconds / 86400
	seconds %= 86400
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60

	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	parts = append(parts, fmt.Sprintf("%dm", minutes))
	return strings.Join(parts, " ")
}

func monitoringHostUptimeSummary() string {
	if runtime.GOOS != "linux" {
		return "Available on Linux hosts"
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "Unavailable"
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return "Unavailable"
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "Unavailable"
	}
	return formatMonitoringDuration(time.Duration(seconds * float64(time.Second)))
}

func monitoringCPUSummary() string {
	base := fmt.Sprintf("%d core(s)", runtime.NumCPU())
	if runtime.GOOS != "linux" {
		return base
	}
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return base
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return base
	}
	return base + " | load " + strings.Join(fields[:3], " ")
}

func monitoringMemorySummary() string {
	if runtime.GOOS != "linux" {
		return "Available on Linux hosts"
	}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "Unavailable"
	}

	var totalKB uint64
	var availableKB uint64
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				totalKB = value
			}
		case "MemAvailable:":
			if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				availableKB = value
			}
		}
	}
	if totalKB == 0 {
		return "Unavailable"
	}
	usedKB := totalKB
	if availableKB < totalKB {
		usedKB = totalKB - availableKB
	}
	usedGiB := float64(usedKB) / (1024 * 1024)
	totalGiB := float64(totalKB) / (1024 * 1024)
	usedPercent := (float64(usedKB) / float64(totalKB)) * 100
	return fmt.Sprintf("%.1f / %.1f GiB used (%.0f%%)", usedGiB, totalGiB, usedPercent)
}

func monitoringFilesystemUsage(path string) string {
	_, detail := monitoringFilesystemMetrics(path)
	return detail
}

func monitoringFilesystemMetrics(path string) (int, string) {
	if runtime.GOOS != "linux" {
		return -1, "Available on Linux hosts"
	}
	target := firstNonEmptyWeb(strings.TrimSpace(path), "/")
	output, err := exec.Command("df", "-P", "-h", target).CombinedOutput()
	if err != nil {
		return -1, "Unavailable"
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return -1, "Unavailable"
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 6 {
		return -1, strings.TrimSpace(lines[len(lines)-1])
	}
	usedPercent := -1
	if strings.HasSuffix(fields[4], "%") {
		if value, err := strconv.Atoi(strings.TrimSuffix(fields[4], "%")); err == nil {
			usedPercent = value
		}
	}
	return usedPercent, fmt.Sprintf("%s used of %s (%s) | %s free", fields[2], fields[1], fields[4], fields[3])
}

func monitoringZeekRuntime() string {
	if runtime.GOOS != "linux" {
		return "Available on Linux hosts"
	}
	if _, err := platform.ResolveExecutable("zeekctl"); err != nil {
		return "zeekctl not installed"
	}
	output, err := exec.Command("zeekctl", "status").CombinedOutput()
	if err != nil {
		return "zeekctl installed"
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "zeekctl installed"
	}
	return strings.TrimSpace(lines[0])
}

func monitoringToolStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok":
		return "Available"
	case "warning":
		return "Optional missing"
	case "error":
		return "Required missing"
	default:
		return firstNonEmptyWeb(strings.TrimSpace(status), "Unknown")
	}
}

func monitoringToolStatusClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok":
		return "status-success"
	case "warning":
		return "status-warning"
	case "error":
		return "status-danger"
	default:
		return "status-neutral"
	}
}

func monitoringToolRuntime(name string, status string) string {
	if strings.ToLower(strings.TrimSpace(status)) != "ok" {
		return "-"
	}
	switch name {
	case "zeekctl":
		return monitoringZeekRuntime()
	default:
		return "Ready"
	}
}

func monitoringToolVersion(name string, status string) string {
	if strings.ToLower(strings.TrimSpace(status)) != "ok" {
		return "-"
	}
	if runtime.GOOS != "linux" {
		return "Resolved on Linux hosts"
	}

	candidates := toolVersionCommands(name)
	for _, candidate := range candidates {
		output, err := exec.Command(candidate[0], candidate[1:]...).CombinedOutput()
		if err != nil {
			continue
		}
		line := firstMeaningfulLine(string(output))
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
	return "available"
}

func toolVersionCommands(name string) [][]string {
	switch name {
	case "naabu":
		return [][]string{{"naabu", "-version"}}
	case "nmap":
		return [][]string{{"nmap", "--version"}}
	case "httpx":
		return [][]string{{"httpx", "-version"}}
	case "zgrab2":
		return [][]string{{"zgrab2", "--version"}}
	case "scamper":
		return [][]string{{"scamper", "-v"}}
	case "arp-scan":
		return [][]string{{"arp-scan", "--version"}}
	case "avahi-browse":
		return [][]string{{"avahi-browse", "--version"}}
	case "testssl.sh":
		return [][]string{{"testssl.sh", "--version"}}
	case "snmpwalk":
		return [][]string{{"snmpwalk", "-V"}, {"snmpwalk", "--version"}}
	case "zeekctl":
		return [][]string{{"zeekctl", "version"}, {"zeekctl", "--version"}}
	default:
		return [][]string{{name, "--version"}, {name, "-version"}, {name, "-v"}}
	}
}

func firstMeaningfulLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		return trimmed
	}
	return ""
}

func countOnlineRegisteredSatellites(satellites []monitoringSatellite) int {
	count := 0
	for _, satellite := range filterRegisteredSatellites(satellites) {
		if satellite.StatusClass == "status-success" {
			count++
		}
	}
	return count
}
