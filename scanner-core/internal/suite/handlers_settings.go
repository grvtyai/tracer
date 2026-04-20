package suite

import (
	"net/http"
	"os"
	"strings"

	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderSettings(w, r)
	case http.MethodPost:
		s.handleSettingsSave(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	satelliteOptions := s.satelliteOptions(ctx)

	data := pageData{
		Title:                 "Settings",
		AppName:               s.options.AppName,
		ActiveNav:             "settings",
		ActiveSection:         "settings-overview",
		BasePath:              s.options.BasePath,
		DBPath:                s.options.DBPath,
		DataDir:               s.options.DataDir,
		HeroNote:              "Global defaults and project-centric startup behavior",
		Notice:                noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:              projects,
		CurrentProject:        currentProject,
		ProjectSwitchPath:     "/settings",
		Project:               currentProject,
		HelpLink:              buildProjectPath("/help", currentProject),
		Settings:              appSettings,
		SatelliteOptions:      satelliteOptions,
		DefaultProjectLabel:   appSettingProjectLabel(projects, appSettings.DefaultProjectID),
		DefaultSatelliteLabel: appSettingSatelliteLabel(satelliteOptions, appSettings.DefaultSatelliteID),
		RepoURL:               "https://github.com/grvtyai/startrace",
		RepoPath:              currentWorkspacePath(),
	}
	s.render(w, "settings.html", data)
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	helpCards := buildHelpCards(currentProjectID(currentProject))
	data := pageData{
		Title:             "Help",
		AppName:           s.options.AppName,
		ActiveNav:         "help",
		ActiveSection:     "help-overview",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/help",
		Project:           currentProject,
		HelpLink:          buildProjectPath("/help", currentProject),
		HelpTopics:        helpCards,
		HelpLatest:        latestHelpCards(helpCards, 3),
		RepoURL:           "https://github.com/grvtyai/startrace",
		RepoPath:          currentWorkspacePath(),
		Settings:          appSettings,
	}
	s.render(w, "help.html", data)
}

func (s *Server) handleHelpTopic(w http.ResponseWriter, r *http.Request) {
	slug := strings.Trim(strings.TrimPrefix(r.URL.Path, "/help/"), "/")
	if slug == "" {
		http.Redirect(w, r, "/help", http.StatusSeeOther)
		return
	}

	topic, ok := findHelpTopic(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:             topic.Title,
		AppName:           s.options.AppName,
		ActiveNav:         "help",
		ActiveSection:     "help-" + topic.Slug,
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/help/" + topic.Slug,
		Project:           currentProject,
		HelpLink:          buildProjectPath("/help", currentProject),
		HelpTopic:         &topic,
		RepoURL:           "https://github.com/grvtyai/startrace",
		RepoPath:          currentWorkspacePath(),
		Settings:          appSettings,
	}
	s.render(w, "help_topic.html", data)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.repo.SaveAppSettings(r.Context(), appSettingsFromForm(r)); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, buildNoticeURL("/settings", strings.TrimSpace(r.FormValue("project")), "settings-saved"), http.StatusSeeOther)
}

func appSettingsFromForm(r *http.Request) storage.AppSettings {
	return storage.AppSettings{
		DefaultProjectID:           strings.TrimSpace(r.FormValue("default_project_id")),
		DefaultSatelliteID:         strings.TrimSpace(r.FormValue("default_satellite_id")),
		DefaultScanTag:             strings.TrimSpace(r.FormValue("default_scan_tag")),
		DefaultPortTemplate:        strings.TrimSpace(r.FormValue("default_port_template")),
		DefaultActiveInterface:     strings.TrimSpace(r.FormValue("default_active_interface")),
		DefaultPassiveInterface:    strings.TrimSpace(r.FormValue("default_passive_interface")),
		DefaultPassiveMode:         strings.TrimSpace(r.FormValue("default_passive_mode")),
		DefaultZeekLogDir:          strings.TrimSpace(r.FormValue("default_zeek_log_dir")),
		DefaultRouteSampling:       isChecked(r.FormValue("default_route_sampling")),
		DefaultServiceScan:         isChecked(r.FormValue("default_service_scan")),
		DefaultAvahi:               isChecked(r.FormValue("default_avahi")),
		DefaultTestSSL:             isChecked(r.FormValue("default_testssl")),
		DefaultSNMP:                isChecked(r.FormValue("default_snmp")),
		DefaultPassiveIngest:       isChecked(r.FormValue("default_passive_ingest")),
		DefaultOSDetection:         isChecked(r.FormValue("default_os_detection")),
		DefaultLayer2:              isChecked(r.FormValue("default_layer2")),
		DefaultLargeRangeStrategy:  isChecked(r.FormValue("default_large_range_strategy")),
		DefaultZeekAutoStart:       isChecked(r.FormValue("default_zeek_auto_start")),
		DefaultContinueOnError:     isChecked(r.FormValue("default_continue_on_error")),
		DefaultRetainPartialResult: isChecked(r.FormValue("default_retain_partial_results")),
		DeploymentMode:             strings.TrimSpace(r.FormValue("deployment_mode")),
	}
}

func appSettingProjectLabel(projects []storage.ProjectSummary, selectedID string) string {
	selectedID = strings.TrimSpace(selectedID)
	if selectedID == "" {
		return "Not set"
	}
	for _, project := range projects {
		if project.ID == selectedID {
			if strings.TrimSpace(project.PublicID) != "" {
				return project.Name + " (" + project.PublicID + ")"
			}
			return project.Name
		}
	}
	return selectedID
}

func appSettingSatelliteLabel(options []satelliteOption, selectedID string) string {
	selectedID = strings.TrimSpace(selectedID)
	if selectedID == "" {
		selectedID = "nexus"
	}
	for _, option := range options {
		if option.ID == selectedID {
			return option.Label
		}
	}
	return selectedID
}

func currentWorkspacePath() string {
	workingDir, err := os.Getwd()
	if err != nil {
		return "Unavailable"
	}
	return workingDir
}

func buildNoticeURL(path string, projectID string, notice string) string {
	query := make([]string, 0, 2)
	if trimmed := strings.TrimSpace(projectID); trimmed != "" {
		query = append(query, "project="+urlQueryEscape(trimmed))
	}
	if trimmed := strings.TrimSpace(notice); trimmed != "" {
		query = append(query, "notice="+urlQueryEscape(trimmed))
	}
	if len(query) == 0 {
		return path
	}
	return path + "?" + strings.Join(query, "&")
}

func noticeMessage(code string) string {
	switch code {
	case "create-first-project":
		return "Create a project before using the rest of the interface."
	case "project-created":
		return "Project created successfully."
	case "project-create-failed":
		return "Project creation failed. Check the submitted paths and name."
	case "scan-started":
		return "Discovery run started successfully."
	case "scan-create-failed":
		return "Discovery run could not be started. Check the submitted scope and settings."
	case "asset-updated":
		return "Asset successfully updated."
	case "reevaluation-scheduled":
		return "Timebased reevaluation saved successfully."
	case "reevaluation-schedule-failed":
		return "Timebased reevaluation could not be saved. Check the selected time and try again."
	case "run-acknowledged":
		return "Run warnings were accepted and the run now appears as completed."
	case "settings-saved":
		return "Settings updated successfully."
	case "satellite-registered":
		return "Satelite registered successfully."
	case "satellite-register-failed":
		return "Satelite registration failed. Check the submitted values and try again."
	case "satellite-refreshed":
		return "Satelite status refreshed."
	default:
		return ""
	}
}

func filepathJoin(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	return strings.Join(filtered, string(os.PathSeparator))
}

func urlQueryEscape(value string) string {
	replacer := strings.NewReplacer(
		"%", "%25",
		" ", "%20",
		"\n", "%0A",
		"+", "%2B",
		"&", "%26",
		"=", "%3D",
		"?", "%3F",
		"#", "%23",
	)
	return replacer.Replace(value)
}
