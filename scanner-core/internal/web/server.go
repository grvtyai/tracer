package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Options struct {
	DBPath   string
	DataDir  string
	AppName  string
	BasePath string
}

type Server struct {
	repo    *storage.SQLiteRepository
	mux     *http.ServeMux
	options Options
}

type pageData struct {
	Title              string
	AppName            string
	ActiveNav          string
	BasePath           string
	DBPath             string
	DataDir            string
	BodyClass          string
	HeroNote           string
	Notice             string
	Project            *storage.ProjectSummary
	Projects           []storage.ProjectSummary
	CurrentProject     *storage.ProjectSummary
	ProjectSwitchPath  string
	ProjectForm        projectFormData
	Settings           storage.AppSettings
	PreflightChecks    []preflightCheck
	PreflightHealthy   bool
	PreflightState     string
	ScanForm           scanFormData
	RecentRuns         []storage.RunSummary
	RecentRunItems     []runListItem
	Runs               []storage.RunSummary
	RunItems           []runListItem
	Run                *storage.RunDetails
	RunReevaluateURL   string
	Assets             []storage.AssetSummary
	Asset              *storage.AssetDetails
	AssetReevaluateURL string
	AssetGroups        []assetGroup
	Hosts              []hostSummary
	RunStatus          statusInfo
	ScheduledScans     []storage.ScheduledScan
	WarningDetails     []warningDetail
	HelpLink           string
	Stats              dashboardStats
	DeviceTypeStats    []labelCount
	ConnectionStats    []labelCount
	StatusStats        []labelCount
	DiffAPI            string
}

type dashboardStats struct {
	RunCount      int
	AssetCount    int
	HostCount     int
	EvidenceCount int
	ReevalCount   int
}

type hostSummary struct {
	AssetID         string
	Target          string
	Verdict         string
	Confidence      string
	OpenPorts       []int
	EvidenceCount   int
	BlockingReasons []string
	LastObserved    time.Time
	Reevaluate      bool
}

type assetGroup struct {
	Name   string
	Assets []storage.AssetSummary
}

type labelCount struct {
	Label string
	Count int
}

type statusInfo struct {
	Label   string
	Class   string
	Title   string
	Message string
}

type warningDetail struct {
	Plugin string
	Host   string
	JobID  string
	Error  string
	Kind   string
}

type runListItem struct {
	Run         storage.RunSummary `json:"run"`
	HostCount   int                `json:"host_count"`
	SubnetCount int                `json:"subnet_count"`
	StatusLabel string             `json:"status_label"`
	StatusClass string             `json:"status_class"`
	Clickable   bool               `json:"clickable"`
}

type projectFormData struct {
	Name            string
	Notes           string
	StoragePath     string
	TargetDBPath    string
	OwnerUsername   string
	PublicIDPreview string
	TargetDBExists  bool
}

type optionsResponse struct {
	AppName      string                   `json:"app_name"`
	DBPath       string                   `json:"db_path"`
	DataDir      string                   `json:"data_dir"`
	PassiveModes []string                 `json:"passive_modes"`
	Defaults     options.EffectiveOptions `json:"defaults"`
}

func NewServer(repo *storage.SQLiteRepository, opts Options) (*Server, error) {
	if repo == nil {
		return nil, fmt.Errorf("web server requires a repository")
	}
	if strings.TrimSpace(opts.AppName) == "" {
		opts.AppName = "Startrace"
	}

	server := &Server{
		repo:    repo,
		mux:     http.NewServeMux(),
		options: opts,
	}
	server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	fileServer := http.FileServer(http.FS(assets))
	s.mux.Handle("/static/", http.StripPrefix("/", fileServer))

	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/projects", s.handleProjectsIndex)
	s.mux.HandleFunc("/projects/new", s.handleProjectNew)
	s.mux.HandleFunc("/projects/", s.handleProject)
	s.mux.HandleFunc("/runs", s.handleRuns)
	s.mux.HandleFunc("/runs/", s.handleRun)
	s.mux.HandleFunc("/scans/new", s.handleScanNew)
	s.mux.HandleFunc("/assets", s.handleAssets)
	s.mux.HandleFunc("/assets/", s.handleAsset)
	s.mux.HandleFunc("/analytics", s.handleAnalytics)
	s.mux.HandleFunc("/settings", s.handleSettings)
	s.mux.HandleFunc("/help", s.handleHelp)

	s.mux.HandleFunc("/api/health", s.handleHealthAPI)
	s.mux.HandleFunc("/api/options", s.handleOptionsAPI)
	s.mux.HandleFunc("/api/preflight", s.handlePreflightAPI)
	s.mux.HandleFunc("/api/settings", s.handleSettingsAPI)
	s.mux.HandleFunc("/api/projects", s.handleProjectsAPI)
	s.mux.HandleFunc("/api/projects/", s.handleProjectRunsAPI)
	s.mux.HandleFunc("/api/assets", s.handleAssetsAPI)
	s.mux.HandleFunc("/api/assets/", s.handleAssetAPI)
	s.mux.HandleFunc("/api/runs/", s.handleRunAPI)
	s.mux.HandleFunc("/api/diff", s.handleDiffAPI)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(projects) == 0 {
		http.Redirect(w, r, "/projects/new?notice=create-first-project", http.StatusSeeOther)
		return
	}

	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	projectAssets, err := s.repo.ListAssets(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:             "Dashboard",
		AppName:           s.options.AppName,
		ActiveNav:         "dashboard",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Project-first network inventory and scan history",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/",
		Project:           currentProject,
		RecentRuns:        takeRuns(runs, 8),
		RecentRunItems:    buildRunListItems(ctx, s.repo, takeRuns(runs, 8)),
		Assets:            takeAssets(projectAssets, 8),
		HelpLink:          "/help",
		Stats: dashboardStats{
			RunCount:      len(runs),
			AssetCount:    len(projectAssets),
			HostCount:     len(projectAssets),
			EvidenceCount: countEvidence(runs),
			ReevalCount:   countReevaluationAcrossRuns(ctx, s.repo, runs),
		},
		Settings: appSettings,
	}
	s.render(w, "dashboard.html", data)
}

func (s *Server) handleProjectsIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/projects" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	projects, currentProject, _, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject != nil {
		http.Redirect(w, r, "/?project="+currentProject.ID, http.StatusSeeOther)
		return
	}
	if len(projects) == 0 {
		http.Redirect(w, r, "/projects/new?notice=create-first-project", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?project="+projects[0].ID, http.StatusSeeOther)
}

func (s *Server) handleProjectNew(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderProjectNew(w, r)
	case http.MethodPost:
		s.handleProjectCreate(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderProjectNew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, "")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	form := projectFormData{
		Name:            strings.TrimSpace(r.URL.Query().Get("name")),
		Notes:           strings.TrimSpace(r.URL.Query().Get("notes")),
		OwnerUsername:   currentOperatorFromEnv(),
		PublicIDPreview: previewPublicID(),
	}
	if form.Name != "" {
		form.StoragePath = storagePathSuggestion(s.optionsDataDir(), form.Name)
		form.TargetDBPath = targetDBPathSuggestion(form.StoragePath)
		form.TargetDBExists = pathExists(form.TargetDBPath)
	}

	data := pageData{
		Title:             "Create Project",
		AppName:           s.options.AppName,
		ActiveNav:         "dashboard",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Every operator flow starts inside a project",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/",
		ProjectForm:       form,
		Settings:          appSettings,
		PreflightChecks:   collectPreflightChecks(s.options.DBPath),
		PreflightHealthy:  preflightHealthy(collectPreflightChecks(s.options.DBPath)),
	}
	s.render(w, "project_new.html", data)
}

func (s *Server) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	project, err := s.repo.CreateProject(r.Context(), storage.ProjectCreateInput{
		Name:          r.FormValue("name"),
		Notes:         r.FormValue("notes"),
		StoragePath:   r.FormValue("storage_path"),
		TargetDBPath:  r.FormValue("target_db_path"),
		OwnerUsername: r.FormValue("owner_username"),
	})
	if err != nil {
		http.Redirect(w, r, "/projects/new?notice=project-create-failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?project="+project.ID+"&notice=project-created", http.StatusSeeOther)
}

func (s *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	projectID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/projects/"), "/")
	if projectID == "" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/?project="+projectID, http.StatusSeeOther)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/runs" {
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

	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:             "Runs",
		AppName:           s.options.AppName,
		ActiveNav:         "runs",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Chronological scan history for the active project",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/runs",
		Project:           currentProject,
		Runs:              runs,
		RunItems:          buildRunListItems(ctx, s.repo, runs),
		DiffAPI:           "/api/diff",
		HelpLink:          "/help#run-status",
		Settings:          appSettings,
	}
	s.render(w, "runs.html", data)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/runs/"), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	runID := parts[0]
	if len(parts) == 2 && parts[1] == "schedule-reevaluation" && r.Method == http.MethodPost {
		s.handleScheduleReevaluation(w, r, runID)
		return
	}
	if len(parts) == 2 && parts[1] == "acknowledge" && r.Method == http.MethodPost {
		s.handleRunAcknowledge(w, r, runID)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}

	run, err := s.repo.GetRun(r.Context(), runID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	project, err := s.repo.GetProject(r.Context(), run.Run.ProjectID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	projects, _, appSettings, err := s.loadShellContext(r.Context(), project.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	scheduledScans, err := s.repo.ListScheduledScansByRun(r.Context(), runID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	projectAssets := mustListAssets(r.Context(), s.repo, project.ID)

	data := pageData{
		Title:             run.Run.TemplateName,
		AppName:           s.options.AppName,
		ActiveNav:         "runs",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		Projects:          projects,
		CurrentProject:    &project,
		ProjectSwitchPath: "/runs",
		Project:           &project,
		Run:               &run,
		Hosts:             buildHostSummaries(run, projectAssets),
		RunStatus:         describeRunStatus(run),
		ScheduledScans:    scheduledScans,
		RunReevaluateURL:  buildReevaluationURL(project.ID, "Reevaluate "+run.Run.TemplateName, runScopeInput(run), "30m"),
		WarningDetails:    buildWarningDetails(run),
		HelpLink:          "/help#run-status-needs-attention",
		Settings:          appSettings,
	}
	s.render(w, "run.html", data)
}

func (s *Server) handleScheduleReevaluation(w http.ResponseWriter, r *http.Request, runID string) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	run, err := s.repo.GetRun(r.Context(), runID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}

	executeAtRaw := strings.TrimSpace(r.FormValue("execute_at"))
	if executeAtRaw == "" {
		http.Redirect(w, r, "/runs/"+runID+"?notice=reevaluation-schedule-failed", http.StatusSeeOther)
		return
	}

	executeAt, err := time.Parse("2006-01-02T15:04", executeAtRaw)
	if err != nil {
		http.Redirect(w, r, "/runs/"+runID+"?notice=reevaluation-schedule-failed", http.StatusSeeOther)
		return
	}

	scopeInput := strings.TrimSpace(strings.Join(run.Scope.Targets, "\n"))
	if len(run.Scope.CIDRs) > 0 {
		cidrs := strings.TrimSpace(strings.Join(run.Scope.CIDRs, "\n"))
		if scopeInput == "" {
			scopeInput = cidrs
		} else {
			scopeInput += "\n" + cidrs
		}
	}

	_, err = s.repo.CreateScheduledScan(r.Context(), storage.ScheduledScanInput{
		ProjectID:   run.Run.ProjectID,
		SourceRunID: run.Run.ID,
		Name:        "Timebased Reevaluation " + run.Run.ID,
		Kind:        "timebased-reevaluation",
		ScopeInput:  scopeInput,
		ExecuteAt:   executeAt,
	})
	if err != nil {
		http.Redirect(w, r, "/runs/"+runID+"?notice=reevaluation-schedule-failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/runs/"+runID+"?notice=reevaluation-scheduled", http.StatusSeeOther)
}

func (s *Server) handleRunAcknowledge(w http.ResponseWriter, r *http.Request, runID string) {
	if err := s.repo.AcknowledgeRunWarnings(r.Context(), runID, "accepted from web ui"); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, "/runs/"+runID+"?notice=run-acknowledged", http.StatusSeeOther)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/assets" {
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

	projectAssets, err := s.repo.ListAssets(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:             "Assets",
		AppName:           s.options.AppName,
		ActiveNav:         "assets",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Persistent inventory with safe manual overrides",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/assets",
		Project:           currentProject,
		Assets:            projectAssets,
		AssetGroups:       groupAssets(projectAssets),
		Settings:          appSettings,
	}
	s.render(w, "assets.html", data)
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/assets/"), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	assetID := parts[0]
	if len(parts) == 2 && parts[1] == "edit" && r.Method == http.MethodPost {
		s.handleAssetEdit(w, r, assetID)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}

	asset, err := s.repo.GetAsset(r.Context(), assetID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	project, err := s.repo.GetProject(r.Context(), asset.Asset.ProjectID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	projects, _, appSettings, err := s.loadShellContext(r.Context(), project.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:              "Asset " + asset.Asset.DisplayName,
		AppName:            s.options.AppName,
		ActiveNav:          "assets",
		BasePath:           s.options.BasePath,
		DBPath:             s.options.DBPath,
		DataDir:            s.options.DataDir,
		Projects:           projects,
		CurrentProject:     &project,
		ProjectSwitchPath:  "/assets",
		Project:            &project,
		Asset:              &asset,
		AssetReevaluateURL: buildReevaluationURL(project.ID, "Reevaluate "+asset.Asset.DisplayName, asset.Asset.PrimaryTarget, "30m"),
		HelpLink:           "/help#asset-overrides",
		Notice:             noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Settings:           appSettings,
	}
	s.render(w, "asset.html", data)
}

func (s *Server) handleAssetEdit(w http.ResponseWriter, r *http.Request, assetID string) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	asset, err := s.repo.UpdateAsset(r.Context(), assetID, storage.AssetUpdateInput{
		DisplayName:    r.FormValue("display_name"),
		DeviceType:     r.FormValue("manual_device_type"),
		ConnectionType: r.FormValue("manual_connection_type"),
		Reevaluate:     isChecked(r.FormValue("manual_reevaluate")),
		Tags:           splitTags(r.FormValue("tags")),
		Notes:          r.FormValue("manual_notes"),
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	http.Redirect(w, r, "/assets/"+asset.Asset.ID+"?notice=asset-updated", http.StatusSeeOther)
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/analytics" {
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

	runs, err := s.repo.ListRuns(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	projectAssets, err := s.repo.ListAssets(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:             "Analytics",
		AppName:           s.options.AppName,
		ActiveNav:         "analytics",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Grouped views that become the basis for later dashboards",
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/analytics",
		Project:           currentProject,
		Stats: dashboardStats{
			RunCount:      len(runs),
			AssetCount:    len(projectAssets),
			HostCount:     len(projectAssets),
			EvidenceCount: countEvidence(runs),
			ReevalCount:   countReevaluationAcrossRuns(ctx, s.repo, runs),
		},
		DeviceTypeStats: countAssetProperty(projectAssets, func(asset storage.AssetSummary) string { return asset.EffectiveDeviceType }),
		ConnectionStats: countAssetProperty(projectAssets, func(asset storage.AssetSummary) string { return asset.EffectiveConnectionType }),
		StatusStats:     countRunStatuses(runs),
		HelpLink:        "/help#analytics",
		Settings:        appSettings,
	}
	s.render(w, "analytics.html", data)
}

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

	data := pageData{
		Title:             "Settings",
		AppName:           s.options.AppName,
		ActiveNav:         "settings",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Global defaults and project-centric startup behavior",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/settings",
		Project:           currentProject,
		HelpLink:          "/help",
		Settings:          appSettings,
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

	data := pageData{
		Title:             "Help",
		AppName:           s.options.AppName,
		ActiveNav:         "help",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Operator guide for troubleshooting, reevaluation and host workflows",
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/help",
		Project:           currentProject,
		HelpLink:          "/help",
		Settings:          appSettings,
	}
	s.render(w, "help.html", data)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.repo.SetDefaultProject(r.Context(), r.FormValue("default_project_id")); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, "/settings?notice=settings-saved", http.StatusSeeOther)
}

func (s *Server) handleHealthAPI(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"app_name":  s.options.AppName,
		"timestamp": time.Now().UTC(),
	})
}

func (s *Server) handleOptionsAPI(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, optionsResponse{
		AppName:      s.options.AppName,
		DBPath:       s.options.DBPath,
		DataDir:      s.options.DataDir,
		PassiveModes: []string{"off", "auto", "always"},
		Defaults:     options.DefaultEffectiveOptions(),
	})
}

func (s *Server) handleSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.repo.GetAppSettings(r.Context())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, settings)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.repo.SetDefaultProject(r.Context(), r.FormValue("default_project_id")); err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		settings, err := s.repo.GetAppSettings(r.Context())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, settings)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProjectsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		projects, err := s.repo.ListProjects(r.Context())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.writeError(w, http.StatusBadRequest, err)
			return
		}
		project, err := s.repo.CreateProject(r.Context(), storage.ProjectCreateInput{
			Name:          r.FormValue("name"),
			Notes:         r.FormValue("notes"),
			StoragePath:   r.FormValue("storage_path"),
			TargetDBPath:  r.FormValue("target_db_path"),
			OwnerUsername: r.FormValue("owner_username"),
		})
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err)
			return
		}
		s.writeJSON(w, http.StatusCreated, project)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAssetsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/assets" {
		http.NotFound(w, r)
		return
	}

	projectRef := strings.TrimSpace(r.URL.Query().Get("project"))
	if projectRef == "" {
		_, currentProject, _, err := s.loadShellContext(r.Context(), "")
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		if currentProject != nil {
			projectRef = currentProject.ID
		}
	}

	projectAssets, err := s.repo.ListAssets(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"project": projectRef,
		"assets":  projectAssets,
	})
}

func (s *Server) handleAssetAPI(w http.ResponseWriter, r *http.Request) {
	assetID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/assets/"), "/")
	if assetID == "" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		asset, err := s.repo.GetAsset(r.Context(), assetID)
		if err != nil {
			s.writeError(w, http.StatusNotFound, err)
			return
		}
		s.writeJSON(w, http.StatusOK, asset)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.writeError(w, http.StatusBadRequest, err)
			return
		}
		asset, err := s.repo.UpdateAsset(r.Context(), assetID, storage.AssetUpdateInput{
			DisplayName:    r.FormValue("display_name"),
			DeviceType:     r.FormValue("manual_device_type"),
			ConnectionType: r.FormValue("manual_connection_type"),
			Reevaluate:     isChecked(r.FormValue("manual_reevaluate")),
			Tags:           splitTags(r.FormValue("tags")),
			Notes:          r.FormValue("manual_notes"),
		})
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, asset)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProjectRunsAPI(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/projects/"), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "runs" {
		http.NotFound(w, r)
		return
	}

	projectID := parts[0]
	runs, err := s.repo.ListRuns(r.Context(), projectID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	runItems := buildRunListItems(r.Context(), s.repo, runs)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"project_id": projectID,
		"runs":       runs,
		"run_items":  runItems,
	})
}

func (s *Server) handleRunAPI(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/runs/"), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	runID := parts[0]
	run, err := s.repo.GetRun(r.Context(), runID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}

	if len(parts) == 1 {
		s.writeJSON(w, http.StatusOK, run)
		return
	}

	switch parts[1] {
	case "evidence":
		s.writeJSON(w, http.StatusOK, map[string]any{"run_id": runID, "evidence": run.Evidence})
	case "blocking":
		s.writeJSON(w, http.StatusOK, map[string]any{"run_id": runID, "blocking": run.Blocking})
	case "reevaluation":
		s.writeJSON(w, http.StatusOK, map[string]any{"run_id": runID, "reevaluation": run.Reevaluation})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleDiffAPI(w http.ResponseWriter, r *http.Request) {
	baselineRunID := strings.TrimSpace(r.URL.Query().Get("baseline_run"))
	candidateRunID := strings.TrimSpace(r.URL.Query().Get("candidate_run"))
	if baselineRunID == "" || candidateRunID == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "baseline_run and candidate_run are required",
		})
		return
	}

	diff, err := s.repo.DiffRuns(r.Context(), baselineRunID, candidateRunID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	s.writeJSON(w, http.StatusOK, diff)
}

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	if data.PreflightChecks == nil {
		data.PreflightChecks = collectPreflightChecks(s.options.DBPath)
	}
	data.PreflightHealthy = preflightHealthy(data.PreflightChecks)
	data.PreflightState = preflightState(data.PreflightChecks)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates, err := template.ParseFS(assets, "templates/base.html", "templates/"+name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func (s *Server) writeError(w http.ResponseWriter, status int, err error) {
	s.writeJSON(w, status, map[string]any{"error": err.Error()})
}

func (s *Server) loadShellContext(ctx context.Context, requestedProject string) ([]storage.ProjectSummary, *storage.ProjectSummary, storage.AppSettings, error) {
	projects, err := s.repo.ListProjects(ctx)
	if err != nil {
		return nil, nil, storage.AppSettings{}, err
	}
	settings, err := s.repo.GetAppSettings(ctx)
	if err != nil {
		return nil, nil, storage.AppSettings{}, err
	}
	if len(projects) == 0 {
		return projects, nil, settings, nil
	}

	current := selectProject(projects, requestedProject, settings.DefaultProjectID)
	return projects, current, settings, nil
}

func selectProject(projects []storage.ProjectSummary, requested string, defaultProjectID string) *storage.ProjectSummary {
	if selected := findProjectInList(projects, requested); selected != nil {
		return selected
	}
	if selected := findProjectInList(projects, defaultProjectID); selected != nil {
		return selected
	}
	return &projects[0]
}

func findProjectInList(projects []storage.ProjectSummary, ref string) *storage.ProjectSummary {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	for i := range projects {
		project := &projects[i]
		if project.ID == ref || strings.EqualFold(project.Name, ref) || strings.EqualFold(project.PublicID, ref) {
			return project
		}
	}
	return nil
}

func buildHostSummaries(run storage.RunDetails, projectAssets []storage.AssetSummary) []hostSummary {
	perTarget := make(map[string]*hostSummary)
	openPorts := make(map[string]map[int]struct{})
	assetByTarget := make(map[string]storage.AssetSummary, len(projectAssets))
	for _, asset := range projectAssets {
		target := strings.TrimSpace(asset.PrimaryTarget)
		if target == "" {
			continue
		}
		assetByTarget[target] = asset
	}

	for _, record := range run.Evidence {
		target := strings.TrimSpace(record.Target)
		if target == "" {
			continue
		}
		entry, ok := perTarget[target]
		if !ok {
			entry = &hostSummary{Target: target}
			if asset, exists := assetByTarget[target]; exists {
				entry.AssetID = asset.ID
				entry.Reevaluate = asset.ManualReevaluate
			}
			perTarget[target] = entry
		}
		entry.EvidenceCount++
		if !record.ObservedAt.IsZero() && record.ObservedAt.After(entry.LastObserved) {
			entry.LastObserved = record.ObservedAt
		}
		switch record.Kind {
		case "open_port", "service_fingerprint", "http_probe", "l7_grab":
			if record.Port > 0 {
				if _, ok := openPorts[target]; !ok {
					openPorts[target] = make(map[int]struct{})
				}
				openPorts[target][record.Port] = struct{}{}
			}
		}
	}

	for _, assessment := range run.Blocking {
		target := strings.TrimSpace(assessment.Target)
		if target == "" || assessment.Port != 0 {
			continue
		}
		entry, ok := perTarget[target]
		if !ok {
			entry = &hostSummary{Target: target}
			if asset, exists := assetByTarget[target]; exists {
				entry.AssetID = asset.ID
				entry.Reevaluate = asset.ManualReevaluate
			}
			perTarget[target] = entry
		}
		entry.Verdict = string(assessment.Verdict)
		entry.Confidence = string(assessment.Confidence)
		entry.BlockingReasons = append([]string{}, assessment.Reasons...)
	}

	hosts := make([]hostSummary, 0, len(perTarget))
	for target, entry := range perTarget {
		if ports, ok := openPorts[target]; ok {
			entry.OpenPorts = make([]int, 0, len(ports))
			for port := range ports {
				entry.OpenPorts = append(entry.OpenPorts, port)
			}
			sort.Ints(entry.OpenPorts)
		}
		if entry.Verdict == "" {
			if len(entry.OpenPorts) > 0 {
				entry.Verdict = "reachable"
				entry.Confidence = "confirmed"
			} else {
				entry.Verdict = "observed"
			}
		}
		hosts = append(hosts, *entry)
	}

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Target < hosts[j].Target
	})
	return hosts
}

func buildRunListItems(ctx context.Context, repo *storage.SQLiteRepository, runs []storage.RunSummary) []runListItem {
	items := make([]runListItem, 0, len(runs))
	for _, run := range runs {
		item := runListItem{
			Run:         run,
			StatusLabel: runStatusLabel(run.Status),
			StatusClass: runStatusClass(run.Status),
			Clickable:   strings.TrimSpace(strings.ToLower(run.Status)) != "running",
		}
		details, err := repo.GetRun(ctx, run.ID)
		if err == nil {
			item.HostCount = countRunHosts(details)
			item.SubnetCount = len(details.Scope.CIDRs)
		}
		items = append(items, item)
	}
	return items
}

func buildWarningDetails(run storage.RunDetails) []warningDetail {
	details := make([]warningDetail, 0)
	for _, result := range run.JobResults {
		if result.Status != "failed" {
			continue
		}
		host := "-"
		if len(result.Targets) > 0 {
			host = strings.Join(result.Targets, ", ")
		}
		details = append(details, warningDetail{
			Plugin: firstNonEmptyWeb(result.Plugin, "unknown"),
			Host:   host,
			JobID:  result.JobID,
			Error:  firstNonEmptyWeb(result.Error, "No detailed error text was stored."),
			Kind:   string(result.Kind),
		})
	}
	return details
}

func countEvidence(runs []storage.RunSummary) int {
	total := 0
	for _, run := range runs {
		total += run.EvidenceCount
	}
	return total
}

func countReevaluationAcrossRuns(ctx context.Context, repo *storage.SQLiteRepository, runs []storage.RunSummary) int {
	total := 0
	for _, run := range runs {
		details, err := repo.GetRun(ctx, run.ID)
		if err != nil {
			continue
		}
		total += len(details.Reevaluation)
	}
	return total
}

func takeRuns(runs []storage.RunSummary, n int) []storage.RunSummary {
	if len(runs) <= n {
		return runs
	}
	return runs[:n]
}

func takeAssets(projectAssets []storage.AssetSummary, n int) []storage.AssetSummary {
	if len(projectAssets) <= n {
		return projectAssets
	}
	return projectAssets[:n]
}

func groupAssets(projectAssets []storage.AssetSummary) []assetGroup {
	grouped := make(map[string][]storage.AssetSummary)
	for _, asset := range projectAssets {
		key := asset.EffectiveDeviceType
		if strings.TrimSpace(key) == "" {
			key = "unknown"
		}
		grouped[key] = append(grouped[key], asset)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	groups := make([]assetGroup, 0, len(keys))
	for _, key := range keys {
		group := assetGroup{Name: key, Assets: grouped[key]}
		sort.Slice(group.Assets, func(i, j int) bool {
			return group.Assets[i].DisplayName < group.Assets[j].DisplayName
		})
		groups = append(groups, group)
	}
	return groups
}

func countAssetProperty(projectAssets []storage.AssetSummary, selector func(storage.AssetSummary) string) []labelCount {
	counts := make(map[string]int)
	for _, asset := range projectAssets {
		label := strings.TrimSpace(selector(asset))
		if label == "" {
			label = "unknown"
		}
		counts[label]++
	}
	return mapToLabelCounts(counts)
}

func countRunStatuses(runs []storage.RunSummary) []labelCount {
	counts := make(map[string]int)
	for _, run := range runs {
		label := strings.TrimSpace(run.Status)
		if label == "" {
			label = "unknown"
		}
		label = runStatusLabel(label)
		counts[label]++
	}
	return mapToLabelCounts(counts)
}

func countRunHosts(run storage.RunDetails) int {
	targets := make(map[string]struct{})
	for _, record := range run.Evidence {
		if target := strings.TrimSpace(record.Target); target != "" {
			targets[target] = struct{}{}
		}
	}
	for _, assessment := range run.Blocking {
		if target := strings.TrimSpace(assessment.Target); target != "" {
			targets[target] = struct{}{}
		}
	}
	return len(targets)
}

func runStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return "Running"
	case "completed":
		return "Completed"
	case "partial":
		return "Needs attention"
	case "failed":
		return "Failed"
	default:
		return firstNonEmptyWeb(strings.TrimSpace(status), "Unknown")
	}
}

func runStatusClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed":
		return "status-success"
	case "partial":
		return "status-warning"
	case "running":
		return "status-info"
	case "failed":
		return "status-danger"
	default:
		return "status-neutral"
	}
}

func describeRunStatus(run storage.RunDetails) statusInfo {
	info := statusInfo{
		Label: runStatusLabel(run.Run.Status),
		Class: runStatusClass(run.Run.Status),
	}

	switch strings.ToLower(strings.TrimSpace(run.Run.Status)) {
	case "completed":
		info.Title = "Run completed successfully"
		info.Message = "All planned jobs finished without a recorded failure. The stored evidence is ready to review."
	case "running":
		info.Title = "Run is still in progress"
		info.Message = "This run is still collecting results. Open it again after completion to inspect full details."
	case "partial":
		info.Title = "Run needs attention"
		info.Message = buildNeedsAttentionMessage(run)
	case "failed":
		info.Title = "Run failed"
		info.Message = "The run stopped before completion. Review missing tools, plugin errors or the selected scan configuration and then launch it again."
	default:
		info.Title = "Run status"
		info.Message = "This run finished with a custom state. Inspect the stored jobs and evidence for details."
	}

	return info
}

func buildNeedsAttentionMessage(run storage.RunDetails) string {
	failedJobs := 0
	for _, result := range run.JobResults {
		if result.Status == "failed" {
			failedJobs++
		}
	}
	switch {
	case failedJobs > 0 && len(run.Reevaluation) > 0:
		return fmt.Sprintf("%d job(s) failed and %d host(s) were marked for reevaluation. Fix the failing tool or scan step, then rerun or reevaluate the affected hosts to move future runs to Completed.", failedJobs, len(run.Reevaluation))
	case failedJobs > 0:
		return fmt.Sprintf("%d job(s) failed during this run. Check plugin availability, network reachability or scan settings, then rerun to reach Completed.", failedJobs)
	case len(run.Reevaluation) > 0:
		return fmt.Sprintf("%d host(s) were marked as uncertain and should be checked again. Use Reevaluate all Hosts or a host-specific reevaluation once you are ready.", len(run.Reevaluation))
	default:
		return "This run kept partial results but at least one stage did not finish cleanly. Review the recorded jobs and then rerun the scan to reach Completed."
	}
}

func mustListAssets(ctx context.Context, repo *storage.SQLiteRepository, projectID string) []storage.AssetSummary {
	assets, err := repo.ListAssets(ctx, projectID)
	if err != nil {
		return nil
	}
	return assets
}

func runScopeInput(run storage.RunDetails) string {
	parts := make([]string, 0, len(run.Scope.Targets)+len(run.Scope.CIDRs))
	parts = append(parts, run.Scope.Targets...)
	parts = append(parts, run.Scope.CIDRs...)
	return strings.Join(parts, "\n")
}

func buildReevaluationURL(projectID string, scanName string, scope string, reevaluateAfter string) string {
	values := make([]string, 0, 4)
	if trimmed := strings.TrimSpace(projectID); trimmed != "" {
		values = append(values, "project="+urlQueryEscape(trimmed))
	}
	if trimmed := strings.TrimSpace(scanName); trimmed != "" {
		values = append(values, "scan_name="+urlQueryEscape(trimmed))
	}
	if trimmed := strings.TrimSpace(scope); trimmed != "" {
		values = append(values, "scope="+urlQueryEscape(trimmed))
	}
	if trimmed := strings.TrimSpace(reevaluateAfter); trimmed != "" {
		values = append(values, "reevaluate_after="+urlQueryEscape(trimmed))
	}
	if len(values) == 0 {
		return "/scans/new"
	}
	return "/scans/new?" + strings.Join(values, "&")
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

func mapToLabelCounts(values map[string]int) []labelCount {
	labels := make([]string, 0, len(values))
	for label := range values {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	out := make([]labelCount, 0, len(labels))
	for _, label := range labels {
		out = append(out, labelCount{Label: label, Count: values[label]})
	}
	return out
}

func splitTags(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	})
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	return tags
}

func previewPublicID() string {
	return "PRJ-XXXXXXX"
}

func storagePathSuggestion(dataDir string, name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "project"
	}
	return filepathJoin(dataDir, "projects", slug)
}

func targetDBPathSuggestion(storagePath string) string {
	if strings.TrimSpace(storagePath) == "" {
		return ""
	}
	return filepathJoin(storagePath, "project.sqlite")
}

func pathExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func currentOperatorFromEnv() string {
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" {
		return sudoUser
	}
	if userValue := strings.TrimSpace(os.Getenv("USER")); userValue != "" {
		return userValue
	}
	return ""
}

func noticeMessage(code string) string {
	switch code {
	case "create-first-project":
		return "Create a project before using the rest of the interface."
	case "project-created":
		return "Project created successfully."
	case "project-create-failed":
		return "Project creation failed. Check the submitted paths and name."
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

func (s *Server) optionsDataDir() string {
	if strings.TrimSpace(s.options.DataDir) != "" {
		return s.options.DataDir
	}
	return storage.DefaultDataDir()
}
