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
	Title             string
	AppName           string
	ActiveNav         string
	BasePath          string
	DBPath            string
	DataDir           string
	BodyClass         string
	HeroNote          string
	Notice            string
	Project           *storage.ProjectSummary
	Projects          []storage.ProjectSummary
	CurrentProject    *storage.ProjectSummary
	ProjectSwitchPath string
	ProjectForm       projectFormData
	Settings          storage.AppSettings
	PreflightChecks   []preflightCheck
	PreflightHealthy  bool
	ScanForm          scanFormData
	RecentRuns        []storage.RunSummary
	Runs              []storage.RunSummary
	Run               *storage.RunDetails
	Assets            []storage.AssetSummary
	Asset             *storage.AssetDetails
	AssetGroups       []assetGroup
	Hosts             []hostSummary
	Stats             dashboardStats
	DeviceTypeStats   []labelCount
	ConnectionStats   []labelCount
	StatusStats       []labelCount
	DiffAPI           string
}

type dashboardStats struct {
	RunCount      int
	AssetCount    int
	HostCount     int
	EvidenceCount int
	ReevalCount   int
}

type hostSummary struct {
	Target          string
	Verdict         string
	Confidence      string
	OpenPorts       []int
	EvidenceCount   int
	BlockingReasons []string
	LastObserved    time.Time
}

type assetGroup struct {
	Name   string
	Assets []storage.AssetSummary
}

type labelCount struct {
	Label string
	Count int
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
	preflightChecks := collectPreflightChecks(s.options.DBPath)
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
		Assets:            takeAssets(projectAssets, 8),
		PreflightChecks:   preflightChecks,
		PreflightHealthy:  preflightHealthy(preflightChecks),
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
		DiffAPI:           "/api/diff",
		Settings:          appSettings,
	}
	s.render(w, "runs.html", data)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	runID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/runs/"), "/")
	if runID == "" {
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

	data := pageData{
		Title:             "Run " + run.Run.ID,
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
		Hosts:             buildHostSummaries(run),
		Settings:          appSettings,
	}
	s.render(w, "run.html", data)
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
		Title:             "Asset " + asset.Asset.DisplayName,
		AppName:           s.options.AppName,
		ActiveNav:         "assets",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		Projects:          projects,
		CurrentProject:    &project,
		ProjectSwitchPath: "/assets",
		Project:           &project,
		Asset:             &asset,
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Settings:          appSettings,
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
		Settings:          appSettings,
	}
	s.render(w, "settings.html", data)
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
	s.writeJSON(w, http.StatusOK, map[string]any{
		"project_id": projectID,
		"runs":       runs,
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

func buildHostSummaries(run storage.RunDetails) []hostSummary {
	perTarget := make(map[string]*hostSummary)
	openPorts := make(map[string]map[int]struct{})

	for _, record := range run.Evidence {
		target := strings.TrimSpace(record.Target)
		if target == "" {
			continue
		}
		entry, ok := perTarget[target]
		if !ok {
			entry = &hostSummary{Target: target}
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
		counts[label]++
	}
	return mapToLabelCounts(counts)
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
