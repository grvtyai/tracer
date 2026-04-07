package suite

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/classify"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/storage"
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
	Title                 string
	AppName               string
	BrandLogoURL          string
	ActiveNav             string
	ActiveSection         string
	SuiteModules          []suiteModule
	ModuleNav             []moduleNavItem
	BasePath              string
	DBPath                string
	DataDir               string
	BodyClass             string
	HeroNote              string
	Notice                string
	Project               *storage.ProjectSummary
	Projects              []storage.ProjectSummary
	CurrentProject        *storage.ProjectSummary
	ProjectSwitchPath     string
	ProjectForm           projectFormData
	Settings              storage.AppSettings
	PreflightChecks       []preflightCheck
	PreflightHealthy      bool
	PreflightState        string
	ScanForm              scanFormData
	RecentRuns            []storage.RunSummary
	CompareBaselineRunID  string
	CompareCandidateRunID string
	RecentRunItems        []runListItem
	Runs                  []storage.RunSummary
	RunItems              []runListItem
	Run                   *storage.RunDetails
	RunReevaluateURL      string
	Assets                []storage.AssetSummary
	Asset                 *storage.AssetDetails
	AssetReevaluateURL    string
	PortSections          []portSection
	AssetGroups           []assetGroup
	InventorySections     []inventorySubnetSection
	Hosts                 []hostSummary
	RunStatus             statusInfo
	ScheduledScans        []storage.ScheduledScan
	WarningDetails        []warningDetail
	HelpLink              string
	Stats                 dashboardStats
	DashboardCharts       []dashboardChart
	InventoryNetworkAPI   string
	InventoryNetworkJSON  template.JS
	DiscoveryTemplates    []discoveryTemplateCard
	HelpTopics            []helpTopicCard
	HelpLatest            []helpTopicCard
	HelpTopic             *helpTopicPage
	HelpSearchQuery       string
	RepoURL               string
	RepoPath              string
	DeviceTypeStats       []labelCount
	ConnectionStats       []labelCount
	StatusStats           []labelCount
	SuiteCards            []suiteCard
	OverviewText          string
	CurrentStateItems     []string
	RoadmapItems          []string
	PrimaryAction         *pageAction
	SecondaryAction       *pageAction
	ModuleImageURL        string
	DiffAPI               string
}

type dashboardStats struct {
	RunCount      int
	AssetCount    int
	HostCount     int
	EvidenceCount int
	ReevalCount   int
	SubnetCount   int
	OpenPortCount int
	CVECount      int
	CriticalCVEs  int
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

type inventorySubnetSection struct {
	ID              string
	Label           string
	HostCount       int
	CategoryCount   int
	Categories      []inventoryCategorySection
	ExpandByDefault bool
}

type inventoryCategorySection struct {
	Name      string
	Label     string
	HostCount int
	Hosts     []inventoryHostItem
}

type inventoryHostItem struct {
	ID                    string
	DisplayName           string
	PrimaryTarget         string
	CurrentOS             string
	DeviceType            string
	ConnectionType        string
	OpenPortCount         int
	ServicePreviews       []inventoryServicePreview
	AdditionalServiceHint string
	DeviceTypeGuess       string
	DeviceTypeConfidence  string
	ManualOverride        bool
	Tags                  []string
}

type inventoryServicePreview struct {
	Port     int
	Protocol string
	Service  string
	Detail   string
}

type portSection struct {
	Title        string
	Class        string
	DefaultOpen  bool
	Entries      []portEntry
	Summary      string
	EmptyMessage string
}

type portEntry struct {
	Port    int
	Label   string
	Detail  string
	Summary string
}

type labelCount struct {
	Label string
	Count int
}

type dashboardChart struct {
	Title        string
	TotalValue   int
	Segments     []dashboardChartSegment
	EmptyMessage string
}

type dashboardChartSegment struct {
	Label        string
	Count        int
	PercentLabel string
	Color        string
	DashArray    string
	DashOffset   string
	Tooltip      string
}

type inventoryNetworkData struct {
	RootLabel    string                  `json:"root_label"`
	RootSubLabel string                  `json:"root_sub_label,omitempty"`
	Networks     []inventoryNetworkGroup `json:"networks"`
}

type inventoryNetworkGroup struct {
	ID        string                 `json:"id"`
	Label     string                 `json:"label"`
	HostCount int                    `json:"host_count"`
	GatewayID string                 `json:"gateway_id,omitempty"`
	Hosts     []inventoryNetworkHost `json:"hosts"`
}

type inventoryNetworkHost struct {
	ID               string                `json:"id"`
	AssetID          string                `json:"asset_id"`
	DisplayName      string                `json:"display_name"`
	Target           string                `json:"target"`
	DeviceType       string                `json:"device_type"`
	ConnectionType   string                `json:"connection_type"`
	CurrentOS        string                `json:"current_os,omitempty"`
	CurrentVendor    string                `json:"current_vendor,omitempty"`
	CurrentProduct   string                `json:"current_product,omitempty"`
	OpenPorts        []int                 `json:"open_ports,omitempty"`
	PortDetails      []inventoryPortDetail `json:"port_details,omitempty"`
	ObservationCount int                   `json:"observation_count"`
	Tags             []string              `json:"tags,omitempty"`
	Status           string                `json:"status"`
	RoutePath        []string              `json:"route_path,omitempty"`
	RouteMode        string                `json:"route_mode,omitempty"`
	RouteSummary     string                `json:"route_summary,omitempty"`
	IsGateway        bool                  `json:"is_gateway,omitempty"`
	Infrastructure   bool                  `json:"infrastructure,omitempty"`
	GraphRole        string                `json:"graph_role,omitempty"`
	GraphRoleLabel   string                `json:"graph_role_label,omitempty"`
}

type inventoryPortDetail struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source,omitempty"`
	Summary  string `json:"summary,omitempty"`
	Detail   string `json:"detail,omitempty"`
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
	s.mux.HandleFunc("/inventory", s.handleInventory)
	s.mux.HandleFunc("/inventory/network", s.handleInventoryNetwork)
	s.mux.HandleFunc("/discovery/assets", s.handleDiscoveryAssets)
	s.mux.HandleFunc("/discovery/templates", s.handleDiscoveryTemplates)
	s.mux.HandleFunc("/discovery/compare", s.handleDiscoveryCompare)
	s.mux.HandleFunc("/discovery", s.handleDiscovery)
	s.mux.HandleFunc("/security", s.handleSecurity)
	s.mux.HandleFunc("/workbench", s.handleWorkbench)
	s.mux.HandleFunc("/automation", s.handleAutomation)
	s.mux.HandleFunc("/brand-logo", s.handleBrandLogo)
	s.mux.HandleFunc("/module-illustration", s.handleModuleIllustration)
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
	s.mux.HandleFunc("/help/", s.handleHelpTopic)

	s.mux.HandleFunc("/api/health", s.handleHealthAPI)
	s.mux.HandleFunc("/api/options", s.handleOptionsAPI)
	s.mux.HandleFunc("/api/preflight", s.handlePreflightAPI)
	s.mux.HandleFunc("/api/settings", s.handleSettingsAPI)
	s.mux.HandleFunc("/api/projects", s.handleProjectsAPI)
	s.mux.HandleFunc("/api/projects/", s.handleProjectRunsAPI)
	s.mux.HandleFunc("/api/assets", s.handleAssetsAPI)
	s.mux.HandleFunc("/api/inventory/network", s.handleInventoryNetworkAPI)
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
		ActiveSection:     "dashboard-overview",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Shared command surface for the Startrace operator suite",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/",
		Project:           currentProject,
		RecentRuns:        takeRuns(runs, 8),
		RecentRunItems:    buildRunListItems(ctx, s.repo, takeRuns(runs, 8)),
		Assets:            takeAssets(projectAssets, 8),
		HelpLink:          buildProjectPath("/help", currentProject),
		Stats: dashboardStats{
			RunCount:      len(runs),
			AssetCount:    len(projectAssets),
			HostCount:     len(projectAssets),
			EvidenceCount: countEvidence(runs),
			ReevalCount:   countReevaluationAcrossRuns(ctx, s.repo, runs),
		},
		DashboardCharts: buildDashboardCharts(projectAssets),
		Settings:        appSettings,
	}
	s.render(w, "dashboard.html", data)
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/discovery" {
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
		Title:              "Radar",
		AppName:            s.options.AppName,
		ActiveNav:          "discovery",
		ActiveSection:      "discovery-overview",
		BasePath:           s.options.BasePath,
		DBPath:             s.options.DBPath,
		DataDir:            s.options.DataDir,
		HeroNote:           "Discovery is now one module inside the wider Startrace suite",
		Notice:             noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:           projects,
		CurrentProject:     currentProject,
		ProjectSwitchPath:  "/discovery",
		Project:            currentProject,
		RecentRunItems:     buildRunListItems(ctx, s.repo, takeRuns(runs, 6)),
		DiscoveryTemplates: buildDiscoveryTemplateCards(currentProject),
		Stats: dashboardStats{
			RunCount:      len(runs),
			AssetCount:    len(projectAssets),
			HostCount:     len(projectAssets),
			EvidenceCount: countEvidence(runs),
			ReevalCount:   countReevaluationAcrossRuns(ctx, s.repo, runs),
			SubnetCount:   countUniqueSubnets(projectAssets),
			OpenPortCount: countObservedOpenPorts(projectAssets),
			CVECount:      countCVEFindingsAcrossRuns(ctx, s.repo, runs, false),
			CriticalCVEs:  countCVEFindingsAcrossRuns(ctx, s.repo, runs, true),
		},
		SecondaryAction: &pageAction{
			Label:   "Open Run History",
			URL:     buildProjectPath("/runs", currentProject),
			Variant: "button-secondary",
		},
		Settings: appSettings,
	}
	s.render(w, "discovery.html", data)
}

func (s *Server) handleDiscoveryAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/discovery/assets" {
		http.NotFound(w, r)
		return
	}
	target := "/inventory"
	if projectID := strings.TrimSpace(r.URL.Query().Get("project")); projectID != "" {
		target += "?project=" + urlQueryEscape(projectID)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleDiscoveryTemplates(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/discovery/templates" {
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

	data := pageData{
		Title:              "Radar Templates",
		AppName:            s.options.AppName,
		ActiveNav:          "discovery",
		ActiveSection:      "discovery-templates",
		BasePath:           s.options.BasePath,
		DBPath:             s.options.DBPath,
		DataDir:            s.options.DataDir,
		Notice:             noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:           projects,
		CurrentProject:     currentProject,
		ProjectSwitchPath:  "/discovery/templates",
		Project:            currentProject,
		DiscoveryTemplates: buildDiscoveryTemplateCards(currentProject),
		Settings:           appSettings,
	}
	s.render(w, "discovery_templates.html", data)
}

func (s *Server) handleDiscoveryCompare(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/discovery/compare" {
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

	baselineRunID := strings.TrimSpace(r.URL.Query().Get("baseline_run"))
	candidateRunID := strings.TrimSpace(r.URL.Query().Get("candidate_run"))
	if baselineRunID == "" && len(runs) >= 2 {
		baselineRunID = runs[1].ID
	}
	if candidateRunID == "" && len(runs) >= 1 {
		candidateRunID = runs[0].ID
	}

	data := pageData{
		Title:                 "Compare Radar Runs",
		AppName:               s.options.AppName,
		ActiveNav:             "discovery",
		ActiveSection:         "discovery-compare",
		BasePath:              s.options.BasePath,
		DBPath:                s.options.DBPath,
		DataDir:               s.options.DataDir,
		HeroNote:              "Left-versus-right discovery run comparison",
		Notice:                noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:              projects,
		CurrentProject:        currentProject,
		ProjectSwitchPath:     "/discovery/compare",
		Project:               currentProject,
		Runs:                  runs,
		DiffAPI:               "/api/diff",
		CompareBaselineRunID:  baselineRunID,
		CompareCandidateRunID: candidateRunID,
		Settings:              appSettings,
	}
	s.render(w, "compare.html", data)
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
		ActiveSection:     "dashboard-projects",
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
		ActiveNav:         "discovery",
		ActiveSection:     "discovery-runs",
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
		HelpLink:          buildProjectPath("/help/runs", currentProject),
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
		ActiveNav:         "discovery",
		ActiveSection:     "discovery-runs",
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
		HelpLink:          buildProjectPath("/help/troubleshooting", &project),
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

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/inventory" {
		http.NotFound(w, r)
		return
	}
	s.renderInventory(w, r, "/inventory")
}

func (s *Server) handleInventoryNetwork(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/inventory/network" {
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
	runLookup := s.inventoryRunLookup(ctx)
	networkData := buildInventoryNetworkData(*currentProject, projectAssets, runLookup)

	data := pageData{
		Title:                "Satelite Network View",
		AppName:              s.options.AppName,
		ActiveNav:            "inventory",
		ActiveSection:        "inventory-network",
		BasePath:             s.options.BasePath,
		DBPath:               s.options.DBPath,
		DataDir:              s.options.DataDir,
		HeroNote:             "Interactive network topology built from the shared inventory",
		Notice:               noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:             projects,
		CurrentProject:       currentProject,
		ProjectSwitchPath:    "/inventory/network",
		Project:              currentProject,
		InventoryNetworkAPI:  buildProjectPath("/api/inventory/network", currentProject),
		InventoryNetworkJSON: marshalTemplateJSON(networkData),
		Settings:             appSettings,
	}
	s.render(w, "inventory_network.html", data)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/assets" {
		http.NotFound(w, r)
		return
	}
	s.renderInventory(w, r, "/assets")
}

func (s *Server) renderInventory(w http.ResponseWriter, r *http.Request, switchPath string) {

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
		Title:             "Inventory",
		AppName:           s.options.AppName,
		ActiveNav:         "inventory",
		ActiveSection:     "inventory-overview",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Shared inventory for every suite module, not only discovery runs",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: switchPath,
		Project:           currentProject,
		Assets:            projectAssets,
		AssetGroups:       groupAssets(projectAssets),
		InventorySections: buildInventorySections(projectAssets),
		Settings:          appSettings,
	}
	s.render(w, "assets.html", data)
}

func (s *Server) handleInventoryNetworkAPI(w http.ResponseWriter, r *http.Request) {
	projectRef := strings.TrimSpace(r.URL.Query().Get("project"))
	_, currentProject, _, err := s.loadShellContext(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject == nil {
		s.writeJSON(w, http.StatusOK, inventoryNetworkData{})
		return
	}
	projectRef = currentProject.ID

	projectAssets, err := s.repo.ListAssets(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	runLookup := s.inventoryRunLookup(r.Context())
	s.writeJSON(w, http.StatusOK, buildInventoryNetworkData(*currentProject, projectAssets, runLookup))
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
	var lastRun *storage.RunDetails
	if strings.TrimSpace(asset.Asset.LastRunID) != "" {
		run, err := s.repo.GetRun(r.Context(), asset.Asset.LastRunID)
		if err == nil {
			lastRun = &run
		}
	}

	data := pageData{
		Title:              "Asset " + asset.Asset.DisplayName,
		AppName:            s.options.AppName,
		ActiveNav:          "inventory",
		ActiveSection:      "inventory-overview",
		BasePath:           s.options.BasePath,
		DBPath:             s.options.DBPath,
		DataDir:            s.options.DataDir,
		Projects:           projects,
		CurrentProject:     &project,
		ProjectSwitchPath:  "/inventory",
		Project:            &project,
		Asset:              &asset,
		AssetReevaluateURL: buildReevaluationURL(project.ID, "Reevaluate "+asset.Asset.DisplayName, asset.Asset.PrimaryTarget, "30m"),
		PortSections:       buildPortSections(asset, lastRun),
		HelpLink:           buildProjectPath("/help/inventory", &project),
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
		ActiveNav:         "dashboard",
		ActiveSection:     "dashboard-analytics",
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
		HelpLink:        buildProjectPath("/help/best-practices", currentProject),
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
		ActiveSection:     "settings-overview",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Global defaults and project-centric startup behavior",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/settings",
		Project:           currentProject,
		HelpLink:          buildProjectPath("/help", currentProject),
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
		RepoURL:           "https://github.com/grvtyai/tracer",
		RepoPath:          "C:\\Users\\andre\\Desktop\\repos\\tracer\\tracer",
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
		RepoURL:           "https://github.com/grvtyai/tracer",
		RepoPath:          "C:\\Users\\andre\\Desktop\\repos\\tracer\\tracer",
		Settings:          appSettings,
	}
	s.render(w, "help_topic.html", data)
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
	if data.SuiteModules == nil {
		data.SuiteModules = buildSuiteModules(data.ActiveNav, data.CurrentProject)
	}
	if data.ModuleNav == nil {
		data.ModuleNav = buildModuleNav(data.ActiveNav, data.ActiveSection, data.CurrentProject)
	}
	if strings.TrimSpace(data.BrandLogoURL) == "" {
		data.BrandLogoURL = "/brand-logo"
	}

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

func (s *Server) renderSuitePlaceholder(w http.ResponseWriter, r *http.Request, title string, overview string, currentState []string, roadmap []string, secondaryAction *pageAction, showImage bool) {
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

	activeNav := strings.ToLower(strings.TrimSpace(title))
	data := pageData{
		Title:             title,
		AppName:           s.options.AppName,
		ActiveNav:         activeNav,
		ActiveSection:     activeNav + "-overview",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Module foundation inside the wider Startrace suite",
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: "/" + activeNav,
		Project:           currentProject,
		OverviewText:      overview,
		CurrentStateItems: currentState,
		RoadmapItems:      roadmap,
		PrimaryAction: &pageAction{
			Label:   "Open Dashboard",
			URL:     buildProjectPath("/", currentProject),
			Variant: "button-primary",
		},
		SecondaryAction: secondaryAction,
		Settings:        appSettings,
	}
	if showImage {
		data.ModuleImageURL = "/module-illustration"
	}
	if data.SecondaryAction != nil && currentProject != nil {
		data.SecondaryAction.URL = buildProjectPath(strings.Split(data.SecondaryAction.URL, "?")[0], currentProject)
	}
	s.render(w, "module.html", data)
}

func (s *Server) handleModuleIllustration(w http.ResponseWriter, r *http.Request) {
	imagePath, err := resolveAssetPicturePath("404_Image.png")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, imagePath)
}

func (s *Server) handleBrandLogo(w http.ResponseWriter, r *http.Request) {
	logoPath, err := resolveAssetPicturePath("logo.png")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, logoPath)
}

func resolveAssetPicturePath(fileName string) (string, error) {
	candidates := []string{}

	if executable, err := os.Executable(); err == nil {
		execDir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(execDir, "..", "..", "assets", "pictures", fileName),
			filepath.Join(execDir, "..", "assets", "pictures", fileName),
			filepath.Join(execDir, "assets", "pictures", fileName),
		)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "assets", "pictures", fileName),
			filepath.Join(cwd, "..", "assets", "pictures", fileName),
		)
	}

	for _, candidate := range candidates {
		cleaned := filepath.Clean(candidate)
		if _, err := os.Stat(cleaned); err == nil {
			return cleaned, nil
		}
	}

	return "", fmt.Errorf("asset picture %q not found", fileName)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func marshalTemplateJSON(value any) template.JS {
	encoded, err := json.Marshal(value)
	if err != nil {
		return template.JS("null")
	}
	return template.JS(encoded)
}

func (s *Server) writeError(w http.ResponseWriter, status int, err error) {
	s.writeJSON(w, status, map[string]any{"error": err.Error()})
}

func (s *Server) inventoryRunLookup(ctx context.Context) func(string) *storage.RunDetails {
	cache := make(map[string]*storage.RunDetails)
	return func(runID string) *storage.RunDetails {
		trimmed := strings.TrimSpace(runID)
		if trimmed == "" {
			return nil
		}
		if cached, ok := cache[trimmed]; ok {
			return cached
		}
		run, err := s.repo.GetRun(ctx, trimmed)
		if err != nil {
			return nil
		}
		cache[trimmed] = &run
		return &run
	}
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

func currentProjectID(project *storage.ProjectSummary) string {
	if project == nil {
		return ""
	}
	return strings.TrimSpace(project.ID)
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

func buildInventorySections(projectAssets []storage.AssetSummary) []inventorySubnetSection {
	type sectionBucket struct {
		id         string
		label      string
		categories map[string]*inventoryCategorySection
	}

	subnet24Counts, subnet16Counts := inventorySubnetCounts(projectAssets)
	sectionBuckets := make(map[string]*sectionBucket)

	for _, asset := range projectAssets {
		sectionID, sectionLabel := inventorySubnetGroup(asset, subnet24Counts, subnet16Counts)
		bucket, ok := sectionBuckets[sectionID]
		if !ok {
			bucket = &sectionBucket{
				id:         sectionID,
				label:      sectionLabel,
				categories: make(map[string]*inventoryCategorySection),
			}
			sectionBuckets[sectionID] = bucket
		}

		categoryKey := normalizedInventoryCategory(asset.EffectiveDeviceType)
		category, ok := bucket.categories[categoryKey]
		if !ok {
			category = &inventoryCategorySection{
				Name:  categoryKey,
				Label: inventoryCategoryLabel(categoryKey),
				Hosts: make([]inventoryHostItem, 0),
			}
			bucket.categories[categoryKey] = category
		}

		servicePreviews, additionalHint := buildInventoryServicePreviews(asset.CurrentOpenPorts)
		category.Hosts = append(category.Hosts, inventoryHostItem{
			ID:                    asset.ID,
			DisplayName:           asset.DisplayName,
			PrimaryTarget:         asset.PrimaryTarget,
			CurrentOS:             asset.CurrentOS,
			DeviceType:            asset.EffectiveDeviceType,
			ConnectionType:        asset.EffectiveConnectionType,
			OpenPortCount:         len(asset.CurrentOpenPorts),
			ServicePreviews:       servicePreviews,
			AdditionalServiceHint: additionalHint,
			DeviceTypeGuess:       asset.DeviceTypeGuess,
			DeviceTypeConfidence:  asset.DeviceTypeConfidence,
			ManualOverride:        strings.TrimSpace(asset.ManualDeviceType) != "",
			Tags:                  asset.Tags,
		})
	}

	keys := make([]string, 0, len(sectionBuckets))
	for key := range sectionBuckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	sections := make([]inventorySubnetSection, 0, len(keys))
	for _, key := range keys {
		bucket := sectionBuckets[key]
		categoryKeys := make([]string, 0, len(bucket.categories))
		for categoryKey := range bucket.categories {
			categoryKeys = append(categoryKeys, categoryKey)
		}
		sort.SliceStable(categoryKeys, func(i, j int) bool {
			return inventoryCategorySortWeight(categoryKeys[i]) < inventoryCategorySortWeight(categoryKeys[j])
		})

		section := inventorySubnetSection{
			ID:         bucket.id,
			Label:      bucket.label,
			Categories: make([]inventoryCategorySection, 0, len(categoryKeys)),
		}
		for _, categoryKey := range categoryKeys {
			category := bucket.categories[categoryKey]
			sort.Slice(category.Hosts, func(i, j int) bool {
				if category.Hosts[i].DisplayName == category.Hosts[j].DisplayName {
					return category.Hosts[i].PrimaryTarget < category.Hosts[j].PrimaryTarget
				}
				return category.Hosts[i].DisplayName < category.Hosts[j].DisplayName
			})
			category.HostCount = len(category.Hosts)
			section.HostCount += category.HostCount
			section.Categories = append(section.Categories, *category)
		}
		section.CategoryCount = len(section.Categories)
		sections = append(sections, section)
	}

	if len(sections) == 1 {
		sections[0].ExpandByDefault = true
	}
	return sections
}

func buildInventoryNetworkData(project storage.ProjectSummary, projectAssets []storage.AssetSummary, runLookup func(string) *storage.RunDetails) inventoryNetworkData {
	type pendingHost struct {
		groupID    string
		groupLabel string
		host       inventoryNetworkHost
	}

	hosts := make([]pendingHost, 0, len(projectAssets))
	subnet24Counts, subnet16Counts := inventorySubnetCounts(projectAssets)
	for _, asset := range projectAssets {
		groupID := "inventory_hosts"
		groupLabel := "Inventory Hosts"
		hostID := asset.ID
		hostTarget := firstNonEmptyWeb(asset.PrimaryTarget, asset.DisplayName, asset.ID)
		if addr, ok := parseIPv4AssetTarget(asset.PrimaryTarget); ok {
			hostID = addr.String()
			hostTarget = addr.String()
			groupLabel, groupID = inventoryNetworkLabel(addr, subnet24Counts, subnet16Counts)
		}
		var lastRun *storage.RunDetails
		if runLookup != nil {
			lastRun = runLookup(asset.LastRunID)
		}
		portDetails := buildInventoryPortDetails(asset, lastRun)
		routePath, routeMode, routeSummary := buildInventoryRouteInfo(asset, lastRun)
		graphRole, graphRoleLabel, infrastructure := detectInventoryGraphRole(asset, routePath)

		hosts = append(hosts, pendingHost{
			groupID:    groupID,
			groupLabel: groupLabel,
			host: inventoryNetworkHost{
				ID:               hostID,
				AssetID:          asset.ID,
				DisplayName:      asset.DisplayName,
				Target:           hostTarget,
				DeviceType:       asset.EffectiveDeviceType,
				ConnectionType:   asset.EffectiveConnectionType,
				CurrentOS:        asset.CurrentOS,
				CurrentVendor:    asset.CurrentVendor,
				CurrentProduct:   asset.CurrentProduct,
				OpenPorts:        asset.CurrentOpenPorts,
				PortDetails:      portDetails,
				ObservationCount: asset.ObservationCount,
				Tags:             asset.Tags,
				Status:           inventoryHostStatus(asset),
				RoutePath:        routePath,
				RouteMode:        routeMode,
				RouteSummary:     routeSummary,
				Infrastructure:   infrastructure,
				GraphRole:        graphRole,
				GraphRoleLabel:   graphRoleLabel,
			},
		})
	}

	grouped := make(map[string]*inventoryNetworkGroup)
	for _, item := range hosts {
		groupID := item.groupID
		groupLabel := item.groupLabel

		group, ok := grouped[groupID]
		if !ok {
			group = &inventoryNetworkGroup{ID: groupID, Label: groupLabel, Hosts: make([]inventoryNetworkHost, 0)}
			grouped[groupID] = group
		}
		group.Hosts = append(group.Hosts, item.host)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := inventoryNetworkData{
		RootLabel:    "Origin",
		RootSubLabel: inventoryOriginHostname(),
		Networks:     make([]inventoryNetworkGroup, 0, len(keys)),
	}
	for _, key := range keys {
		group := grouped[key]
		markInventoryGateway(group)
		sort.Slice(group.Hosts, func(i, j int) bool {
			return group.Hosts[i].Target < group.Hosts[j].Target
		})
		group.HostCount = len(group.Hosts)
		out.Networks = append(out.Networks, *group)
	}
	return out
}

func inventorySubnetCounts(projectAssets []storage.AssetSummary) (map[string]int, map[string]int) {
	subnet24Counts := make(map[string]int)
	subnet16Counts := make(map[string]int)
	for _, asset := range projectAssets {
		addr, ok := parseIPv4AssetTarget(asset.PrimaryTarget)
		if !ok {
			continue
		}
		octets := addr.As4()
		group24 := fmt.Sprintf("%d.%d.%d", octets[0], octets[1], octets[2])
		group16 := fmt.Sprintf("%d.%d", octets[0], octets[1])
		subnet24Counts[group24]++
		subnet16Counts[group16]++
	}
	return subnet24Counts, subnet16Counts
}

func parseIPv4AssetTarget(target string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

func inventoryNetworkLabel(addr netip.Addr, subnet24Counts map[string]int, subnet16Counts map[string]int) (string, string) {
	octets := addr.As4()
	key24 := fmt.Sprintf("%d.%d.%d", octets[0], octets[1], octets[2])
	key16 := fmt.Sprintf("%d.%d", octets[0], octets[1])

	if subnet24Counts[key24] > 1 {
		label := fmt.Sprintf("%s.0/24", key24)
		return label, "net_" + strings.ReplaceAll(key24, ".", "_")
	}
	if subnet16Counts[key16] > 1 {
		label := fmt.Sprintf("%s.0.0/16", key16)
		return label, "net_" + strings.ReplaceAll(key16, ".", "_")
	}

	label := addr.String() + "/32"
	return label, "host_" + strings.ReplaceAll(addr.String(), ".", "_")
}

func inventorySubnetGroup(asset storage.AssetSummary, subnet24Counts map[string]int, subnet16Counts map[string]int) (string, string) {
	addr, ok := parseIPv4AssetTarget(asset.PrimaryTarget)
	if !ok {
		return "inventory_hosts", "Inventory Hosts"
	}
	return inventoryNetworkLabel(addr, subnet24Counts, subnet16Counts)
}

func normalizedInventoryCategory(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func inventoryCategoryLabel(value string) string {
	switch normalizedInventoryCategory(value) {
	case "router":
		return "Router"
	case "server":
		return "Server"
	case "workstation":
		return "Workstation"
	case "smartphone":
		return "Smartphone"
	case "tablet":
		return "Tablet"
	case "printer":
		return "Printer"
	case "iot":
		return "IoT"
	default:
		return "Unknown"
	}
}

func inventoryCategorySortWeight(value string) string {
	switch normalizedInventoryCategory(value) {
	case "router":
		return "01_router"
	case "server":
		return "02_server"
	case "workstation":
		return "03_workstation"
	case "smartphone":
		return "04_smartphone"
	case "tablet":
		return "05_tablet"
	case "printer":
		return "06_printer"
	case "iot":
		return "07_iot"
	default:
		return "99_" + normalizedInventoryCategory(value)
	}
}

func buildInventoryServicePreviews(ports []int) ([]inventoryServicePreview, string) {
	if len(ports) == 0 {
		return nil, "No open ports observed."
	}

	cloned := append([]int{}, ports...)
	sort.Ints(cloned)
	limit := len(cloned)
	if limit > 4 {
		limit = 4
	}

	previews := make([]inventoryServicePreview, 0, limit)
	for _, port := range cloned[:limit] {
		previews = append(previews, inventoryServicePreview{
			Port:     port,
			Protocol: "TCP",
			Service:  inventoryServiceName(port),
			Detail:   inventoryServiceDetail(port),
		})
	}

	if len(cloned) > limit {
		return previews, fmt.Sprintf("+%d more ports", len(cloned)-limit)
	}
	return previews, ""
}

func inventoryServiceName(port int) string {
	switch port {
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 88:
		return "Kerberos"
	case 110:
		return "POP3"
	case 111:
		return "RPC"
	case 123:
		return "NTP"
	case 135:
		return "RPC Endpoint"
	case 139:
		return "NetBIOS"
	case 143:
		return "IMAP"
	case 389:
		return "LDAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 465:
		return "SMTPS"
	case 587:
		return "Submission"
	case 631:
		return "IPP"
	case 636:
		return "LDAPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 1433:
		return "MSSQL"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP Alt"
	case 8443:
		return "HTTPS Alt"
	default:
		return inventoryServiceClassName(classify.FromPort(port))
	}
}

func inventoryServiceDetail(port int) string {
	switch classify.FromPort(port) {
	case "web":
		return "Webserver"
	case "directory":
		return "Directory Service"
	case "database":
		return "Database Service"
	case "remote_access":
		return "Remote Access"
	case "messaging":
		return "Messaging Service"
	case "printing":
		return "Print Service"
	default:
		return "No more data"
	}
}

func inventoryServiceClassName(category string) string {
	switch strings.TrimSpace(category) {
	case "web":
		return "Web"
	case "directory":
		return "Directory"
	case "database":
		return "Database"
	case "remote_access":
		return "Remote Access"
	case "messaging":
		return "Messaging"
	case "printing":
		return "Printing"
	default:
		return "General Service"
	}
}

func inventoryHostStatus(asset storage.AssetSummary) string {
	switch {
	case len(asset.CurrentOpenPorts) > 0:
		return "online"
	case asset.ObservationCount > 0:
		return "observed"
	default:
		return "unknown"
	}
}

func buildInventoryPortDetails(asset storage.AssetSummary, run *storage.RunDetails) []inventoryPortDetail {
	entries := make(map[int]inventoryPortDetail)

	for _, port := range asset.CurrentOpenPorts {
		entries[port] = inventoryPortDetail{
			Port:     port,
			Protocol: "tcp",
			State:    "OPEN",
			Service:  inventoryServiceName(port),
			Source:   "inventory",
			Detail:   inventoryServiceDetail(port),
			Summary:  "Observed as reachable",
		}
	}

	if run != nil {
		target := strings.TrimSpace(asset.PrimaryTarget)
		for _, record := range run.Evidence {
			if strings.TrimSpace(record.Target) != target || record.Port <= 0 {
				continue
			}
			if !isOpenPortKind(record.Kind) && !strings.EqualFold(record.Kind, "port_state") {
				continue
			}
			detail := describeInventoryPortDetail(record)
			existing, ok := entries[record.Port]
			if !ok || inventoryPortDetailPriority(detail) >= inventoryPortDetailPriority(existing) {
				entries[record.Port] = detail
			}
		}
	}

	ports := make([]int, 0, len(entries))
	for port := range entries {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	out := make([]inventoryPortDetail, 0, len(ports))
	for _, port := range ports {
		out = append(out, entries[port])
	}
	return out
}

func describeInventoryPortDetail(record evidence.Record) inventoryPortDetail {
	protocol := strings.TrimSpace(record.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	state := "OPEN"
	if strings.EqualFold(record.Kind, "port_state") {
		switch strings.ToLower(strings.TrimSpace(record.Attributes["state"])) {
		case "blocked":
			state = "BLOCKED"
		case "filtered":
			state = "FILTERED"
		case "closed":
			state = "CLOSED"
		}
	}

	service := firstNonEmptyWeb(
		record.Attributes["service_name"],
		record.Attributes["web_server"],
		record.Attributes["title"],
		inventoryServiceName(record.Port),
	)
	product := strings.TrimSpace(record.Attributes["product"])
	version := firstNonEmptyWeb(record.Attributes["version"], record.Attributes["tls_version"])
	detail := firstNonEmptyWeb(
		record.Attributes["title"],
		record.Attributes["tech"],
		record.Attributes["extra_info"],
		record.Attributes["content_type"],
		record.Attributes["location"],
		record.Attributes["state_reason"],
		record.Attributes["status"],
		record.Summary,
	)

	return inventoryPortDetail{
		Port:     record.Port,
		Protocol: protocol,
		State:    state,
		Service:  service,
		Product:  product,
		Version:  version,
		Source:   record.Source,
		Summary:  strings.TrimSpace(record.Summary),
		Detail:   detail,
	}
}

func inventoryPortDetailPriority(detail inventoryPortDetail) int {
	score := 0
	if detail.Service != "" {
		score += 4
	}
	if detail.Product != "" {
		score += 3
	}
	if detail.Version != "" {
		score += 2
	}
	if detail.Detail != "" {
		score++
	}
	return score
}

func buildInventoryRouteInfo(asset storage.AssetSummary, run *storage.RunDetails) ([]string, string, string) {
	if run == nil {
		return nil, "", ""
	}
	target := strings.TrimSpace(asset.PrimaryTarget)
	if target == "" {
		return nil, "", ""
	}

	for _, record := range run.Evidence {
		if !strings.EqualFold(record.Kind, "route_trace") || strings.TrimSpace(record.Target) != target {
			continue
		}
		hops := splitCSVList(record.Attributes["hop_addrs"])
		if len(hops) == 0 {
			continue
		}
		if hops[len(hops)-1] != target {
			hops = append(hops, target)
		}
		return hops, "exact", firstNonEmptyWeb(record.Summary, "Route trace available")
	}

	return nil, "", ""
}

func detectInventoryGraphRole(asset storage.AssetSummary, routePath []string) (string, string, bool) {
	joined := strings.ToLower(strings.Join([]string{
		asset.DisplayName,
		asset.PrimaryTarget,
		asset.CurrentHostname,
		asset.CurrentOS,
		asset.CurrentVendor,
		asset.CurrentProduct,
	}, " "))

	hasPort := func(port int) bool {
		return slices.Contains(asset.CurrentOpenPorts, port)
	}

	switch {
	case containsAny(joined, "pfsense", "opnsense", "firewall", "fortigate", "fortinet", "sophos", "checkpoint", "netgate", "utm"):
		return "firewall", "Firewall", true
	case containsAny(joined, "domain controller", "active directory") || ((hasPort(88) || hasPort(389) || hasPort(636) || hasPort(3268)) && (containsAny(joined, "windows server", "microsoft") || hasPort(445))):
		return "domain_controller", "Domain Controller", true
	case normalizedInventoryCategory(asset.EffectiveDeviceType) == "router":
		return "router", "Router", true
	case containsAny(joined, "switch", "catalyst", "aruba", "procurve", "netgear", "unifi switch", "edge switch", "mikrotik switch"):
		return "switch", "Switch", true
	case hasPort(53) && (hasPort(53) || hasPort(853)) && normalizedInventoryCategory(asset.EffectiveDeviceType) != "router":
		return "dns", "DNS Server", true
	case len(routePath) > 1:
		return "gateway", "Gateway", true
	default:
		return "host", inventoryCategoryLabel(asset.EffectiveDeviceType), false
	}
}

func inventoryOriginHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "startrace-host"
	}
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return "startrace-host"
	}
	return trimmed
}

func markInventoryGateway(group *inventoryNetworkGroup) {
	if group == nil || len(group.Hosts) == 0 {
		return
	}

	referencedFirstHops := make(map[string]int)
	for _, host := range group.Hosts {
		if len(host.RoutePath) > 1 {
			referencedFirstHops[host.RoutePath[0]]++
		}
	}

	bestIndex := -1
	bestScore := 0
	for index := range group.Hosts {
		score := inventoryGatewayScore(group.Hosts[index]) + referencedFirstHops[group.Hosts[index].Target]*6
		if score > bestScore {
			bestScore = score
			bestIndex = index
		}
	}

	if bestIndex < 0 || bestScore < 8 {
		return
	}

	group.GatewayID = group.Hosts[bestIndex].ID
	group.Hosts[bestIndex].IsGateway = true
	group.Hosts[bestIndex].Infrastructure = true
	if strings.TrimSpace(group.Hosts[bestIndex].GraphRole) == "" || group.Hosts[bestIndex].GraphRole == "host" {
		group.Hosts[bestIndex].GraphRole = "gateway"
		group.Hosts[bestIndex].GraphRoleLabel = "Gateway"
	}
	for index := range group.Hosts {
		if index == bestIndex {
			if len(group.Hosts[index].RoutePath) == 0 {
				group.Hosts[index].RoutePath = []string{group.Hosts[index].Target}
				group.Hosts[index].RouteMode = "inferred"
				group.Hosts[index].RouteSummary = "Gateway candidate for this subnet"
			}
			continue
		}
		if len(group.Hosts[index].RoutePath) == 0 {
			group.Hosts[index].RoutePath = []string{group.Hosts[bestIndex].Target, group.Hosts[index].Target}
			group.Hosts[index].RouteMode = "inferred"
			group.Hosts[index].RouteSummary = "Inferred path through subnet gateway"
		}
	}
}

func inventoryGatewayScore(host inventoryNetworkHost) int {
	score := 0
	if host.Infrastructure {
		score += 4
	}
	switch normalizedInventoryCategory(host.DeviceType) {
	case "router":
		score += 14
	case "server":
		score += 5
	}
	if strings.Contains(strings.ToLower(host.CurrentProduct), "firewall") || strings.Contains(strings.ToLower(host.CurrentProduct), "gateway") {
		score += 7
	}
	if strings.Contains(strings.ToLower(host.CurrentVendor), "pfsense") || strings.Contains(strings.ToLower(host.CurrentVendor), "opnsense") {
		score += 6
	}
	if hostHasPort(host, 53) {
		score += 3
	}
	if hostHasPort(host, 67) || hostHasPort(host, 68) {
		score += 4
	}
	if hostHasPort(host, 80) || hostHasPort(host, 443) {
		score += 1
	}
	if len(host.RoutePath) > 0 {
		score += 2
	}
	return score
}

func hostHasPort(host inventoryNetworkHost, port int) bool {
	for _, current := range host.OpenPorts {
		if current == port {
			return true
		}
	}
	return false
}

func splitCSVList(value string) []string {
	parts := strings.Split(strings.TrimSpace(value), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func containsAny(joined string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(joined, strings.ToLower(strings.TrimSpace(needle))) {
			return true
		}
	}
	return false
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

func countPortUsage(projectAssets []storage.AssetSummary) []labelCount {
	counts := make(map[string]int)
	for _, asset := range projectAssets {
		for _, port := range asset.CurrentOpenPorts {
			counts[fmt.Sprintf("%d/tcp", port)]++
		}
	}
	return mapToLabelCounts(counts)
}

func countUniqueSubnets(projectAssets []storage.AssetSummary) int {
	subnet24Counts, subnet16Counts := inventorySubnetCounts(projectAssets)
	seen := make(map[string]struct{})
	for _, asset := range projectAssets {
		_, groupID := inventorySubnetGroup(asset, subnet24Counts, subnet16Counts)
		if strings.TrimSpace(groupID) == "" || groupID == "inventory_hosts" {
			continue
		}
		seen[groupID] = struct{}{}
	}
	return len(seen)
}

func countObservedOpenPorts(projectAssets []storage.AssetSummary) int {
	total := 0
	for _, asset := range projectAssets {
		total += len(asset.CurrentOpenPorts)
	}
	return total
}

func countCVEFindingsAcrossRuns(ctx context.Context, repo *storage.SQLiteRepository, runs []storage.RunSummary, criticalOnly bool) int {
	seen := make(map[string]struct{})
	total := 0
	for _, run := range runs {
		details, err := repo.GetRun(ctx, run.ID)
		if err != nil {
			continue
		}
		for _, record := range details.Evidence {
			if !recordLooksLikeCVE(record) {
				continue
			}
			if criticalOnly && !recordLooksCritical(record) {
				continue
			}
			key := firstNonEmptyWeb(
				strings.TrimSpace(record.Attributes["cve"]),
				strings.TrimSpace(record.Attributes["cve_id"]),
				strings.TrimSpace(record.RawRef),
				strings.TrimSpace(record.Summary),
				fmt.Sprintf("%s:%d:%s", record.Target, record.Port, record.Kind),
			)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			total++
		}
	}
	return total
}

func recordLooksLikeCVE(record evidence.Record) bool {
	values := []string{
		record.Kind,
		record.RawRef,
		record.Summary,
		record.Attributes["cve"],
		record.Attributes["cve_id"],
		record.Attributes["finding"],
		record.Attributes["title"],
		record.Attributes["description"],
	}
	for _, value := range values {
		lowered := strings.ToLower(strings.TrimSpace(value))
		if lowered == "" {
			continue
		}
		if strings.Contains(lowered, "cve-") || strings.Contains(lowered, "vulnerability") || strings.Contains(lowered, "vuln") {
			return true
		}
	}
	return false
}

func recordLooksCritical(record evidence.Record) bool {
	values := []string{
		record.Attributes["severity"],
		record.Attributes["risk"],
		record.Attributes["level"],
		record.Summary,
		record.RawRef,
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), "critical") {
			return true
		}
	}
	return false
}

func countOSFamilies(projectAssets []storage.AssetSummary) []labelCount {
	return countAssetProperty(projectAssets, func(asset storage.AssetSummary) string {
		return detectOSFamily(asset.CurrentOS)
	})
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

func buildDashboardCharts(projectAssets []storage.AssetSummary) []dashboardChart {
	return []dashboardChart{
		buildDashboardChart(
			"Assets",
			countAssetProperty(projectAssets, func(asset storage.AssetSummary) string { return asset.EffectiveDeviceType }),
			"No assets are available for this project yet.",
		),
		buildDashboardChart(
			"Ports",
			countPortUsage(projectAssets),
			"No open ports have been stored yet.",
		),
		buildDashboardChart(
			"Operating Systems",
			countOSFamilies(projectAssets),
			"No operating system data has been stored yet.",
		),
		buildDashboardChart(
			"Connections",
			countAssetProperty(projectAssets, func(asset storage.AssetSummary) string { return asset.EffectiveConnectionType }),
			"No connection type data is available yet.",
		),
	}
}

func buildDashboardChart(title string, counts []labelCount, emptyMessage string) dashboardChart {
	normalized := normalizeChartCounts(counts, 6)
	total := 0
	for _, entry := range normalized {
		total += entry.Count
	}

	if total == 0 {
		return dashboardChart{
			Title:        title,
			EmptyMessage: emptyMessage,
		}
	}

	palette := []string{"#5b8cff", "#2fd7ff", "#ff9f43", "#3fdc7a", "#ff6b6b", "#c792ea", "#8be9fd"}
	segments := make([]dashboardChartSegment, 0, len(normalized))
	start := 0.0
	for idx, entry := range normalized {
		color := palette[idx%len(palette)]
		percent := float64(entry.Count) / float64(total) * 100
		dashArray, dashOffset := buildDonutStroke(start, percent)
		segments = append(segments, dashboardChartSegment{
			Label:        entry.Label,
			Count:        entry.Count,
			PercentLabel: fmt.Sprintf("%.1f%%", percent),
			Color:        color,
			DashArray:    dashArray,
			DashOffset:   dashOffset,
			Tooltip:      fmt.Sprintf("%s | %d | %.1f%%", entry.Label, entry.Count, percent),
		})
		start += percent
	}

	return dashboardChart{
		Title:      title,
		TotalValue: total,
		Segments:   segments,
	}
}

func buildDonutStroke(startPercent float64, spanPercent float64) (string, string) {
	if spanPercent >= 99.999 {
		return "100 0", "0"
	}

	gap := math.Min(1.4, spanPercent*0.18)
	visible := math.Max(spanPercent-gap, 0.8)
	offset := -(startPercent + gap/2)
	return fmt.Sprintf("%.3f %.3f", visible, 100-visible), fmt.Sprintf("%.3f", offset)
}

func normalizeChartCounts(counts []labelCount, maxSlices int) []labelCount {
	if len(counts) == 0 {
		return nil
	}

	normalized := append([]labelCount(nil), counts...)
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].Count == normalized[j].Count {
			return normalized[i].Label < normalized[j].Label
		}
		return normalized[i].Count > normalized[j].Count
	})

	if maxSlices <= 0 || len(normalized) <= maxSlices {
		return normalized
	}

	visible := append([]labelCount(nil), normalized[:maxSlices-1]...)
	other := 0
	for _, entry := range normalized[maxSlices-1:] {
		other += entry.Count
	}
	visible = append(visible, labelCount{Label: "other", Count: other})
	return visible
}

func detectOSFamily(value string) string {
	lowered := strings.ToLower(strings.TrimSpace(value))
	switch {
	case lowered == "":
		return "unknown"
	case strings.Contains(lowered, "windows"):
		return "windows"
	case strings.Contains(lowered, "macos"), strings.Contains(lowered, "os x"), strings.Contains(lowered, "darwin"):
		return "macos"
	case strings.Contains(lowered, "ios"), strings.Contains(lowered, "iphone"), strings.Contains(lowered, "ipad"):
		return "ios"
	case strings.Contains(lowered, "android"):
		return "android"
	case strings.Contains(lowered, "ubuntu"), strings.Contains(lowered, "debian"), strings.Contains(lowered, "linux"), strings.Contains(lowered, "centos"), strings.Contains(lowered, "fedora"), strings.Contains(lowered, "red hat"):
		return "linux"
	case strings.Contains(lowered, "freebsd"), strings.Contains(lowered, "openbsd"), strings.Contains(lowered, "netbsd"), strings.Contains(lowered, "bsd"):
		return "bsd"
	default:
		return "other"
	}
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

func buildPortSections(asset storage.AssetDetails, run *storage.RunDetails) []portSection {
	openEntries := map[int]portEntry{}
	blockedEntries := map[int]portEntry{}
	filteredEntries := map[int]portEntry{}
	closedEntries := map[int]portEntry{}

	for _, port := range asset.Asset.CurrentOpenPorts {
		openEntries[port] = portEntry{
			Port:    port,
			Label:   "OPEN",
			Summary: "Port " + fmt.Sprintf("%d", port),
			Detail:  "Observed as reachable",
		}
	}

	if run != nil {
		target := strings.TrimSpace(asset.Asset.PrimaryTarget)
		for _, record := range run.Evidence {
			if strings.TrimSpace(record.Target) != target || record.Port <= 0 {
				continue
			}
			entry := describePortRecord(record)
			switch portRecordCategory(record, run) {
			case "blocked":
				blockedEntries[record.Port] = entry
			case "filtered":
				filteredEntries[record.Port] = entry
			case "closed":
				closedEntries[record.Port] = entry
			case "open":
				openEntries[record.Port] = entry
			}
		}

		for _, assessment := range run.Blocking {
			if strings.TrimSpace(assessment.Target) != target || assessment.Port <= 0 {
				continue
			}
			switch assessment.Verdict {
			case evidence.VerdictConfirmedBlocked, evidence.VerdictProbableBlocked:
				blockedEntries[assessment.Port] = portEntry{
					Port:    assessment.Port,
					Label:   "BLOCKED",
					Summary: fmt.Sprintf("Port %d", assessment.Port),
					Detail:  strings.Join(assessment.Reasons, " "),
				}
			}
		}
	}

	observedStatePorts := make(map[int]struct{})
	for port := range openEntries {
		observedStatePorts[port] = struct{}{}
	}
	for port := range blockedEntries {
		observedStatePorts[port] = struct{}{}
	}
	for port := range filteredEntries {
		observedStatePorts[port] = struct{}{}
	}
	for port := range closedEntries {
		observedStatePorts[port] = struct{}{}
	}

	notTestedSummary := ""
	if run != nil {
		if templatePorts := portUniverseForTemplate(run.Options.PortTemplate); len(templatePorts) > 0 {
			notTested := make([]int, 0, len(templatePorts))
			for _, port := range templatePorts {
				if _, ok := observedStatePorts[port]; ok {
					continue
				}
				notTested = append(notTested, port)
			}
			notTestedSummary = compactPortRanges(notTested)
		}
	}

	return []portSection{
		{
			Title:        "Open",
			Class:        "port-open",
			DefaultOpen:  true,
			Entries:      sortPortEntries(openEntries),
			EmptyMessage: "No open ports were observed for this asset yet.",
		},
		{
			Title:        "Blocked",
			Class:        "port-blocked",
			Entries:      sortPortEntries(blockedEntries),
			EmptyMessage: "No blocked ports were recorded for this asset.",
		},
		{
			Title:        "Filtered",
			Class:        "port-filtered",
			Entries:      sortPortEntries(filteredEntries),
			EmptyMessage: "No filtered ports were recorded for this asset.",
		},
		{
			Title:        "Closed",
			Class:        "port-closed",
			Entries:      sortPortEntries(closedEntries),
			EmptyMessage: "No closed ports were recorded for this asset.",
		},
		{
			Title:        "Not tested",
			Class:        "port-untested",
			Summary:      firstNonEmptyWeb(notTestedSummary, "No compact not-tested range is available for the last run yet."),
			EmptyMessage: "No compact not-tested range is available for the last run yet.",
		},
	}
}

func portRecordCategory(record evidence.Record, run *storage.RunDetails) string {
	if strings.EqualFold(record.Kind, "port_state") {
		switch strings.ToLower(strings.TrimSpace(record.Attributes["state"])) {
		case "blocked":
			return "blocked"
		case "filtered":
			return "filtered"
		case "closed":
			return "closed"
		default:
			return "open"
		}
	}
	if isOpenPortKind(record.Kind) {
		return "open"
	}
	if run != nil {
		for _, assessment := range run.Blocking {
			if assessment.Target != record.Target || assessment.Port != record.Port {
				continue
			}
			if assessment.Verdict == evidence.VerdictConfirmedBlocked || assessment.Verdict == evidence.VerdictProbableBlocked {
				return "blocked"
			}
		}
	}
	return ""
}

func describePortRecord(record evidence.Record) portEntry {
	label := "OPEN"
	switch strings.ToLower(strings.TrimSpace(record.Attributes["state"])) {
	case "blocked":
		label = "BLOCKED"
	case "filtered":
		label = "FILTERED"
	case "closed":
		label = "CLOSED"
	}

	detail := firstNonEmptyWeb(
		record.Attributes["service_name"],
		record.Attributes["product"],
		record.Attributes["title"],
		record.Attributes["tech"],
	)
	if product := strings.TrimSpace(record.Attributes["product"]); product != "" && !strings.EqualFold(strings.TrimSpace(detail), product) {
		detail = strings.TrimSpace(detail + " " + product)
	}
	if detail == "" {
		detail = strings.TrimSpace(record.Summary)
	}

	return portEntry{
		Port:    record.Port,
		Label:   label,
		Summary: fmt.Sprintf("Port %d", record.Port),
		Detail:  detail,
	}
}

func isOpenPortKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "open_port", "service_fingerprint", "http_probe", "l7_grab":
		return true
	default:
		return false
	}
}

func sortPortEntries(entries map[int]portEntry) []portEntry {
	ports := make([]int, 0, len(entries))
	for port := range entries {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	out := make([]portEntry, 0, len(ports))
	for _, port := range ports {
		out = append(out, entries[port])
	}
	return out
}

func portUniverseForTemplate(templateName string) []int {
	switch strings.ToLower(strings.TrimSpace(templateName)) {
	case "all-default-ports":
		ports := make([]int, 0, 65535)
		for port := 1; port <= 65535; port++ {
			ports = append(ports, port)
		}
		return ports
	case "top-1000-ports":
		ports := make([]int, 0, 1000)
		for port := 1; port <= 1000; port++ {
			ports = append(ports, port)
		}
		return ports
	case "web-only":
		return []int{80, 81, 88, 443, 444, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443}
	case "entra-id":
		return []int{53, 80, 88, 123, 135, 389, 443, 445, 464, 636, 3268, 3269, 3389, 5985, 5986, 8080, 8443}
	default:
		return nil
	}
}

func compactPortRanges(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sort.Ints(ports)

	ranges := make([]string, 0)
	start := ports[0]
	prev := ports[0]
	for i := 1; i < len(ports); i++ {
		current := ports[i]
		if current == prev || current == prev+1 {
			prev = current
			continue
		}
		ranges = append(ranges, formatPortRange(start, prev))
		start = current
		prev = current
	}
	ranges = append(ranges, formatPortRange(start, prev))
	return strings.Join(ranges, ", ")
}

func formatPortRange(start int, end int) string {
	if start == end {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
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
