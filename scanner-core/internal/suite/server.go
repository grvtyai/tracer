package suite

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
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
	started time.Time
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
		started: time.Now(),
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
	s.mux.HandleFunc("/monitoring/satellites/register", s.handleMonitoringSatelliteRegister)
	s.mux.HandleFunc("/monitoring/satellites/refresh", s.handleMonitoringSatelliteRefresh)
	s.mux.HandleFunc("/monitoring/satellites", s.handleMonitoringSatellites)
	s.mux.HandleFunc("/monitoring/health", s.handleMonitoringHealth)
	s.mux.HandleFunc("/monitoring/jobs", s.handleMonitoringJobs)
	s.mux.HandleFunc("/monitoring", s.handleMonitoring)
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

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	if data.PreflightChecks == nil {
		data.PreflightChecks = collectPreflightChecks(s.options.DBPath)
	}
	deploymentMode := data.Settings.DeploymentMode
	if deploymentMode == "distributed" {
		coreChecks := make([]preflightCheck, 0)
		for _, c := range data.PreflightChecks {
			if isNexusCorePreflightCheck(c.Name) {
				coreChecks = append(coreChecks, c)
			}
		}
		data.PreflightHealthy = preflightHealthy(coreChecks)
		data.PreflightState = preflightState(coreChecks)
		hasSats := false
		if sats, err := s.repo.ListSatellites(context.Background()); err == nil {
			hasSats = len(sats) > 0
		}
		data.PreflightGroups = buildPreflightGroupsForMode(data.PreflightChecks, deploymentMode, hasSats)
	} else {
		data.PreflightHealthy = preflightHealthy(data.PreflightChecks)
		data.PreflightState = preflightState(data.PreflightChecks)
		data.PreflightGroups = buildPreflightGroups(data.PreflightChecks)
	}
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

func marshalTemplateJSON(value any) template.JS {
	encoded, err := json.Marshal(value)
	if err != nil {
		return template.JS("null")
	}
	return template.JS(encoded)
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

func (s *Server) optionsDataDir() string {
	if strings.TrimSpace(s.options.DataDir) != "" {
		return s.options.DataDir
	}
	return storage.DefaultDataDir()
}
