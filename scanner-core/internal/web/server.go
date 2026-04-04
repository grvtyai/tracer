package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
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
	Title       string
	AppName     string
	ActiveNav   string
	BasePath    string
	Generated   time.Time
	DBPath      string
	DataDir     string
	BodyClass   string
	HeroNote    string
	Project     *storage.ProjectSummary
	Projects    []storage.ProjectSummary
	RecentRuns  []storage.RunSummary
	Runs        []storage.RunSummary
	Run         *storage.RunDetails
	Assets      []storage.AssetSummary
	Asset       *storage.AssetDetails
	AssetGroups []assetGroup
	Hosts       []hostSummary
	DiffAPI     string
	Stats       dashboardStats
	Notice      string
}

type dashboardStats struct {
	ProjectCount  int
	RunCount      int
	HostCount     int
	EvidenceCount int
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

	s.mux.HandleFunc("/", s.handleLanding)
	s.mux.HandleFunc("/projects", s.handleProjects)
	s.mux.HandleFunc("/projects/", s.handleProject)
	s.mux.HandleFunc("/assets", s.handleAssets)
	s.mux.HandleFunc("/assets/", s.handleAsset)
	s.mux.HandleFunc("/runs/", s.handleRun)
	s.mux.HandleFunc("/settings", s.handleSettings)

	s.mux.HandleFunc("/api/health", s.handleHealthAPI)
	s.mux.HandleFunc("/api/options", s.handleOptionsAPI)
	s.mux.HandleFunc("/api/projects", s.handleProjectsAPI)
	s.mux.HandleFunc("/api/projects/", s.handleProjectRunsAPI)
	s.mux.HandleFunc("/api/assets", s.handleAssetsAPI)
	s.mux.HandleFunc("/api/assets/", s.handleAssetAPI)
	s.mux.HandleFunc("/api/runs/", s.handleRunAPI)
	s.mux.HandleFunc("/api/diff", s.handleDiffAPI)
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	projects, err := s.repo.ListProjects(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	runs, err := s.repo.ListRuns(ctx, "")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	stats := dashboardStats{
		ProjectCount:  len(projects),
		RunCount:      len(runs),
		EvidenceCount: countEvidence(runs),
	}
	if len(runs) > 0 {
		stats.HostCount = countTargetsAcrossRuns(ctx, s.repo, runs[:min(5, len(runs))])
	}

	data := pageData{
		Title:      "Startrace Overview",
		AppName:    s.options.AppName,
		ActiveNav:  "landing",
		BasePath:   s.options.BasePath,
		Generated:  time.Now().UTC(),
		DBPath:     s.options.DBPath,
		DataDir:    s.options.DataDir,
		BodyClass:  "landing-page",
		HeroNote:   "Go-hosted Startrace foundation on top of tracer scanner-core",
		Projects:   takeProjects(projects, 6),
		RecentRuns: takeRuns(runs, 6),
		Stats:      stats,
	}
	s.render(w, "landing.html", data)
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/projects" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	projects, err := s.repo.ListProjects(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	runs, err := s.repo.ListRuns(ctx, "")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:      "Projects",
		AppName:    s.options.AppName,
		ActiveNav:  "projects",
		BasePath:   s.options.BasePath,
		Generated:  time.Now().UTC(),
		DBPath:     s.options.DBPath,
		DataDir:    s.options.DataDir,
		Projects:   projects,
		RecentRuns: takeRuns(runs, 8),
	}
	s.render(w, "projects.html", data)
}

func (s *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	projectID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/projects/"), "/")
	if projectID == "" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	project, err := s.findProject(ctx, projectID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	runs, err := s.repo.ListRuns(ctx, projectID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:     "Project " + project.Name,
		AppName:   s.options.AppName,
		ActiveNav: "projects",
		BasePath:  s.options.BasePath,
		Generated: time.Now().UTC(),
		DBPath:    s.options.DBPath,
		DataDir:   s.options.DataDir,
		Project:   &project,
		Runs:      runs,
		DiffAPI:   "/api/diff",
	}
	s.render(w, "project.html", data)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/assets" {
		http.NotFound(w, r)
		return
	}

	projectRef := strings.TrimSpace(r.URL.Query().Get("project"))
	assets, err := s.repo.ListAssets(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:       "Assets",
		AppName:     s.options.AppName,
		ActiveNav:   "assets",
		BasePath:    s.options.BasePath,
		Generated:   time.Now().UTC(),
		DBPath:      s.options.DBPath,
		DataDir:     s.options.DataDir,
		Assets:      assets,
		AssetGroups: groupAssets(assets),
		Notice:      strings.TrimSpace(r.URL.Query().Get("notice")),
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

	data := pageData{
		Title:     "Asset " + asset.Asset.DisplayName,
		AppName:   s.options.AppName,
		ActiveNav: "assets",
		BasePath:  s.options.BasePath,
		Generated: time.Now().UTC(),
		DBPath:    s.options.DBPath,
		DataDir:   s.options.DataDir,
		Asset:     &asset,
		Notice:    strings.TrimSpace(r.URL.Query().Get("notice")),
	}
	s.render(w, "asset.html", data)
}

func (s *Server) handleAssetEdit(w http.ResponseWriter, r *http.Request, assetID string) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	tags := splitTags(r.FormValue("tags"))
	_, err := s.repo.UpdateAsset(r.Context(), assetID, storage.AssetUpdateInput{
		DisplayName:    r.FormValue("display_name"),
		DeviceType:     r.FormValue("manual_device_type"),
		ConnectionType: r.FormValue("manual_connection_type"),
		Tags:           tags,
		Notes:          r.FormValue("manual_notes"),
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	http.Redirect(w, r, "/assets/"+assetID+"?notice=asset-updated", http.StatusSeeOther)
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

	data := pageData{
		Title:     "Run " + run.Run.ID,
		AppName:   s.options.AppName,
		ActiveNav: "runs",
		BasePath:  s.options.BasePath,
		Generated: time.Now().UTC(),
		DBPath:    s.options.DBPath,
		DataDir:   s.options.DataDir,
		Run:       &run,
		Hosts:     buildHostSummaries(run),
	}
	s.render(w, "run.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/settings" {
		http.NotFound(w, r)
		return
	}

	data := pageData{
		Title:     "Settings",
		AppName:   s.options.AppName,
		ActiveNav: "settings",
		BasePath:  s.options.BasePath,
		Generated: time.Now().UTC(),
		DBPath:    s.options.DBPath,
		DataDir:   s.options.DataDir,
	}
	s.render(w, "settings.html", data)
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

func (s *Server) handleProjectsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/projects" {
		http.NotFound(w, r)
		return
	}

	projects, err := s.repo.ListProjects(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"projects": projects,
	})
}

func (s *Server) handleAssetsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/assets" {
		http.NotFound(w, r)
		return
	}

	projectRef := strings.TrimSpace(r.URL.Query().Get("project"))
	assets, err := s.repo.ListAssets(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"project": projectRef,
		"assets":  assets,
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

func (s *Server) findProject(ctx context.Context, ref string) (storage.ProjectSummary, error) {
	projects, err := s.repo.ListProjects(ctx)
	if err != nil {
		return storage.ProjectSummary{}, err
	}
	for _, project := range projects {
		if project.ID == ref || strings.EqualFold(project.Name, ref) {
			return project, nil
		}
	}
	return storage.ProjectSummary{}, fmt.Errorf("project %q not found", ref)
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

func countTargetsAcrossRuns(ctx context.Context, repo *storage.SQLiteRepository, runs []storage.RunSummary) int {
	seen := make(map[string]struct{})
	for _, run := range runs {
		details, err := repo.GetRun(ctx, run.ID)
		if err != nil {
			continue
		}
		for _, host := range buildHostSummaries(details) {
			seen[host.Target] = struct{}{}
		}
	}
	return len(seen)
}

func takeProjects(projects []storage.ProjectSummary, n int) []storage.ProjectSummary {
	if len(projects) <= n {
		return projects
	}
	return projects[:n]
}

func takeRuns(runs []storage.RunSummary, n int) []storage.RunSummary {
	if len(runs) <= n {
		return runs
	}
	return runs[:n]
}

func groupAssets(assets []storage.AssetSummary) []assetGroup {
	grouped := make(map[string][]storage.AssetSummary)
	for _, asset := range assets {
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
		group := assetGroup{
			Name:   key,
			Assets: grouped[key],
		}
		sort.Slice(group.Assets, func(i, j int) bool {
			return group.Assets[i].DisplayName < group.Assets[j].DisplayName
		})
		groups = append(groups, group)
	}
	return groups
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
