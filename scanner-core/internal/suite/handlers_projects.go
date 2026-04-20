package suite

import (
	"net/http"
	"os"
	"strings"

	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

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
