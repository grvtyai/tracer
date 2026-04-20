package suite

import (
	"net/http"
	"strings"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/options"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

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
		if err := s.repo.SaveAppSettings(r.Context(), appSettingsFromForm(r)); err != nil {
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
