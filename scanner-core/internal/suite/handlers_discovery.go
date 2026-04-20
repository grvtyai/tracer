package suite

import (
	"net/http"
	"strings"
)

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
