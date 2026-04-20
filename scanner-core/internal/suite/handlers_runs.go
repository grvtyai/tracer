package suite

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

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
		RunExecutionFacts: buildRunExecutionFacts(run),
		RunJobItems:       buildRunJobItems(run),
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
			item.ScanTag = runTagLabel(details.Scope.Labels["scan_tag"])
			item.ScanTagClass = runTagClass(details.Scope.Labels["scan_tag"])
		}
		items = append(items, item)
	}
	return items
}

func runTagLabel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "external":
		return "External"
	case "internal":
		return "Internal"
	default:
		return ""
	}
}

func runTagClass(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "external":
		return "tag-external"
	case "internal":
		return "tag-internal"
	default:
		return ""
	}
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

func buildRunExecutionFacts(run storage.RunDetails) []monitoringFact {
	scopeEntries := len(run.Scope.Targets) + len(run.Scope.CIDRs)
	satelliteName := firstNonEmptyWeb(
		strings.TrimSpace(run.Scope.Labels["execution_satellite_name"]),
		"Startrace Nexus - "+detectNexusAddress(),
	)
	satelliteID := firstNonEmptyWeb(strings.TrimSpace(run.Scope.Labels["execution_satellite_id"]), "nexus")

	completedSteps := 0
	failedSteps := 0
	for _, result := range run.JobResults {
		switch result.Status {
		case jobs.StatusSucceeded:
			completedSteps++
		case jobs.StatusFailed:
			failedSteps++
		}
	}

	return []monitoringFact{
		{Key: "Execution satelite", Value: satelliteName},
		{Key: "Satelite ID", Value: satelliteID},
		{Key: "Run mode", Value: firstNonEmptyWeb(strings.TrimSpace(run.Run.Mode), "run")},
		{Key: "Scope entries", Value: fmt.Sprintf("%d", scopeEntries)},
		{Key: "Planned steps", Value: fmt.Sprintf("%d", len(run.Plan))},
		{Key: "Finished steps", Value: fmt.Sprintf("%d", completedSteps)},
		{Key: "Failed steps", Value: fmt.Sprintf("%d", failedSteps)},
		{Key: "Evidence records", Value: fmt.Sprintf("%d", run.Run.EvidenceCount)},
	}
}

func buildRunJobItems(run storage.RunDetails) []runJobItem {
	items := make([]runJobItem, 0, len(run.Plan)+len(run.JobResults))
	resultsByID := make(map[string]jobs.ExecutionResult, len(run.JobResults))
	usedResults := make(map[string]struct{}, len(run.JobResults))
	for _, result := range run.JobResults {
		resultsByID[result.JobID] = result
	}

	for _, planned := range run.Plan {
		result, ok := resultsByID[planned.ID]
		if ok {
			usedResults[planned.ID] = struct{}{}
		}
		items = append(items, buildRunJobItemFromPlan(planned, result, ok, strings.EqualFold(strings.TrimSpace(run.Run.Status), "running")))
	}

	for _, result := range run.JobResults {
		if _, ok := usedResults[result.JobID]; ok {
			continue
		}
		items = append(items, buildRunJobItemFromResult(result))
	}

	return items
}

func buildRunJobItemFromPlan(planned jobs.Job, result jobs.ExecutionResult, hasResult bool, runIsRunning bool) runJobItem {
	item := runJobItem{
		ID:     planned.ID,
		Kind:   string(planned.Kind),
		Plugin: firstNonEmptyWeb(strings.TrimSpace(planned.Plugin), "planner"),
		Target: summarizeJobTargets(planned.Targets, planned.Ports),
	}

	if !hasResult {
		item.Status = "Pending"
		item.StatusClass = "status-neutral"
		if !runIsRunning {
			item.Status = "Not recorded"
		}
		item.Duration = "-"
		item.StartedAt = "-"
		item.FinishedAt = "-"
		return item
	}

	item.Status = runJobStatusLabel(result.Status)
	item.StatusClass = runJobStatusClass(result.Status)
	item.StartedAt = formatMonitoringTimestamp(result.StartedAt)
	item.FinishedAt = formatMonitoringTimestamp(result.FinishedAt)
	item.Duration = formatRunJobDuration(result.StartedAt, result.FinishedAt)
	item.RecordsWritten = result.RecordsWritten
	item.Error = strings.TrimSpace(result.Error)
	item.NeedsReevaluation = result.NeedsReevaluation
	item.ReevaluationAfter = strings.TrimSpace(result.ReevaluationAfter)
	item.ReevaluationReason = strings.TrimSpace(result.ReevaluationReason)
	if target := summarizeJobTargets(result.Targets, result.Ports); target != "-" {
		item.Target = target
	}
	if strings.TrimSpace(result.Plugin) != "" {
		item.Plugin = result.Plugin
	}
	if strings.TrimSpace(string(result.Kind)) != "" {
		item.Kind = string(result.Kind)
	}
	return item
}

func buildRunJobItemFromResult(result jobs.ExecutionResult) runJobItem {
	return runJobItem{
		ID:                 result.JobID,
		Kind:               string(result.Kind),
		Plugin:             firstNonEmptyWeb(strings.TrimSpace(result.Plugin), "runtime"),
		Target:             summarizeJobTargets(result.Targets, result.Ports),
		Status:             runJobStatusLabel(result.Status),
		StatusClass:        runJobStatusClass(result.Status),
		StartedAt:          formatMonitoringTimestamp(result.StartedAt),
		FinishedAt:         formatMonitoringTimestamp(result.FinishedAt),
		Duration:           formatRunJobDuration(result.StartedAt, result.FinishedAt),
		RecordsWritten:     result.RecordsWritten,
		Error:              strings.TrimSpace(result.Error),
		NeedsReevaluation:  result.NeedsReevaluation,
		ReevaluationAfter:  strings.TrimSpace(result.ReevaluationAfter),
		ReevaluationReason: strings.TrimSpace(result.ReevaluationReason),
	}
}

func summarizeJobTargets(targets []string, ports []int) string {
	if len(targets) > 0 {
		if len(targets) == 1 {
			return targets[0]
		}
		return fmt.Sprintf("%s +%d more", targets[0], len(targets)-1)
	}
	if len(ports) > 0 {
		parts := make([]string, 0, len(ports))
		limit := len(ports)
		if limit > 4 {
			limit = 4
		}
		for idx := 0; idx < limit; idx++ {
			parts = append(parts, fmt.Sprintf("%d", ports[idx]))
		}
		if len(ports) > limit {
			return "ports " + strings.Join(parts, ", ") + fmt.Sprintf(" +%d more", len(ports)-limit)
		}
		return "ports " + strings.Join(parts, ", ")
	}
	return "-"
}

func runJobStatusLabel(status jobs.ExecutionStatus) string {
	switch status {
	case jobs.StatusSucceeded:
		return "Succeeded"
	case jobs.StatusFailed:
		return "Failed"
	case jobs.StatusSkipped:
		return "Skipped"
	default:
		return "Unknown"
	}
}

func runJobStatusClass(status jobs.ExecutionStatus) string {
	switch status {
	case jobs.StatusSucceeded:
		return "status-success"
	case jobs.StatusFailed:
		return "status-danger"
	case jobs.StatusSkipped:
		return "status-warning"
	default:
		return "status-neutral"
	}
}

func formatRunJobDuration(start time.Time, finish time.Time) string {
	if start.IsZero() || finish.IsZero() || finish.Before(start) {
		return "-"
	}
	return formatMonitoringDuration(finish.Sub(start))
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
