package suite

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

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
	preflightChecks := collectPreflightChecks(s.options.DBPath)
	monitoringSatellites, _, err := s.monitoringSatellites(ctx, preflightChecks, runs)
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
			RunCount:       len(runs),
			AssetCount:     len(projectAssets),
			HostCount:      len(projectAssets),
			EvidenceCount:  countEvidence(runs),
			ReevalCount:    countReevaluationAcrossRuns(ctx, s.repo, runs),
			SatelliteCount: countOnlineRegisteredSatellites(monitoringSatellites),
		},
		DashboardCharts: buildDashboardCharts(projectAssets),
		Settings:        appSettings,
	}
	s.render(w, "dashboard.html", data)
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
