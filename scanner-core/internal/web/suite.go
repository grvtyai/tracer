package web

import "github.com/grvtyai/tracer/scanner-core/internal/storage"

type suiteModule struct {
	Key    string
	Label  string
	URL    string
	Active bool
}

type suiteCard struct {
	Title       string
	Summary     string
	URL         string
	StatusLabel string
	StatusClass string
}

type moduleNavItem struct {
	Label   string
	URL     string
	Active  bool
	Primary bool
}

type pageAction struct {
	Label   string
	URL     string
	Variant string
}

func buildSuiteModules(activeNav string, currentProject *storage.ProjectSummary) []suiteModule {
	modules := []struct {
		key   string
		label string
		path  string
	}{
		{key: "dashboard", label: "Dashboard", path: "/"},
		{key: "inventory", label: "Inventory", path: "/inventory"},
		{key: "discovery", label: "Discovery", path: "/discovery"},
		{key: "security", label: "Security", path: "/security"},
		{key: "workbench", label: "Workbench", path: "/workbench"},
		{key: "automation", label: "Automation", path: "/automation"},
		{key: "settings", label: "Settings", path: "/settings"},
	}

	items := make([]suiteModule, 0, len(modules))
	for _, module := range modules {
		items = append(items, suiteModule{
			Key:    module.key,
			Label:  module.label,
			URL:    buildProjectPath(module.path, currentProject),
			Active: activeNav == module.key,
		})
	}

	return items
}

func buildProjectPath(path string, currentProject *storage.ProjectSummary) string {
	if currentProject == nil || currentProject.ID == "" {
		return path
	}
	if path == "/" {
		return "/?project=" + currentProject.ID
	}
	return path + "?project=" + currentProject.ID
}

func moduleStatusClass(status string) string {
	switch status {
	case "Live":
		return "status-success"
	case "Foundation":
		return "status-warning"
	default:
		return "status-neutral"
	}
}

func buildModuleNav(activeNav string, activeSection string, currentProject *storage.ProjectSummary) []moduleNavItem {
	type candidate struct {
		section string
		label   string
		url     string
	}

	var candidates []candidate
	switch activeNav {
	case "discovery":
		candidates = []candidate{
			{section: "discovery-launch", label: "Start Run", url: "/scans/new"},
			{section: "discovery-overview", label: "Overview", url: "/discovery"},
			{section: "discovery-runs", label: "Runs", url: "/runs"},
			{section: "discovery-assets", label: "Assets", url: "/discovery/assets"},
			{section: "discovery-compare", label: "Compare", url: "/discovery/compare"},
		}
	case "inventory":
		candidates = []candidate{
			{section: "inventory-overview", label: "Overview", url: "/inventory"},
			{section: "inventory-network", label: "Netzwerkansicht", url: "/inventory/network"},
		}
	case "security":
		candidates = []candidate{
			{section: "security-overview", label: "Overview", url: "/security"},
		}
	case "workbench":
		candidates = []candidate{
			{section: "workbench-overview", label: "Overview", url: "/workbench"},
		}
	case "automation":
		candidates = []candidate{
			{section: "automation-overview", label: "Overview", url: "/automation"},
		}
	case "settings":
		candidates = []candidate{
			{section: "settings-overview", label: "Overview", url: "/settings"},
			{section: "settings-help", label: "Help", url: "/help"},
		}
	default:
		return nil
	}

	items := make([]moduleNavItem, 0, len(candidates))
	for _, candidate := range candidates {
		items = append(items, moduleNavItem{
			Label:   candidate.label,
			URL:     buildProjectPath(candidate.url, currentProject),
			Active:  activeSection == candidate.section,
			Primary: activeNav == "discovery" && candidate.section == "discovery-launch",
		})
	}

	return items
}
