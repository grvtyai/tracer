package suite

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	"github.com/grvtyai/tracer/scanner-core/internal/shared/storage"
)

type discoveryTemplateCard struct {
	ID           string
	Name         string
	Owner        string
	Description  string
	Scope        string
	PortProfile  string
	SearchText   string
	EditURL      string
	DuplicateURL string
}

type discoveryTemplatePreset struct {
	Name                  string
	Owner                 string
	Description           string
	Scope                 string
	PortTemplate          string
	ScanTag               string
	ActiveInterface       string
	PassiveInterface      string
	PassiveMode           string
	ZeekLogDir            string
	ReevaluateAfter       string
	EnableRouteSampling   bool
	EnableServiceScan     bool
	EnablePassiveIngest   bool
	EnableOSDetection     bool
	EnableLayer2          bool
	UseLargeRangeStrategy bool
	ZeekAutoStart         bool
	ContinueOnError       bool
	RetainPartialResults  bool
}

func buildDiscoveryTemplateCards(currentProject *storage.ProjectSummary) []discoveryTemplateCard {
	presets := []discoveryTemplatePreset{
		{
			Name:                 "Home Lab Baseline",
			Owner:                "Startrace",
			Description:          "Active-first home network sweep with shared route, service and OS context for a typical local /24.",
			Scope:                "192.168.178.0/24",
			PortTemplate:         "all-default-ports",
			ScanTag:              "internal",
			ActiveInterface:      "eth2",
			PassiveInterface:     "eth2",
			PassiveMode:          "auto",
			ZeekLogDir:           "/opt/zeek/logs/current",
			ReevaluateAfter:      "30m",
			EnableRouteSampling:  true,
			EnableServiceScan:    true,
			EnablePassiveIngest:  true,
			EnableOSDetection:    true,
			ZeekAutoStart:        true,
			ContinueOnError:      true,
			RetainPartialResults: true,
		},
		{
			Name:                "Smoke Lab",
			Owner:               "Startrace",
			Description:         "Fast smoke pass for a small lab pair to validate discovery, ports and service fingerprints without extra noise.",
			Scope:               "192.168.56.10\n192.168.56.20",
			PortTemplate:        "top-1000-ports",
			ScanTag:             "internal",
			EnableRouteSampling: true,
			EnableServiceScan:   true,
			EnableOSDetection:   true,
		},
		{
			Name:                "Local Smoke",
			Owner:               "Startrace",
			Description:         "Very small localhost-style validation template for quick runtime checks and plugin sanity testing.",
			Scope:               "127.0.0.1",
			PortTemplate:        "top-1000-ports",
			ScanTag:             "internal",
			EnableRouteSampling: true,
			EnableServiceScan:   true,
			EnableOSDetection:   true,
		},
		{
			Name:                "Web Surface Smoke",
			Owner:               "Startrace",
			Description:         "Narrower web-facing check for HTTP and TLS validation when you care more about application exposure than full service breadth.",
			Scope:               "127.0.0.1",
			PortTemplate:        "web-only",
			ScanTag:             "external",
			EnableRouteSampling: true,
			EnableServiceScan:   true,
			EnableOSDetection:   true,
		},
		{
			Name:                 "Zeek Lab Passive Blend",
			Owner:                "Startrace",
			Description:          "Lab-oriented active plus passive sweep that keeps Zeek in the loop so route, service and passive evidence land together.",
			Scope:                "192.168.77.2",
			PortTemplate:         "all-default-ports",
			ScanTag:              "internal",
			ActiveInterface:      "eth1",
			PassiveInterface:     "eth1",
			PassiveMode:          "auto",
			ZeekLogDir:           "/opt/zeek/logs/current",
			ReevaluateAfter:      "30m",
			EnableRouteSampling:  true,
			EnableServiceScan:    true,
			EnablePassiveIngest:  true,
			EnableOSDetection:    true,
			ZeekAutoStart:        true,
			ContinueOnError:      true,
			RetainPartialResults: true,
		},
	}

	cards := make([]discoveryTemplateCard, 0, len(presets))
	for _, preset := range presets {
		id := shortTemplateID(preset.Name)
		cards = append(cards, discoveryTemplateCard{
			ID:           id,
			Name:         preset.Name,
			Owner:        firstNonEmptyWeb(preset.Owner, "Startrace"),
			Description:  preset.Description,
			Scope:        templateScopeSummary(preset.Scope),
			PortProfile:  portTemplateLabel(preset.PortTemplate),
			SearchText:   strings.ToLower(strings.Join([]string{preset.Name, preset.Description, preset.Scope, preset.PortTemplate, preset.Owner}, " ")),
			EditURL:      buildDiscoveryTemplateLaunchURL(currentProject, id, preset, false),
			DuplicateURL: buildDiscoveryTemplateLaunchURL(currentProject, id, preset, true),
		})
	}

	sort.SliceStable(cards, func(i, j int) bool {
		return cards[i].Name < cards[j].Name
	})
	return cards
}

func buildDiscoveryTemplateLaunchURL(currentProject *storage.ProjectSummary, templateID string, preset discoveryTemplatePreset, duplicate bool) string {
	params := map[string]string{
		"template_id":              templateID,
		"template_mode":            "edit",
		"scan_name":                preset.Name,
		"scope":                    preset.Scope,
		"port_template":            preset.PortTemplate,
		"scan_tag":                 preset.ScanTag,
		"active_interface":         preset.ActiveInterface,
		"passive_interface":        preset.PassiveInterface,
		"passive_mode":             preset.PassiveMode,
		"zeek_log_dir":             preset.ZeekLogDir,
		"reevaluate_after":         preset.ReevaluateAfter,
		"enable_route_sampling":    strconv.FormatBool(preset.EnableRouteSampling),
		"enable_service_scan":      strconv.FormatBool(preset.EnableServiceScan),
		"enable_passive_ingest":    strconv.FormatBool(preset.EnablePassiveIngest),
		"enable_os_detection":      strconv.FormatBool(preset.EnableOSDetection),
		"enable_layer2":            strconv.FormatBool(preset.EnableLayer2),
		"use_large_range_strategy": strconv.FormatBool(preset.UseLargeRangeStrategy),
		"zeek_auto_start":          strconv.FormatBool(preset.ZeekAutoStart),
		"continue_on_error":        strconv.FormatBool(preset.ContinueOnError),
		"retain_partial_results":   strconv.FormatBool(preset.RetainPartialResults),
	}
	if duplicate {
		params["template_mode"] = "duplicate"
		params["scan_name"] = preset.Name + " Copy"
	}
	return buildProjectPathWithParams("/scans/new", currentProject, params)
}

func buildProjectPathWithParams(path string, currentProject *storage.ProjectSummary, params map[string]string) string {
	values := make([]string, 0, len(params)+1)
	if currentProject != nil && strings.TrimSpace(currentProject.ID) != "" {
		values = append(values, "project="+urlQueryEscape(currentProject.ID))
	}

	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := strings.TrimSpace(params[key])
		if value == "" {
			continue
		}
		values = append(values, key+"="+urlQueryEscape(value))
	}

	if len(values) == 0 {
		return path
	}
	return path + "?" + strings.Join(values, "&")
}

func shortTemplateID(name string) string {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.ToLower(strings.TrimSpace(name))))
	value := strings.ToUpper(strconv.FormatUint(uint64(hasher.Sum32()%1679616), 36))
	for len(value) < 4 {
		value = "0" + value
	}
	return "TPL-" + value
}

func templateScopeSummary(scope string) string {
	lines := make([]string, 0)
	for _, line := range strings.Split(scope, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	switch len(lines) {
	case 0:
		return "No explicit scope"
	case 1:
		return lines[0]
	default:
		return fmt.Sprintf("%s + %d more", lines[0], len(lines)-1)
	}
}

func portTemplateLabel(value string) string {
	switch strings.TrimSpace(value) {
	case "all-default-ports":
		return "All Default Ports"
	case "top-1000-ports":
		return "Top 1000 Ports"
	case "web-only":
		return "Web Only"
	case "entra-id":
		return "Entra ID"
	default:
		return firstNonEmptyWeb(value, "Custom")
	}
}
