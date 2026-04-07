package suite

type helpTopicCard struct {
	Slug     string
	Title    string
	Summary  string
	Category string
	URL      string
	IsNew    bool
	Ready    bool
}

type helpTopicPage struct {
	Slug     string
	Title    string
	Summary  string
	Category string
	Sections []helpSection
	Links    []helpExternalLink
}

type helpSection struct {
	Title   string
	Content []string
}

type helpExternalLink struct {
	Label string
	URL   string
}

func helpTopicDefinitions() []helpTopicPage {
	return []helpTopicPage{
		{
			Slug:     "installation",
			Title:    "Installation",
			Category: "Getting Started",
			Summary:  "Linux-first setup, privileges, binaries and the current runtime assumptions for Startrace and tracer.",
			Sections: []helpSection{
				{Title: "Current Direction", Content: []string{
					"Startrace is intended to run on Linux and currently expects elevated privileges for scanner and sensor workflows.",
					"Docker or a dedicated small server remains a good long-term packaging path, but the current baseline is a direct Linux runtime.",
				}},
				{Title: "Setup Areas", Content: []string{
					"Binary build and placement for startrace and tracer.",
					"SQLite database path and data directory planning.",
					"External tool availability such as naabu, nmap, httpx, zgrab2, scamper and zeekctl.",
				}},
			},
			Links: []helpExternalLink{
				{Label: "Ubuntu Install Notes", URL: "/help/troubleshooting"},
			},
		},
		{
			Slug:     "basics",
			Title:    "Basic Functions",
			Category: "Getting Started",
			Summary:  "High-level explanation of projects, dashboard, inventory, discovery and the suite shell.",
			Sections: []helpSection{
				{Title: "Suite Concepts", Content: []string{
					"Projects define the working context shared by every module.",
					"Inventory is the shared asset layer above individual runs.",
					"Discovery is currently the primary live module and feeds the rest of the suite.",
				}},
				{Title: "Shared Behaviors", Content: []string{
					"Project switching and readiness checks are global.",
					"Module navigation is split between the suite sidebar and a module-local horizontal navigation bar.",
				}},
			},
		},
		{
			Slug:     "plugins",
			Title:    "Plugins and Tools",
			Category: "Reference",
			Summary:  "Overview of the currently used plugins, what they do and where their upstream projects live.",
			Sections: []helpSection{
				{Title: "Discovery Plugins", Content: []string{
					"naabu for port discovery.",
					"nmap for service and OS fingerprinting.",
					"httpx and zgrab2 for web and layer-7 probing.",
					"scamper for route tracing.",
					"zeek for passive ingest integration.",
				}},
				{Title: "Notes", Content: []string{
					"This section is intentionally a framework page for now. We can expand each plugin with install notes, flags, caveats and troubleshooting as we solidify the suite.",
				}},
			},
			Links: []helpExternalLink{
				{Label: "naabu", URL: "https://github.com/projectdiscovery/naabu"},
				{Label: "nmap", URL: "https://nmap.org/"},
				{Label: "httpx", URL: "https://github.com/projectdiscovery/httpx"},
				{Label: "zgrab2", URL: "https://github.com/zmap/zgrab2"},
				{Label: "scamper", URL: "https://www.caida.org/catalog/software/scamper/"},
				{Label: "Zeek", URL: "https://zeek.org/"},
			},
		},
		{
			Slug:     "runs",
			Title:    "Runs and History",
			Category: "Operations",
			Summary:  "Run states, review workflow, accepted warnings and the meaning of stored history.",
			Sections: []helpSection{
				{Title: "Run States", Content: []string{
					"Completed means the planned workflow reached a stable end state.",
					"Needs attention indicates failed jobs, uncertainty or follow-up work.",
					"Failed should remain rare and usually points to a larger execution issue.",
				}},
				{Title: "Review Flow", Content: []string{
					"Open failed jobs first, then confirm whether the missing result actually matters.",
					"Use reruns or reevaluation when the missing evidence is operationally important.",
				}},
			},
		},
		{
			Slug:     "reevaluation",
			Title:    "Reevaluation System",
			Category: "Operations",
			Summary:  "What reevaluation is for, when to use it and how it should fit day-to-day review.",
			Sections: []helpSection{
				{Title: "Intent", Content: []string{
					"Reevaluation is for uncertainty, follow-up and time-based confirmation rather than replacing a normal rerun.",
					"It should help operators revisit unclear hosts without losing the current run history.",
				}},
				{Title: "Current State", Content: []string{
					"Manual and scheduled reevaluation concepts already exist in the suite.",
					"Full automation of scheduled reevaluation remains part of the next foundation steps.",
				}},
			},
		},
		{
			Slug:     "troubleshooting",
			Title:    "Troubleshooting",
			Category: "Operations",
			Summary:  "Common setup and runtime issues such as missing binaries, privilege problems and partial plugin failures.",
			Sections: []helpSection{
				{Title: "Typical Problems", Content: []string{
					"Missing binary in PATH, especially under sudo/root execution.",
					"Passive ingest available but no logs visible.",
					"Runs fail early because the suite or worker process cannot see the external scanning tools.",
				}},
				{Title: "Recommended Approach", Content: []string{
					"Start with the readiness check, then inspect the failed job text inside the run.",
					"Confirm binary paths and root privileges before changing scan logic.",
				}},
			},
		},
		{
			Slug:     "inventory",
			Title:    "Inventory and Classification",
			Category: "Reference",
			Summary:  "How Startrace groups assets, stores guesses, handles overrides and builds shared inventory views.",
			Sections: []helpSection{
				{Title: "Inventory Model", Content: []string{
					"Inventory is shared across modules and should not be treated as a Discovery-only view.",
					"Automatic classification, confidence and manual overrides can coexist.",
				}},
				{Title: "Network Views", Content: []string{
					"Subnet grouping and topology rendering are derived from the shared asset model.",
					"Infrastructure roles such as router, firewall, DNS and domain controller receive graph-specific treatment.",
				}},
			},
		},
		{
			Slug:     "best-practices",
			Title:    "Best Practices",
			Category: "Reference",
			Summary:  "Operational habits for small environments, homelabs and SMB-style networks using the suite.",
			Sections: []helpSection{
				{Title: "General Guidance", Content: []string{
					"Keep projects scoped cleanly so dashboards and inventory stay meaningful.",
					"Prefer stable core scans and well-understood tooling over too many heavy modules at once.",
					"Use manual overrides when you know the environment better than the heuristics do.",
				}},
			},
		},
	}
}

func buildHelpCards(currentProjectID string) []helpTopicCard {
	topics := helpTopicDefinitions()
	cards := make([]helpTopicCard, 0, len(topics))
	for index, topic := range topics {
		url := "/help/" + topic.Slug
		if currentProjectID != "" {
			url += "?project=" + currentProjectID
		}
		cards = append(cards, helpTopicCard{
			Slug:     topic.Slug,
			Title:    topic.Title,
			Summary:  topic.Summary,
			Category: topic.Category,
			URL:      url,
			IsNew:    index < 3,
			Ready:    true,
		})
	}
	return cards
}

func latestHelpCards(cards []helpTopicCard, n int) []helpTopicCard {
	out := make([]helpTopicCard, 0, n)
	for _, card := range cards {
		if !card.IsNew {
			continue
		}
		out = append(out, card)
		if len(out) == n {
			return out
		}
	}
	if len(cards) <= n {
		return cards
	}
	return cards[:n]
}

func findHelpTopic(slug string) (helpTopicPage, bool) {
	for _, topic := range helpTopicDefinitions() {
		if topic.Slug == slug {
			return topic, true
		}
	}
	return helpTopicPage{}, false
}
