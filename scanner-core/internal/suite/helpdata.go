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
					"External tool availability such as naabu, nmap, httpx, zgrab2, scamper, avahi-browse, testssl.sh, snmpwalk and zeekctl.",
				}},
			},
			Links: []helpExternalLink{
				{Label: "Ubuntu Install Notes", URL: "/help/troubleshooting"},
			},
		},
		{
			Slug:     "infrastructure",
			Title:    "Infrastructure",
			Category: "Getting Started",
			Summary:  "How Startrace is split between the Mothership, future Satelites and the module-driven suite architecture.",
			Sections: []helpSection{
				{Title: "Mothership", Content: []string{
					"The Mothership is the main Startrace host. It runs the browser UI, stores the shared SQLite data and currently executes jobs locally.",
					"It is the first execution target shown in the suite and acts as the default home for Radar runs until remote Satelites are available.",
				}},
				{Title: "Satelites", Content: []string{
					"Satelites are the planned Startrace runners for other network segments or remote environments.",
					"A Satelite should receive jobs from the Mothership, execute them with the local toolkit and report health, status and results back to the main host.",
				}},
				{Title: "Responsibilities", Content: []string{
					"The Mothership owns the product UI, shared state and orchestration.",
					"Satelites are meant to own execution in places where keeping everything on one host is not practical.",
					"This split keeps Startrace usable as a single-node deployment today while leaving room for a distributed model later.",
				}},
				{Title: "Project Context", Content: []string{
					"The primary repository is https://github.com/grvtyai/startrace.",
					"Runtime paths such as the local workspace, SQLite database and data directory are shown in Settings so operators can confirm the current host context quickly.",
				}},
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
			Summary:  "What Radar does, which technologies it uses and how the current discovery stack is split into separate pieces.",
			Sections: []helpSection{
				{Title: "What Radar Is", Content: []string{
					"Radar is the first live Startrace module and is responsible for network discovery, scan execution and the first wave of technical evidence collection.",
					"It is not one single scanner. Radar combines multiple focused tools and normalizes their output into the shared Startrace data model.",
				}},
				{Title: "Core Discovery Stack", Content: []string{
					"naabu is used for fast port discovery and broad active reachability checks.",
					"nmap is used after initial discovery for deeper service and operating system fingerprinting.",
					"scamper is used for route tracing and path context.",
					"httpx is used to verify and classify web-facing services.",
					"zgrab2 is used for additional layer-7 grabbing when deeper protocol detail is useful.",
					"Zeek is used as the passive ingest path when passive observations are enabled.",
				}},
				{Title: "Optional Enrichment Stack", Content: []string{
					"Avahi is available for mDNS / Bonjour discovery and can surface local service announcements that active port scanning alone would miss.",
					"testssl.sh is available for TLS and certificate inspection on likely TLS-enabled services such as HTTPS and related encrypted endpoints.",
					"snmpwalk is available for lightweight SNMP system discovery on infrastructure-style devices such as switches, printers, access points and NAS systems.",
				}},
				{Title: "Additional Integrations", Content: []string{
					"arp-scan is available for local-segment discovery where layer-2 visibility helps.",
					"ldapdomaindump and SharpHound-related paths are early integrations for later identity- and directory-oriented workflows.",
					"These integrations are kept modular so Radar can grow without forcing every tool into every run.",
				}},
				{Title: "Why It Is Split This Way", Content: []string{
					"Each tool does a narrower job well, and Startrace combines them into one operator flow.",
					"This makes Radar easier to evolve than a monolithic scanner while keeping the results inside shared projects, assets and evidence records.",
				}},
			},
			Links: []helpExternalLink{
				{Label: "naabu", URL: "https://github.com/projectdiscovery/naabu"},
				{Label: "nmap", URL: "https://nmap.org/"},
				{Label: "httpx", URL: "https://github.com/projectdiscovery/httpx"},
				{Label: "zgrab2", URL: "https://github.com/zmap/zgrab2"},
				{Label: "scamper", URL: "https://www.caida.org/catalog/software/scamper/"},
				{Label: "Avahi", URL: "https://github.com/avahi/avahi"},
				{Label: "testssl.sh", URL: "https://github.com/testssl/testssl.sh"},
				{Label: "Net-SNMP", URL: "https://www.net-snmp.org/"},
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
					"Optional tools such as avahi-browse, testssl.sh or snmpwalk installed for the normal user but not visible to Startrace when it runs as sudo/root.",
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
