package ingest

// Scope defines the allowed targets and execution constraints for a scan run.
type Scope struct {
	Name             string            `json:"name"`
	CIDRs            []string          `json:"cidrs,omitempty"`
	Targets          []string          `json:"targets,omitempty"`
	DNSNames         []string          `json:"dns_names,omitempty"`
	AllowedNetworks  []string          `json:"allowed_networks,omitempty"`
	ExcludedNetworks []string          `json:"excluded_networks,omitempty"`
	Template         string            `json:"template,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
}

// RunProfile tunes the breadth and cost of a scan execution.
type RunProfile struct {
	Name                  string `json:"name"`
	EnableLayer2          bool   `json:"enable_layer2"`
	UseLargeRangeStrategy bool   `json:"use_large_range_strategy"`
	EnableRouteSampling   bool   `json:"enable_route_sampling"`
	EnableServiceScan     bool   `json:"enable_service_scan"`
	EnableOSDetection     bool   `json:"enable_os_detection"`
	EnablePassiveIngest   bool   `json:"enable_passive_ingest,omitempty"`
	ZeekLogDir            string `json:"zeek_log_dir,omitempty"`
}
