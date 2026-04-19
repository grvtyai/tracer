package api

// Capabilities is the response body for GET /capabilities. The Nexus uses this
// to determine which scan options to offer the operator in the UI. Plugins not
// marked Available must not be requested in a run.
type Capabilities struct {
	SatelliteID string   `json:"satellite_id"`
	Version     string   `json:"version"`
	APIVersion  string   `json:"api_version"`
	Plugins     []Plugin `json:"plugins"`
}

type Plugin struct {
	Name      string   `json:"name"`
	Kinds     []string `json:"kinds"`
	Available bool     `json:"available"`
	Reason    string   `json:"reason,omitempty"`
	Version   string   `json:"version,omitempty"`
}
