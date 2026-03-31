package service

// Fingerprint captures service- and OS-level identification.
type Fingerprint struct {
	Target      string            `json:"target"`
	Port        int               `json:"port"`
	Transport   string            `json:"transport"`
	ServiceName string            `json:"service_name,omitempty"`
	Product     string            `json:"product,omitempty"`
	Version     string            `json:"version,omitempty"`
	OSFamily    string            `json:"os_family,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
