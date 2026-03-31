package passive

import "time"

// Event represents passive telemetry imported from tools such as Zeek.
type Event struct {
	Source     string            `json:"source"`
	Target     string            `json:"target"`
	Port       int               `json:"port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Signal     string            `json:"signal"`
	Attributes map[string]string `json:"attributes,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}
