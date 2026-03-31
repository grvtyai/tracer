package ad

// Mode lets the pipeline switch between lightweight and deeper AD collection.
type Mode string

const (
	ModeLight Mode = "light"
	ModeFull  Mode = "full"
)

// AuditRequest describes an AD-oriented follow-up task.
type AuditRequest struct {
	Mode         Mode              `json:"mode"`
	Targets      []string          `json:"targets"`
	Credentials  map[string]string `json:"credentials,omitempty"`
	Domain       string            `json:"domain,omitempty"`
	CollectEdges []string          `json:"collect_edges,omitempty"`
}
