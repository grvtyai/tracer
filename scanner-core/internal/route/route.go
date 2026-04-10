package route

// ProbePolicy limits route collection cost.
type ProbePolicy struct {
	PerHost          int `json:"per_host"`
	PerServiceClass  int `json:"per_service_class"`
	PerImportantPort int `json:"per_important_port"`
}

// Observation represents a normalized path result.
type Observation struct {
	Target    string   `json:"target"`
	Port      int      `json:"port,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Hops      []string `json:"hops,omitempty"`
	Completed bool     `json:"completed"`
}
