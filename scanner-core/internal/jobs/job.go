package jobs

import "time"

// Kind identifies a pipeline stage.
type Kind string

const (
	KindScopePrepare  Kind = "scope_prepare"
	KindL2Discover    Kind = "l2_discover"
	KindPortDiscover  Kind = "port_discover"
	KindRouteProbe    Kind = "route_probe"
	KindServiceProbe  Kind = "service_probe"
	KindWebProbe      Kind = "web_probe"
	KindGrabProbe     Kind = "grab_probe"
	KindPassiveIngest Kind = "passive_ingest"
	KindAnalyze       Kind = "analyze"
)

// Job is the scheduler unit used by the engine.
type Job struct {
	ID             string            `json:"id"`
	Kind           Kind              `json:"kind"`
	Plugin         string            `json:"plugin"`
	DependsOn      []string          `json:"depends_on,omitempty"`
	Targets        []string          `json:"targets,omitempty"`
	Ports          []int             `json:"ports,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ServiceClass   string            `json:"service_class,omitempty"`
	ServiceClasses []string          `json:"service_classes,omitempty"`
}

type ExecutionStatus string

const (
	StatusSucceeded ExecutionStatus = "succeeded"
	StatusFailed    ExecutionStatus = "failed"
	StatusSkipped   ExecutionStatus = "skipped"
)

type ExecutionResult struct {
	JobID              string          `json:"job_id"`
	Kind               Kind            `json:"kind"`
	Plugin             string          `json:"plugin"`
	Targets            []string        `json:"targets,omitempty"`
	Ports              []int           `json:"ports,omitempty"`
	Status             ExecutionStatus `json:"status"`
	Error              string          `json:"error,omitempty"`
	RecordsWritten     int             `json:"records_written,omitempty"`
	StartedAt          time.Time       `json:"started_at"`
	FinishedAt         time.Time       `json:"finished_at"`
	NeedsReevaluation  bool            `json:"needs_reevaluation,omitempty"`
	ReevaluationAfter  string          `json:"reevaluation_after,omitempty"`
	ReevaluationReason string          `json:"reevaluation_reason,omitempty"`
}
