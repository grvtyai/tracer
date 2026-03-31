package templates

import "github.com/grvtyai/tracer/scanner-core/internal/ingest"

// Template bundles a reusable scope and profile combination.
type Template struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Scope       ingest.Scope      `json:"scope"`
	Profile     ingest.RunProfile `json:"profile"`
}
