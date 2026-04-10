package templates

import (
	"github.com/grvtyai/startrace/scanner-core/internal/ingest"
	"github.com/grvtyai/startrace/scanner-core/internal/options"
)

// Template bundles a reusable scope and profile combination.
type Template struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	Scope       ingest.Scope            `json:"scope"`
	Profile     ingest.RunProfile       `json:"profile"`
	Options     options.TemplateOptions `json:"options,omitempty"`
}
