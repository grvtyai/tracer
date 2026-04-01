package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
	"github.com/grvtyai/tracer/scanner-core/internal/templates"
	"github.com/grvtyai/tracer/scanner-core/plugins/arp_scan"
	"github.com/grvtyai/tracer/scanner-core/plugins/httpx"
	"github.com/grvtyai/tracer/scanner-core/plugins/ldapdomaindump"
	"github.com/grvtyai/tracer/scanner-core/plugins/naabu"
	"github.com/grvtyai/tracer/scanner-core/plugins/nmap"
	"github.com/grvtyai/tracer/scanner-core/plugins/scamper"
	"github.com/grvtyai/tracer/scanner-core/plugins/sharphound"
	"github.com/grvtyai/tracer/scanner-core/plugins/zeek"
	"github.com/grvtyai/tracer/scanner-core/plugins/zgrab2"
)

type Output struct {
	Mode     string            `json:"mode"`
	Template string            `json:"template"`
	Plan     []jobs.Job        `json:"plan"`
	Evidence []evidence.Record `json:"evidence,omitempty"`
}

type internalPlugin struct{}

func (internalPlugin) Name() string {
	return "internal"
}

func (internalPlugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindScopePrepare
}

func (internalPlugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	return nil, nil
}

func DefaultPlugins() []engine.Plugin {
	return []engine.Plugin{
		internalPlugin{},
		arp_scan.Plugin{},
		naabu.New(),
		nmap.Plugin{},
		scamper.Plugin{},
		httpx.Plugin{},
		zgrab2.Plugin{},
		zeek.Plugin{},
		sharphound.Plugin{},
		ldapdomaindump.Plugin{},
	}
}

func LoadTemplate(path string) (templates.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return templates.Template{}, fmt.Errorf("read template %s: %w", path, err)
	}

	var template templates.Template
	if err := json.Unmarshal(data, &template); err != nil {
		return templates.Template{}, fmt.Errorf("decode template %s: %w", path, err)
	}

	return template, nil
}

func BuildSeedPlan(template templates.Template) []jobs.Job {
	return jobs.BuildSeedPlan(template.Scope, template.Profile)
}

func RunPlan(ctx context.Context, plugins []engine.Plugin, plan []jobs.Job) ([]evidence.Record, error) {
	store := storage.NewMemoryStore()
	runtime := engine.New(plugins, store)

	if err := runtime.Run(ctx, plan); err != nil {
		return nil, err
	}

	return store.Records(), nil
}
