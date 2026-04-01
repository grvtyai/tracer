package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

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
		nmap.New(),
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

func BuildFollowUpPlan(template templates.Template, records []evidence.Record) []jobs.Job {
	if !template.Profile.EnableServiceScan && !template.Profile.EnableRouteSampling {
		return nil
	}

	targetPorts := make(map[string]map[int]struct{})
	for _, record := range records {
		if record.Kind != "open_port" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(record.Protocol)) == "udp" {
			continue
		}

		if _, ok := targetPorts[record.Target]; !ok {
			targetPorts[record.Target] = make(map[int]struct{})
		}
		targetPorts[record.Target][record.Port] = struct{}{}
	}

	targets := make([]string, 0, len(targetPorts))
	for target := range targetPorts {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	plan := make([]jobs.Job, 0)
	for _, target := range targets {
		ports := sortedPorts(targetPorts[target])
		serviceClass := classifyServiceClass(ports)

		if template.Profile.EnableRouteSampling {
			plan = append(plan, jobs.Job{
				ID:           fmt.Sprintf("route-%s", target),
				Kind:         jobs.KindRouteProbe,
				Plugin:       "scamper",
				Targets:      []string{target},
				ServiceClass: serviceClass,
			})
		}

		if template.Profile.EnableServiceScan && len(ports) > 0 {
			dependsOn := []string(nil)
			if template.Profile.EnableRouteSampling {
				dependsOn = []string{fmt.Sprintf("route-%s", target)}
			}

			plan = append(plan, jobs.Job{
				ID:           fmt.Sprintf("service-%s", target),
				Kind:         jobs.KindServiceProbe,
				Plugin:       "nmap",
				DependsOn:    dependsOn,
				Targets:      []string{target},
				Ports:        ports,
				ServiceClass: serviceClass,
				Metadata: map[string]string{
					"os_detection":    boolString(template.Profile.EnableOSDetection),
					"timing_template": "4",
				},
			})
		}
	}

	return plan
}

func RunPlan(ctx context.Context, plugins []engine.Plugin, plan []jobs.Job) ([]evidence.Record, error) {
	store := storage.NewMemoryStore()
	runtime := engine.New(plugins, store)

	if err := runtime.Run(ctx, plan); err != nil {
		return nil, err
	}

	return store.Records(), nil
}

func ExecuteRun(ctx context.Context, plugins []engine.Plugin, template templates.Template) ([]jobs.Job, []evidence.Record, error) {
	seedPlan := BuildSeedPlan(template)
	seedEvidence, err := RunPlan(ctx, plugins, seedPlan)
	if err != nil {
		return nil, nil, err
	}

	fullPlan := append([]jobs.Job{}, seedPlan...)
	allEvidence := append([]evidence.Record{}, seedEvidence...)

	followUpPlan := BuildFollowUpPlan(template, seedEvidence)
	if len(followUpPlan) == 0 {
		return fullPlan, allEvidence, nil
	}

	followUpEvidence, err := RunPlan(ctx, plugins, followUpPlan)
	if err != nil {
		return nil, nil, err
	}

	fullPlan = append(fullPlan, followUpPlan...)
	allEvidence = append(allEvidence, followUpEvidence...)
	return fullPlan, allEvidence, nil
}

func sortedPorts(portSet map[int]struct{}) []int {
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func classifyServiceClass(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	webPorts := map[int]struct{}{
		80: {}, 81: {}, 443: {}, 591: {}, 8000: {}, 8008: {}, 8080: {}, 8081: {}, 8443: {},
	}
	remotePorts := map[int]struct{}{
		22: {}, 23: {}, 3389: {},
	}
	directoryPorts := map[int]struct{}{
		53: {}, 88: {}, 389: {}, 445: {}, 464: {}, 636: {}, 3268: {}, 3269: {},
	}
	databasePorts := map[int]struct{}{
		1433: {}, 1521: {}, 3306: {}, 5432: {}, 6379: {}, 9042: {}, 27017: {},
	}

	switch {
	case containsAnyPort(ports, webPorts):
		return "web"
	case containsAnyPort(ports, directoryPorts):
		return "directory"
	case containsAnyPort(ports, remotePorts):
		return "remote_access"
	case containsAnyPort(ports, databasePorts):
		return "database"
	default:
		return "general"
	}
}

func containsAnyPort(ports []int, allowed map[int]struct{}) bool {
	for _, port := range ports {
		if _, ok := allowed[port]; ok {
			return true
		}
	}
	return false
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
