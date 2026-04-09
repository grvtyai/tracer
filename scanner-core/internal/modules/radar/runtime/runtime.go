package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/analysis"
	"github.com/grvtyai/tracer/scanner-core/internal/classify"
	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/arp_scan"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/avahi"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/httpx"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/ldapdomaindump"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/naabu"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/nmap"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/scamper"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/sharphound"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/snmpwalk"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/testssl"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/zeek"
	"github.com/grvtyai/tracer/scanner-core/internal/modules/radar/integrations/zgrab2"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/storage"
	"github.com/grvtyai/tracer/scanner-core/internal/templates"
)

type Output struct {
	Mode         string                        `json:"mode"`
	Template     string                        `json:"template"`
	Options      options.EffectiveOptions      `json:"options"`
	Plan         []jobs.Job                    `json:"plan"`
	JobResults   []jobs.ExecutionResult        `json:"job_results,omitempty"`
	Evidence     []evidence.Record             `json:"evidence,omitempty"`
	Blocking     []analysis.BlockingAssessment `json:"blocking,omitempty"`
	Reevaluation []analysis.ReevaluationHint   `json:"reevaluation,omitempty"`
	Persistence  *PersistenceInfo              `json:"persistence,omitempty"`
}

type PersistenceInfo struct {
	Backend     string `json:"backend"`
	DBPath      string `json:"db_path"`
	ProjectID   string `json:"project_id,omitempty"`
	ProjectName string `json:"project_name,omitempty"`
	RunID       string `json:"run_id,omitempty"`
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
		avahi.New(),
		naabu.New(),
		nmap.New(),
		scamper.New(),
		httpx.New(),
		testssl.New(),
		snmpwalk.New(),
		zgrab2.New(),
		zeek.Plugin{},
		sharphound.Plugin{},
		ldapdomaindump.Plugin{},
	}
}

func ResolveOptions(template templates.Template, overrides options.TemplateOptions) options.EffectiveOptions {
	return options.Resolve(template.Options, overrides)
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
	return BuildSeedPlanWithOptions(template, ResolveOptions(template, options.TemplateOptions{}))
}

func BuildSeedPlanWithOptions(template templates.Template, resolved options.EffectiveOptions) []jobs.Job {
	plan := jobs.BuildSeedPlan(template.Scope, template.Profile)

	if resolved.EnableAvahi {
		discoveryTargets := append(append([]string{}, template.Scope.Targets...), template.Scope.CIDRs...)
		plan = append(plan, jobs.Job{
			ID:        "local-service-discovery",
			Kind:      jobs.KindLocalService,
			Plugin:    "avahi",
			DependsOn: []string{"scope-prepare"},
			Targets:   discoveryTargets,
			Metadata: map[string]string{
				"resolve":      "true",
				"ignore_local": "true",
			},
		})
	}

	for i := range plan {
		plan[i].Metadata = mergeMetadata(plan[i].Metadata, metadataForJob(plan[i], resolved))
	}

	return plan
}

func BuildFollowUpPlan(template templates.Template, records []evidence.Record) []jobs.Job {
	return BuildFollowUpPlanWithOptions(template, records, ResolveOptions(template, options.TemplateOptions{}))
}

func BuildFollowUpPlanWithOptions(template templates.Template, records []evidence.Record, resolved options.EffectiveOptions) []jobs.Job {
	plan := make([]jobs.Job, 0)

	if metadata, ok := zeekPassiveMetadata(template, resolved); ok {
		plan = append(plan, jobs.Job{
			ID:       "zeek-ingest",
			Kind:     jobs.KindPassiveIngest,
			Plugin:   "zeek",
			Targets:  append(append([]string{}, template.Scope.Targets...), template.Scope.CIDRs...),
			Metadata: metadata,
		})
	}

	if !template.Profile.EnableServiceScan && !template.Profile.EnableRouteSampling {
		for i := range plan {
			plan[i].Metadata = mergeMetadata(plan[i].Metadata, metadataForJob(plan[i], resolved))
		}
		return plan
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

	for _, target := range targets {
		ports := sortedPorts(targetPorts[target])
		serviceClasses := classify.AllFromPorts(ports)
		primaryServiceClass := classify.FromPorts(ports)

		if template.Profile.EnableRouteSampling {
			plan = append(plan, jobs.Job{
				ID:             fmt.Sprintf("route-%s", target),
				Kind:           jobs.KindRouteProbe,
				Plugin:         "scamper",
				Targets:        []string{target},
				ServiceClass:   primaryServiceClass,
				ServiceClasses: serviceClasses,
			})
		}

		if template.Profile.EnableServiceScan && len(ports) > 0 {
			dependsOn := []string(nil)
			if template.Profile.EnableRouteSampling {
				dependsOn = []string{fmt.Sprintf("route-%s", target)}
			}

			plan = append(plan, jobs.Job{
				ID:             fmt.Sprintf("service-%s", target),
				Kind:           jobs.KindServiceProbe,
				Plugin:         "nmap",
				DependsOn:      dependsOn,
				Targets:        []string{target},
				Ports:          ports,
				ServiceClass:   primaryServiceClass,
				ServiceClasses: serviceClasses,
				Metadata: map[string]string{
					"os_detection":    boolString(template.Profile.EnableOSDetection),
					"timing_template": "4",
				},
			})
		}

		if template.Profile.EnableServiceScan {
			webPorts := filterPortsByClass(ports, "web")
			if len(webPorts) > 0 {
				dependsOn := []string(nil)
				if template.Profile.EnableServiceScan {
					dependsOn = []string{fmt.Sprintf("service-%s", target)}
				} else if template.Profile.EnableRouteSampling {
					dependsOn = []string{fmt.Sprintf("route-%s", target)}
				}

				plan = append(plan, jobs.Job{
					ID:             fmt.Sprintf("http-%s", target),
					Kind:           jobs.KindWebProbe,
					Plugin:         "httpx",
					DependsOn:      dependsOn,
					Targets:        []string{target},
					Ports:          webPorts,
					ServiceClass:   classify.FromPorts(webPorts),
					ServiceClasses: classify.AllFromPorts(webPorts),
					Metadata: map[string]string{
						"tech_detect":                "true",
						"follow_redirects":           "true",
						"host_primary_service_class": primaryServiceClass,
						"host_service_classes":       strings.Join(serviceClasses, ","),
						"timeout":                    "10",
						"retries":                    "1",
					},
				})

				plan = append(plan, jobs.Job{
					ID:             fmt.Sprintf("grab-%s", target),
					Kind:           jobs.KindGrabProbe,
					Plugin:         "zgrab2",
					DependsOn:      []string{fmt.Sprintf("http-%s", target)},
					Targets:        []string{target},
					Ports:          webPorts,
					ServiceClass:   classify.FromPorts(webPorts),
					ServiceClasses: classify.AllFromPorts(webPorts),
					Metadata: map[string]string{
						"module":                     "http",
						"max_redirects":              "1",
						"host_primary_service_class": primaryServiceClass,
						"host_service_classes":       strings.Join(serviceClasses, ","),
						"timeout":                    "10",
					},
				})
			}

			if resolved.EnableTestSSL {
				tlsPorts := filterLikelyTLSPorts(ports)
				if len(tlsPorts) > 0 {
					dependsOn := []string(nil)
					if template.Profile.EnableServiceScan {
						dependsOn = []string{fmt.Sprintf("service-%s", target)}
					}
					if len(webPorts) > 0 {
						dependsOn = []string{fmt.Sprintf("http-%s", target)}
					}

					plan = append(plan, jobs.Job{
						ID:             fmt.Sprintf("tls-%s", target),
						Kind:           jobs.KindTLSInspect,
						Plugin:         "testssl",
						DependsOn:      dependsOn,
						Targets:        []string{target},
						Ports:          tlsPorts,
						ServiceClass:   classify.FromPorts(tlsPorts),
						ServiceClasses: classify.AllFromPorts(tlsPorts),
						Metadata: map[string]string{
							"severity":                   "LOW",
							"host_primary_service_class": primaryServiceClass,
							"host_service_classes":       strings.Join(serviceClasses, ","),
						},
					})
				}
			}
		}

		if resolved.EnableSNMP {
			dependsOn := []string(nil)
			if template.Profile.EnableServiceScan {
				dependsOn = []string{fmt.Sprintf("service-%s", target)}
			} else if template.Profile.EnableRouteSampling {
				dependsOn = []string{fmt.Sprintf("route-%s", target)}
			}

			plan = append(plan, jobs.Job{
				ID:             fmt.Sprintf("snmp-%s", target),
				Kind:           jobs.KindSNMPProbe,
				Plugin:         "snmpwalk",
				DependsOn:      dependsOn,
				Targets:        []string{target},
				ServiceClass:   primaryServiceClass,
				ServiceClasses: serviceClasses,
				Metadata: map[string]string{
					"community":                  "public",
					"version":                    "2c",
					"timeout":                    "2",
					"retries":                    "0",
					"host_primary_service_class": primaryServiceClass,
					"host_service_classes":       strings.Join(serviceClasses, ","),
				},
			})
		}
	}

	for i := range plan {
		plan[i].Metadata = mergeMetadata(plan[i].Metadata, metadataForJob(plan[i], resolved))
	}

	return plan
}

func RunPlan(ctx context.Context, plugins []engine.Plugin, plan []jobs.Job) ([]evidence.Record, error) {
	records, _, err := RunPlanWithOptions(ctx, plugins, plan, options.DefaultEffectiveOptions())
	return records, err
}

func RunPlanWithOptions(ctx context.Context, plugins []engine.Plugin, plan []jobs.Job, resolved options.EffectiveOptions) ([]evidence.Record, []jobs.ExecutionResult, error) {
	return RunPlanWithPersistence(ctx, plugins, plan, resolved, nil)
}

func RunPlanWithPersistence(ctx context.Context, plugins []engine.Plugin, plan []jobs.Job, resolved options.EffectiveOptions, persistentStore storage.EvidenceStore) ([]evidence.Record, []jobs.ExecutionResult, error) {
	store := storage.NewMemoryStore()
	compositeStore := storage.EvidenceStore(store)
	if persistentStore != nil {
		compositeStore = storage.NewMultiStore(store, persistentStore)
	}
	runtime := engine.New(plugins, compositeStore)

	runOptions := engine.DefaultRunOptions()
	runOptions.ContinueOnError = resolved.ContinueOnError
	runOptions.RetainPartialResult = resolved.RetainPartialResults
	runOptions.ReevaluateFailures = resolved.ReevaluateAmbiguous
	runOptions.ReevaluateAfter = resolved.ReevaluateAfter

	jobResults := runtime.Run(ctx, plan, runOptions)
	return store.Records(), jobResults, nil
}

func ExecuteRun(ctx context.Context, plugins []engine.Plugin, template templates.Template) ([]jobs.Job, []evidence.Record, error) {
	plan, _, records, err := ExecuteRunWithOptions(ctx, plugins, template, ResolveOptions(template, options.TemplateOptions{}))
	return plan, records, err
}

func ExecuteRunWithOptions(ctx context.Context, plugins []engine.Plugin, template templates.Template, resolved options.EffectiveOptions) ([]jobs.Job, []jobs.ExecutionResult, []evidence.Record, error) {
	return ExecuteRunWithPersistence(ctx, plugins, template, resolved, nil)
}

func ExecuteRunWithPersistence(ctx context.Context, plugins []engine.Plugin, template templates.Template, resolved options.EffectiveOptions, persistentStore storage.EvidenceStore) ([]jobs.Job, []jobs.ExecutionResult, []evidence.Record, error) {
	runStartedAt := time.Now().UTC()
	seedPlan := BuildSeedPlanWithOptions(template, resolved)
	seedEvidence, seedResults, err := RunPlanWithPersistence(ctx, plugins, seedPlan, resolved, persistentStore)
	if err != nil {
		return nil, nil, nil, err
	}
	seedEvidence = dedupeEvidence(seedEvidence)
	seedResults = dedupeJobResults(seedResults)

	fullPlan := append([]jobs.Job{}, seedPlan...)
	allResults := append([]jobs.ExecutionResult{}, seedResults...)
	allEvidence := append([]evidence.Record{}, seedEvidence...)

	followUpPlan := BuildFollowUpPlanWithOptions(template, seedEvidence, resolved)
	annotatePassivePlan(followUpPlan, runStartedAt)
	if len(followUpPlan) == 0 {
		return fullPlan, allResults, allEvidence, nil
	}

	followUpEvidence, followUpResults, err := RunPlanWithPersistence(ctx, plugins, followUpPlan, resolved, persistentStore)
	if err != nil {
		return nil, nil, nil, err
	}
	followUpEvidence = dedupeEvidence(followUpEvidence)
	followUpResults = dedupeJobResults(followUpResults)

	fullPlan = append(fullPlan, followUpPlan...)
	allResults = append(allResults, followUpResults...)
	allResults = dedupeJobResults(allResults)
	allEvidence = append(allEvidence, followUpEvidence...)
	allEvidence = dedupeEvidence(allEvidence)
	return fullPlan, allResults, allEvidence, nil
}

func AnalyzeEvidence(records []evidence.Record) []analysis.BlockingAssessment {
	return analysis.BuildBlockingAssessments(records)
}

func BuildReevaluation(records []evidence.Record, results []jobs.ExecutionResult, resolved options.EffectiveOptions) []analysis.ReevaluationHint {
	return analysis.BuildReevaluationHints(results, AnalyzeEvidence(records), resolved.ReevaluateAfter)
}

func sortedPorts(portSet map[int]struct{}) []int {
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func filterPortsByClass(ports []int, class string) []int {
	filtered := make([]int, 0)
	for _, port := range ports {
		if classify.FromPort(port) != class {
			continue
		}
		filtered = append(filtered, port)
	}
	return filtered
}

func filterLikelyTLSPorts(ports []int) []int {
	filtered := make([]int, 0)
	for _, port := range ports {
		switch port {
		case 443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 8443, 9443, 10443:
			filtered = append(filtered, port)
		}
	}
	return filtered
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func dedupeEvidence(records []evidence.Record) []evidence.Record {
	seen := make(map[string]struct{}, len(records))
	deduped := make([]evidence.Record, 0, len(records))

	for _, record := range records {
		key := evidenceKey(record)
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		deduped = append(deduped, record)
	}

	return deduped
}

func evidenceKey(record evidence.Record) string {
	if strings.TrimSpace(record.ID) != "" {
		return record.ID
	}

	return strings.Join([]string{
		record.Source,
		record.Kind,
		record.Target,
		record.Protocol,
		fmt.Sprintf("%d", record.Port),
	}, "|")
}

func dedupeJobResults(results []jobs.ExecutionResult) []jobs.ExecutionResult {
	seen := make(map[string]struct{}, len(results))
	deduped := make([]jobs.ExecutionResult, 0, len(results))

	for _, result := range results {
		key := result.JobID + "|" + string(result.Status)
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		deduped = append(deduped, result)
	}

	return deduped
}

func metadataForJob(job jobs.Job, resolved options.EffectiveOptions) map[string]string {
	metadata := map[string]string{}

	switch job.Kind {
	case jobs.KindPassiveIngest:
		if resolved.PassiveInterface != "" {
			metadata["passive_interface"] = resolved.PassiveInterface
		}
	default:
		if resolved.ActiveInterface != "" {
			metadata["active_interface"] = resolved.ActiveInterface
		}
	}

	if resolved.PortTemplate != "" {
		metadata["port_template"] = resolved.PortTemplate
	}

	if len(metadata) == 0 {
		return nil
	}

	return metadata
}

func mergeMetadata(base map[string]string, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}

	merged := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}

	return merged
}

func annotatePassivePlan(plan []jobs.Job, runStartedAt time.Time) {
	if runStartedAt.IsZero() {
		return
	}

	for i := range plan {
		if plan[i].Kind != jobs.KindPassiveIngest {
			continue
		}

		plan[i].Metadata = mergeMetadata(plan[i].Metadata, map[string]string{
			"run_started_at": runStartedAt.Format(time.RFC3339Nano),
		})
	}
}

func zeekPassiveMetadata(template templates.Template, resolved options.EffectiveOptions) (map[string]string, bool) {
	mode := normalizePassiveMode(resolved.PassiveMode)
	if mode == "off" {
		return nil, false
	}

	logDir := strings.TrimSpace(resolved.ZeekLogDir)
	if logDir == "" {
		logDir = strings.TrimSpace(template.Profile.ZeekLogDir)
	}

	passiveRequested := template.Profile.EnablePassiveIngest || resolved.PassiveInterface != "" || logDir != "" || mode == "always"
	if !passiveRequested {
		return nil, false
	}

	if mode == "auto" && logDir == "" && resolved.PassiveInterface == "" {
		return nil, false
	}

	metadata := map[string]string{
		"zeek_mode":       mode,
		"zeek_auto_start": boolString(resolved.AutoStartZeek),
	}

	if logDir != "" {
		metadata["zeek_log_dir"] = logDir
	}

	return metadata, true
}

func normalizePassiveMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return "auto"
	case "always", "force", "on":
		return "always"
	case "off", "disabled", "false":
		return "off"
	default:
		return "auto"
	}
}
