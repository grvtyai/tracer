package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/templates"
)

func TestLoadTemplateAndBuildSeedPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.json")

	template := templates.Template{
		Name:        "test",
		Description: "seed plan template",
		Scope: ingest.Scope{
			Name:    "scope",
			CIDRs:   []string{"192.168.1.0/24"},
			Targets: []string{"192.168.1.10"},
		},
		Profile: ingest.RunProfile{
			Name:         "default",
			EnableLayer2: true,
		},
	}

	data, err := json.Marshal(template)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	loaded, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("LoadTemplate returned error: %v", err)
	}

	plan := BuildSeedPlan(loaded)
	if len(plan) != 3 {
		t.Fatalf("expected 3 jobs, got %d", len(plan))
	}

	if plan[0].Plugin != "internal" {
		t.Fatalf("expected internal scope plugin, got %q", plan[0].Plugin)
	}

	if plan[2].Plugin != "naabu" {
		t.Fatalf("expected naabu plugin, got %q", plan[2].Plugin)
	}
}

func TestRunPlanStoresEvidence(t *testing.T) {
	plan := []jobs.Job{
		{
			ID:      "scope-prepare",
			Kind:    jobs.KindScopePrepare,
			Plugin:  "internal",
			Targets: []string{"10.0.0.10"},
		},
		{
			ID:      "port-discovery",
			Kind:    jobs.KindPortDiscover,
			Plugin:  "naabu",
			Targets: []string{"10.0.0.10"},
		},
	}

	records, err := RunPlan(context.Background(), []engine.Plugin{anyPlugin{name: "naabu"}}, plan)
	if err == nil {
		t.Fatal("expected missing internal plugin error")
	}

	records, err = RunPlan(context.Background(), []engine.Plugin{
		anyPlugin{name: "internal"},
		anyPlugin{name: "naabu"},
	}, plan)
	if err != nil {
		t.Fatalf("RunPlan returned error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].Source != "naabu" {
		t.Fatalf("expected naabu evidence, got %q", records[0].Source)
	}
}

func TestBuildFollowUpPlanFromOpenPorts(t *testing.T) {
	template := templates.Template{
		Name: "test",
		Profile: ingest.RunProfile{
			EnableRouteSampling: true,
			EnableServiceScan:   true,
			EnableOSDetection:   true,
		},
	}

	records := []evidence.Record{
		{
			ID:       "open-1",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "10.0.0.20",
			Port:     443,
			Protocol: "tcp",
		},
		{
			ID:       "open-2",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "10.0.0.20",
			Port:     80,
			Protocol: "tcp",
		},
		{
			ID:       "open-3",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "10.0.0.20",
			Port:     443,
			Protocol: "tcp",
		},
		{
			ID:       "open-4",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "10.0.0.30",
			Port:     22,
			Protocol: "tcp",
		},
		{
			ID:       "open-5",
			Source:   "naabu",
			Kind:     "open_port",
			Target:   "10.0.0.40",
			Port:     53,
			Protocol: "udp",
		},
	}

	plan := BuildFollowUpPlan(template, records)
	if len(plan) != 6 {
		t.Fatalf("expected 6 follow-up jobs, got %d", len(plan))
	}

	if plan[0].Plugin != "scamper" || plan[1].Plugin != "nmap" {
		t.Fatalf("unexpected first target plan order: %#v", plan[:2])
	}
	if plan[2].Plugin != "httpx" {
		t.Fatalf("expected httpx web follow-up, got %#v", plan[2])
	}
	if plan[3].Plugin != "zgrab2" {
		t.Fatalf("expected zgrab2 web follow-up, got %#v", plan[3])
	}

	if !reflect.DeepEqual(plan[1].Ports, []int{80, 443}) {
		t.Fatalf("expected deduplicated sorted ports, got %#v", plan[1].Ports)
	}
	if !reflect.DeepEqual(plan[2].Ports, []int{80, 443}) {
		t.Fatalf("expected httpx to inherit web ports, got %#v", plan[2].Ports)
	}
	if !reflect.DeepEqual(plan[3].Ports, []int{80, 443}) {
		t.Fatalf("expected zgrab2 to inherit web ports, got %#v", plan[3].Ports)
	}
	if plan[2].Metadata["host_primary_service_class"] != "web" {
		t.Fatalf("expected host_primary_service_class in web job metadata, got %#v", plan[2].Metadata)
	}
	if plan[2].Metadata["host_service_classes"] != "web" {
		t.Fatalf("expected host_service_classes in web job metadata, got %#v", plan[2].Metadata)
	}

	if plan[1].ServiceClass != "web" {
		t.Fatalf("expected web service class, got %q", plan[1].ServiceClass)
	}
	if !reflect.DeepEqual(plan[1].ServiceClasses, []string{"web"}) {
		t.Fatalf("expected service_classes [web], got %#v", plan[1].ServiceClasses)
	}

	if plan[1].Metadata["os_detection"] != "true" {
		t.Fatalf("expected os_detection metadata, got %#v", plan[1].Metadata)
	}

	if plan[5].ServiceClass != "remote_access" {
		t.Fatalf("expected remote_access class, got %q", plan[5].ServiceClass)
	}
}

func TestBuildFollowUpPlanIncludesZeekIngestWhenConfigured(t *testing.T) {
	template := templates.Template{
		Name: "test",
		Scope: ingest.Scope{
			Targets: []string{"10.0.0.10"},
		},
		Profile: ingest.RunProfile{
			EnablePassiveIngest: true,
			ZeekLogDir:          "/var/log/zeek/current",
		},
	}

	plan := BuildFollowUpPlan(template, nil)
	if len(plan) != 1 {
		t.Fatalf("expected 1 follow-up job, got %d", len(plan))
	}

	if plan[0].Plugin != "zeek" || plan[0].Kind != jobs.KindPassiveIngest {
		t.Fatalf("unexpected zeek follow-up job: %#v", plan[0])
	}
	if plan[0].Metadata["zeek_log_dir"] != "/var/log/zeek/current" {
		t.Fatalf("expected zeek log dir metadata, got %#v", plan[0].Metadata)
	}
}

func TestExecuteRunChainsSeedAndFollowUpPlans(t *testing.T) {
	template := templates.Template{
		Name: "test",
		Scope: ingest.Scope{
			Targets: []string{"10.0.0.10"},
		},
		Profile: ingest.RunProfile{
			EnableServiceScan: true,
			EnableOSDetection: true,
		},
	}

	plan, records, err := ExecuteRun(context.Background(), []engine.Plugin{
		anyPlugin{name: "internal"},
		anyPlugin{name: "naabu"},
		anyPlugin{name: "nmap"},
		anyPlugin{name: "httpx"},
		anyPlugin{name: "zgrab2"},
	}, template)
	if err != nil {
		t.Fatalf("ExecuteRun returned error: %v", err)
	}

	if len(plan) != 5 {
		t.Fatalf("expected 5 jobs total, got %d", len(plan))
	}

	if plan[2].Plugin != "nmap" || plan[3].Plugin != "httpx" || plan[4].Plugin != "zgrab2" {
		t.Fatalf("expected nmap, httpx and zgrab2 follow-up jobs, got %#v", plan[2:])
	}

	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	if records[1].Source != "nmap" || records[2].Source != "httpx" || records[3].Source != "zgrab2" {
		t.Fatalf("expected nmap, httpx, zgrab2 evidence, got %q / %q / %q", records[1].Source, records[2].Source, records[3].Source)
	}
}

func TestExecuteRunDedupesEvidence(t *testing.T) {
	template := templates.Template{
		Name: "test",
		Scope: ingest.Scope{
			Targets: []string{"10.0.0.10"},
		},
		Profile: ingest.RunProfile{
			EnableServiceScan: true,
		},
	}

	plan, records, err := ExecuteRun(context.Background(), []engine.Plugin{
		anyPlugin{name: "internal"},
		duplicateNaabuPlugin{name: "naabu"},
		anyPlugin{name: "nmap"},
		anyPlugin{name: "httpx"},
		anyPlugin{name: "zgrab2"},
	}, template)
	if err != nil {
		t.Fatalf("ExecuteRun returned error: %v", err)
	}

	if len(plan) != 5 {
		t.Fatalf("expected 5 jobs total, got %d", len(plan))
	}

	if len(records) != 4 {
		t.Fatalf("expected deduped evidence count 4, got %d", len(records))
	}
}

func TestDedupeEvidenceKeepsDistinctIDs(t *testing.T) {
	records := []evidence.Record{
		{ID: "hop-1", Source: "scamper", Kind: "route_hop", Target: "10.0.0.10", Protocol: "ip"},
		{ID: "hop-2", Source: "scamper", Kind: "route_hop", Target: "10.0.0.10", Protocol: "ip"},
		{ID: "hop-1", Source: "scamper", Kind: "route_hop", Target: "10.0.0.10", Protocol: "ip"},
	}

	got := dedupeEvidence(records)
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped records, got %d", len(got))
	}
}

type anyPlugin struct {
	name string
}

func (p anyPlugin) Name() string {
	return p.name
}

func (p anyPlugin) CanRun(job jobs.Job) bool {
	switch p.name {
	case "internal":
		return job.Kind == jobs.KindScopePrepare
	case "naabu":
		return job.Kind == jobs.KindPortDiscover
	case "nmap":
		return job.Kind == jobs.KindServiceProbe
	case "httpx":
		return job.Kind == jobs.KindWebProbe
	case "zgrab2":
		return job.Kind == jobs.KindGrabProbe
	case "zeek":
		return job.Kind == jobs.KindPassiveIngest
	default:
		return false
	}
}

func (p anyPlugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	if p.name == "internal" {
		return nil, nil
	}

	if p.name == "nmap" {
		return []evidence.Record{
			{
				ID:         "service-record",
				Source:     p.name,
				Kind:       "service_fingerprint",
				Target:     "10.0.0.10",
				Port:       443,
				Protocol:   "tcp",
				Summary:    "https detected on tcp/443 at 10.0.0.10",
				Confidence: evidence.ConfidenceConfirmed,
				ObservedAt: time.Date(2026, 4, 1, 8, 5, 0, 0, time.UTC),
			},
		}, nil
	}

	if p.name == "httpx" {
		return []evidence.Record{
			{
				ID:         "http-record",
				Source:     p.name,
				Kind:       "http_probe",
				Target:     "10.0.0.10",
				Port:       443,
				Protocol:   "tcp",
				Summary:    "https://10.0.0.10 returned HTTP 200",
				Confidence: evidence.ConfidenceConfirmed,
				ObservedAt: time.Date(2026, 4, 1, 8, 6, 0, 0, time.UTC),
			},
		}, nil
	}

	if p.name == "zgrab2" {
		return []evidence.Record{
			{
				ID:         "grab-record",
				Source:     p.name,
				Kind:       "l7_grab",
				Target:     "10.0.0.10",
				Port:       443,
				Protocol:   "tcp",
				Summary:    "https://10.0.0.10:443 returned HTTP 200",
				Confidence: evidence.ConfidenceConfirmed,
				ObservedAt: time.Date(2026, 4, 1, 8, 7, 0, 0, time.UTC),
			},
		}, nil
	}

	if p.name == "zeek" {
		return []evidence.Record{
			{
				ID:         "zeek-record",
				Source:     p.name,
				Kind:       "passive_http",
				Target:     "10.0.0.10",
				Port:       443,
				Protocol:   "tcp",
				Summary:    "zeek observed HTTP traffic to 10.0.0.10",
				Confidence: evidence.ConfidenceConfirmed,
				ObservedAt: time.Date(2026, 4, 1, 8, 8, 0, 0, time.UTC),
			},
		}, nil
	}

	return []evidence.Record{
		{
			ID:         "port-record",
			Source:     p.name,
			Kind:       "open_port",
			Target:     "10.0.0.10",
			Port:       443,
			Protocol:   "tcp",
			Summary:    "open tcp port 443 on 10.0.0.10",
			Confidence: evidence.ConfidenceConfirmed,
			ObservedAt: time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC),
		},
	}, nil
}

type duplicateNaabuPlugin struct {
	name string
}

func (p duplicateNaabuPlugin) Name() string {
	return p.name
}

func (p duplicateNaabuPlugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindPortDiscover
}

func (p duplicateNaabuPlugin) Run(context.Context, jobs.Job) ([]evidence.Record, error) {
	record := evidence.Record{
		ID:         "port-record",
		Source:     p.name,
		Kind:       "open_port",
		Target:     "10.0.0.10",
		Port:       443,
		Protocol:   "tcp",
		Summary:    "open tcp port 443 on 10.0.0.10",
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC),
	}

	return []evidence.Record{record, record}, nil
}
