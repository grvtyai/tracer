package options

import "testing"

func TestResolveDefaultsAndOverrides(t *testing.T) {
	baseContinue := false
	overrideReevaluate := false
	baseAutoStartZeek := false

	base := TemplateOptions{
		Execution: ExecutionOptions{
			ContinueOnError: &baseContinue,
			ReevaluateAfter: "45m",
		},
		Network: NetworkOptions{
			ActiveInterface: "eth0",
		},
		Sensors: SensorOptions{
			PassiveMode:   "always",
			AutoStartZeek: &baseAutoStartZeek,
			ZeekLogDir:    "/var/log/zeek/current",
		},
	}

	overrides := TemplateOptions{
		Execution: ExecutionOptions{
			ReevaluateAmbiguous: &overrideReevaluate,
		},
		Network: NetworkOptions{
			PassiveInterface: "eth1",
		},
		Scan: ScanOptions{
			PortTemplate: "all-default-ports",
		},
		Storage: StorageOptions{
			Project: "Standort A",
			DBPath:  "/tmp/tracer.db",
		},
	}

	got := Resolve(base, overrides)
	if got.ContinueOnError {
		t.Fatalf("expected continue_on_error override from base to be false, got %#v", got)
	}
	if got.ReevaluateAfter != "45m" {
		t.Fatalf("expected reevaluate_after from base, got %#v", got)
	}
	if got.ReevaluateAmbiguous {
		t.Fatalf("expected reevaluate_ambiguous override to be false, got %#v", got)
	}
	if got.ActiveInterface != "eth0" || got.PassiveInterface != "eth1" {
		t.Fatalf("unexpected interfaces in resolved options: %#v", got)
	}
	if got.PortTemplate != "all-default-ports" {
		t.Fatalf("expected port template override, got %#v", got)
	}
	if got.PassiveMode != "always" || got.AutoStartZeek || got.ZeekLogDir != "/var/log/zeek/current" {
		t.Fatalf("expected sensor settings from base, got %#v", got)
	}
	if got.Project != "Standort A" || got.DBPath != "/tmp/tracer.db" {
		t.Fatalf("expected storage overrides, got %#v", got)
	}
}
