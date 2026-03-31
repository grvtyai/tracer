package jobs

import (
	"fmt"

	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
)

// BuildSeedPlan creates the low-cost opening moves of a run.
func BuildSeedPlan(scope ingest.Scope, profile ingest.RunProfile) []Job {
	plan := []Job{
		{
			ID:     "scope-prepare",
			Kind:   KindScopePrepare,
			Plugin: "internal",
			Targets: append(
				append([]string{}, scope.Targets...),
				scope.CIDRs...,
			),
		},
	}

	if profile.EnableLayer2 {
		plan = append(plan, Job{
			ID:        "l2-discovery",
			Kind:      KindL2Discover,
			Plugin:    "arp-scan",
			DependsOn: []string{"scope-prepare"},
			Targets:   append([]string{}, scope.CIDRs...),
		})
	}

	plan = append(plan, Job{
		ID:        "port-discovery",
		Kind:      KindPortDiscover,
		Plugin:    "naabu",
		DependsOn: dependencyIDs(plan),
		Targets: append(
			append([]string{}, scope.Targets...),
			scope.CIDRs...,
		),
	})

	return plan
}

// BuildFollowUpPlan builds higher-cost jobs only from already useful findings.
func BuildFollowUpPlan(target string, ports []int, serviceClass string) []Job {
	plan := []Job{
		{
			ID:           fmt.Sprintf("route-%s", target),
			Kind:         KindRouteProbe,
			Plugin:       "scamper",
			Targets:      []string{target},
			ServiceClass: serviceClass,
		},
	}

	if len(ports) > 0 {
		plan = append(plan, Job{
			ID:        fmt.Sprintf("service-%s", target),
			Kind:      KindServiceProbe,
			Plugin:    "nmap",
			DependsOn: []string{fmt.Sprintf("route-%s", target)},
			Targets:   []string{target},
			Ports:     append([]int{}, ports...),
		})
	}

	return plan
}

func dependencyIDs(plan []Job) []string {
	ids := make([]string, 0, len(plan))
	for _, job := range plan {
		ids = append(ids, job.ID)
	}

	return ids
}
