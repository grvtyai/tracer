package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/grvtyai/tracer/scanner-core/internal/app"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/storage"
)

func main() {
	var (
		mode                string
		template            string
		activeInterface     string
		passiveInterface    string
		portTemplate        string
		projectName         string
		dataDir             string
		dbPath              string
		reevaluateAfter     string
		continueOnErrorFlag optionalBool
		retainPartialFlag   optionalBool
		reevaluateFlag      optionalBool
	)

	flag.StringVar(&mode, "mode", "plan", "execution mode: plan or run")
	flag.StringVar(&template, "template", "examples/phase1-template.json", "path to a JSON template file")
	flag.StringVar(&activeInterface, "active-interface", "", "preferred active scan interface")
	flag.StringVar(&passiveInterface, "passive-interface", "", "preferred passive capture interface")
	flag.StringVar(&portTemplate, "port-template", "", "named port selection/profile template")
	flag.StringVar(&projectName, "project", "", "logical project name for persisted scan data")
	flag.StringVar(&dataDir, "data-dir", "", "directory for tracer persistent data")
	flag.StringVar(&dbPath, "db-path", "", "path to the SQLite database file")
	flag.StringVar(&reevaluateAfter, "reevaluate-after", "", "duration hint for reevaluating ambiguous or failed results")
	flag.Var(&continueOnErrorFlag, "continue-on-error", "continue when a host or plugin slice fails (true/false)")
	flag.Var(&retainPartialFlag, "retain-partial-results", "retain partial evidence even if later steps fail (true/false)")
	flag.Var(&reevaluateFlag, "reevaluate-ambiguous", "emit reevaluation hints for ambiguous or partial results (true/false)")
	flag.Parse()

	loadedTemplate, err := app.LoadTemplate(template)
	if err != nil {
		fail(err)
	}

	overrides := buildOptionOverrides(activeInterface, passiveInterface, portTemplate, projectName, dataDir, dbPath, reevaluateAfter, continueOnErrorFlag, retainPartialFlag, reevaluateFlag)
	effectiveOptions := app.ResolveOptions(loadedTemplate, overrides)
	if effectiveOptions.Project == "" {
		effectiveOptions.Project = loadedTemplate.Name
	}
	if effectiveOptions.DBPath == "" {
		if effectiveOptions.DataDir != "" {
			effectiveOptions.DBPath = filepath.Join(effectiveOptions.DataDir, "tracer.db")
		} else {
			effectiveOptions.DBPath = storage.DefaultDBPath()
		}
	}
	plan := app.BuildSeedPlanWithOptions(loadedTemplate, effectiveOptions)
	output := app.Output{
		Mode:     mode,
		Template: template,
		Options:  effectiveOptions,
		Plan:     plan,
	}

	switch mode {
	case "plan":
	case "run":
		repository, err := storage.OpenSQLite(effectiveOptions.DBPath)
		if err != nil {
			fail(err)
		}
		defer repository.Close()

		project, err := repository.EnsureProject(context.Background(), effectiveOptions.Project, "")
		if err != nil {
			fail(err)
		}

		runRecord, runStore, err := repository.StartRun(context.Background(), project.ID, storage.RunSpec{
			TemplateName: loadedTemplate.Name,
			TemplatePath: template,
			Mode:         mode,
			Scope:        loadedTemplate.Scope,
			Profile:      loadedTemplate.Profile,
			Options:      effectiveOptions,
		})
		if err != nil {
			fail(err)
		}

		executedPlan, jobResults, records, err := app.ExecuteRunWithPersistence(context.Background(), app.DefaultPlugins(), loadedTemplate, effectiveOptions, runStore)
		if err != nil {
			fail(err)
		}
		output.Plan = executedPlan
		output.JobResults = jobResults
		output.Evidence = records
		output.Blocking = app.AnalyzeEvidence(records)
		output.Reevaluation = app.BuildReevaluation(records, jobResults, effectiveOptions)
		output.Persistence = &app.PersistenceInfo{
			Backend:     "sqlite",
			DBPath:      effectiveOptions.DBPath,
			ProjectID:   project.ID,
			ProjectName: project.Name,
			RunID:       runRecord.ID,
		}

		if err := repository.CompleteRun(context.Background(), runRecord.ID, storage.RunCompletion{
			Status:       summarizeRunStatus(jobResults),
			Plan:         executedPlan,
			Blocking:     output.Blocking,
			Reevaluation: output.Reevaluation,
		}); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unsupported mode %q", mode))
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "tracer: %v\n", err)
	os.Exit(1)
}

type optionalBool struct {
	set   bool
	value bool
}

func (o *optionalBool) String() string {
	if !o.set {
		return ""
	}
	return strconv.FormatBool(o.value)
}

func (o *optionalBool) Set(value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	o.set = true
	o.value = parsed
	return nil
}

func buildOptionOverrides(activeInterface string, passiveInterface string, portTemplate string, project string, dataDir string, dbPath string, reevaluateAfter string, continueOnError optionalBool, retainPartial optionalBool, reevaluate optionalBool) options.TemplateOptions {
	overrides := options.TemplateOptions{}

	if activeInterface != "" {
		overrides.Network.ActiveInterface = activeInterface
	}
	if passiveInterface != "" {
		overrides.Network.PassiveInterface = passiveInterface
	}
	if portTemplate != "" {
		overrides.Scan.PortTemplate = portTemplate
	}
	if project != "" {
		overrides.Storage.Project = project
	}
	if dataDir != "" {
		overrides.Storage.DataDir = dataDir
	}
	if dbPath != "" {
		overrides.Storage.DBPath = dbPath
	}
	if reevaluateAfter != "" {
		overrides.Execution.ReevaluateAfter = reevaluateAfter
	}
	if continueOnError.set {
		value := continueOnError.value
		overrides.Execution.ContinueOnError = &value
	}
	if retainPartial.set {
		value := retainPartial.value
		overrides.Execution.RetainPartialResults = &value
	}
	if reevaluate.set {
		value := reevaluate.value
		overrides.Execution.ReevaluateAmbiguous = &value
	}

	return overrides
}

func summarizeRunStatus(results []jobs.ExecutionResult) string {
	for _, result := range results {
		if result.Status == jobs.StatusFailed {
			return "partial"
		}
	}
	return "completed"
}
