package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	radarruntime "github.com/grvtyai/tracer/scanner-core/internal/modules/radar/runtime"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/platform"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/storage"
	"github.com/grvtyai/tracer/scanner-core/internal/templates"
)

func main() {
	var (
		mode                string
		template            string
		runID               string
		baselineRunID       string
		candidateRunID      string
		activeInterface     string
		passiveInterface    string
		portTemplate        string
		passiveMode         string
		zeekLogDir          string
		projectName         string
		dataDir             string
		dbPath              string
		reevaluateAfter     string
		continueOnErrorFlag optionalBool
		retainPartialFlag   optionalBool
		reevaluateFlag      optionalBool
		autoStartZeekFlag   optionalBool
	)

	flag.StringVar(&mode, "mode", "plan", "execution mode: plan, run, execute-run, projects, runs, show-run, or diff")
	flag.StringVar(&template, "template", "examples/phase1-template.json", "path to a JSON template file")
	flag.StringVar(&runID, "run-id", "", "run identifier for show-run")
	flag.StringVar(&baselineRunID, "baseline-run", "", "baseline run identifier for diff mode")
	flag.StringVar(&candidateRunID, "candidate-run", "", "candidate run identifier for diff mode")
	flag.StringVar(&activeInterface, "active-interface", "", "preferred active scan interface")
	flag.StringVar(&passiveInterface, "passive-interface", "", "preferred passive capture interface")
	flag.StringVar(&portTemplate, "port-template", "", "named port selection/profile template")
	flag.StringVar(&passiveMode, "passive-mode", "", "passive sensor mode: off, auto, or always")
	flag.StringVar(&zeekLogDir, "zeek-log-dir", "", "Zeek log directory override")
	flag.StringVar(&projectName, "project", "", "logical project name for persisted scan data")
	flag.StringVar(&dataDir, "data-dir", "", "directory for tracer persistent data")
	flag.StringVar(&dbPath, "db-path", "", "path to the SQLite database file")
	flag.StringVar(&reevaluateAfter, "reevaluate-after", "", "duration hint for reevaluating ambiguous or failed results")
	flag.Var(&continueOnErrorFlag, "continue-on-error", "continue when a host or plugin slice fails (true/false)")
	flag.Var(&retainPartialFlag, "retain-partial-results", "retain partial evidence even if later steps fail (true/false)")
	flag.Var(&reevaluateFlag, "reevaluate-ambiguous", "emit reevaluation hints for ambiguous or partial results (true/false)")
	flag.Var(&autoStartZeekFlag, "auto-start-zeek", "allow tracer to start or deploy Zeek when passive ingest is requested (true/false)")
	flag.Parse()

	if err := platform.RequireRootOnLinux("tracer"); err != nil {
		fail(err)
	}

	queryDBPath := storage.ResolveDBPath(dataDir, dbPath)

	switch mode {
	case "projects":
		repository, err := storage.OpenSQLite(queryDBPath)
		if err != nil {
			fail(err)
		}
		defer repository.Close()

		projects, err := repository.ListProjects(context.Background())
		if err != nil {
			fail(err)
		}

		emitJSON(queryOutput{
			Mode:        mode,
			Persistence: &radarruntime.PersistenceInfo{Backend: "sqlite", DBPath: repository.Path()},
			Projects:    projects,
		})
		return
	case "runs":
		repository, err := storage.OpenSQLite(queryDBPath)
		if err != nil {
			fail(err)
		}
		defer repository.Close()

		runs, err := repository.ListRuns(context.Background(), projectName)
		if err != nil {
			fail(err)
		}

		emitJSON(queryOutput{
			Mode:          mode,
			ProjectFilter: projectName,
			Persistence:   &radarruntime.PersistenceInfo{Backend: "sqlite", DBPath: repository.Path()},
			Runs:          runs,
		})
		return
	case "show-run":
		if runID == "" {
			fail(fmt.Errorf("show-run mode requires --run-id"))
		}

		repository, err := storage.OpenSQLite(queryDBPath)
		if err != nil {
			fail(err)
		}
		defer repository.Close()

		run, err := repository.GetRun(context.Background(), runID)
		if err != nil {
			fail(err)
		}

		emitJSON(queryOutput{
			Mode:        mode,
			Persistence: &radarruntime.PersistenceInfo{Backend: "sqlite", DBPath: repository.Path(), ProjectID: run.Run.ProjectID, ProjectName: run.Run.ProjectName, RunID: run.Run.ID},
			Run:         &run,
		})
		return
	case "diff":
		if baselineRunID == "" || candidateRunID == "" {
			fail(fmt.Errorf("diff mode requires --baseline-run and --candidate-run"))
		}

		repository, err := storage.OpenSQLite(queryDBPath)
		if err != nil {
			fail(err)
		}
		defer repository.Close()

		diff, err := repository.DiffRuns(context.Background(), baselineRunID, candidateRunID)
		if err != nil {
			fail(err)
		}

		emitJSON(queryOutput{
			Mode:        mode,
			Persistence: &radarruntime.PersistenceInfo{Backend: "sqlite", DBPath: repository.Path()},
			Diff:        &diff,
		})
		return
	case "plan":
		loadedTemplate, _, output := buildScanOutput(mode, template, activeInterface, passiveInterface, portTemplate, passiveMode, zeekLogDir, projectName, dataDir, dbPath, reevaluateAfter, continueOnErrorFlag, retainPartialFlag, reevaluateFlag, autoStartZeekFlag)
		_ = loadedTemplate
		emitJSON(output)
		return
	case "run":
		loadedTemplate, effectiveOptions, output := buildScanOutput(mode, template, activeInterface, passiveInterface, portTemplate, passiveMode, zeekLogDir, projectName, dataDir, dbPath, reevaluateAfter, continueOnErrorFlag, retainPartialFlag, reevaluateFlag, autoStartZeekFlag)
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

		executedPlan, jobResults, records, err := radarruntime.ExecuteRunWithPersistence(context.Background(), radarruntime.DefaultPlugins(), loadedTemplate, effectiveOptions, runStore)
		if err != nil {
			fail(err)
		}
		output.Plan = executedPlan
		output.JobResults = jobResults
		output.Evidence = records
		output.Blocking = radarruntime.AnalyzeEvidence(records)
		output.Reevaluation = radarruntime.BuildReevaluation(records, jobResults, effectiveOptions)
		output.Persistence = &radarruntime.PersistenceInfo{
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
		emitJSON(output)
		return
	case "execute-run":
		if runID == "" {
			fail(fmt.Errorf("execute-run mode requires --run-id"))
		}

		loadedTemplate, effectiveOptions, output := buildScanOutput(mode, template, activeInterface, passiveInterface, portTemplate, passiveMode, zeekLogDir, projectName, dataDir, dbPath, reevaluateAfter, continueOnErrorFlag, retainPartialFlag, reevaluateFlag, autoStartZeekFlag)
		repository, err := storage.OpenSQLite(effectiveOptions.DBPath)
		if err != nil {
			fail(err)
		}
		defer repository.Close()

		runStore, err := repository.BindRunStore(context.Background(), runID)
		if err != nil {
			fail(err)
		}

		executedPlan, jobResults, records, err := radarruntime.ExecuteRunWithPersistence(context.Background(), radarruntime.DefaultPlugins(), loadedTemplate, effectiveOptions, runStore)
		output.Plan = executedPlan
		output.JobResults = jobResults
		output.Evidence = records
		output.Blocking = radarruntime.AnalyzeEvidence(records)
		output.Reevaluation = radarruntime.BuildReevaluation(records, jobResults, effectiveOptions)

		completionStatus := summarizeRunStatus(jobResults)
		if err != nil {
			completionStatus = "failed"
		}
		if completeErr := repository.CompleteRun(context.Background(), runID, storage.RunCompletion{
			Status:       completionStatus,
			Plan:         executedPlan,
			Blocking:     output.Blocking,
			Reevaluation: output.Reevaluation,
		}); completeErr != nil {
			fail(completeErr)
		}

		if err != nil {
			fail(err)
		}
		emitJSON(output)
		return
	default:
		fail(fmt.Errorf("unsupported mode %q", mode))
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

func buildOptionOverrides(activeInterface string, passiveInterface string, portTemplate string, passiveMode string, zeekLogDir string, project string, dataDir string, dbPath string, reevaluateAfter string, continueOnError optionalBool, retainPartial optionalBool, reevaluate optionalBool, autoStartZeek optionalBool) options.TemplateOptions {
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
	if passiveMode != "" {
		overrides.Sensors.PassiveMode = passiveMode
	}
	if zeekLogDir != "" {
		overrides.Sensors.ZeekLogDir = zeekLogDir
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
	if autoStartZeek.set {
		value := autoStartZeek.value
		overrides.Sensors.AutoStartZeek = &value
	}

	return overrides
}

type queryOutput struct {
	Mode          string                        `json:"mode"`
	ProjectFilter string                        `json:"project_filter,omitempty"`
	Persistence   *radarruntime.PersistenceInfo `json:"persistence,omitempty"`
	Projects      []storage.ProjectSummary      `json:"projects,omitempty"`
	Runs          []storage.RunSummary          `json:"runs,omitempty"`
	Run           *storage.RunDetails           `json:"run,omitempty"`
	Diff          *storage.RunDiff              `json:"diff,omitempty"`
}

func buildScanOutput(mode string, template string, activeInterface string, passiveInterface string, portTemplate string, passiveMode string, zeekLogDir string, projectName string, dataDir string, dbPath string, reevaluateAfter string, continueOnError optionalBool, retainPartial optionalBool, reevaluate optionalBool, autoStartZeek optionalBool) (templates.Template, options.EffectiveOptions, radarruntime.Output) {
	loadedTemplate, err := radarruntime.LoadTemplate(template)
	if err != nil {
		fail(err)
	}

	overrides := buildOptionOverrides(activeInterface, passiveInterface, portTemplate, passiveMode, zeekLogDir, projectName, dataDir, dbPath, reevaluateAfter, continueOnError, retainPartial, reevaluate, autoStartZeek)
	effectiveOptions := radarruntime.ResolveOptions(loadedTemplate, overrides)
	if effectiveOptions.Project == "" {
		effectiveOptions.Project = loadedTemplate.Name
	}
	effectiveOptions.DBPath = storage.ResolveDBPath(effectiveOptions.DataDir, effectiveOptions.DBPath)

	plan := radarruntime.BuildSeedPlanWithOptions(loadedTemplate, effectiveOptions)
	output := radarruntime.Output{
		Mode:     mode,
		Template: template,
		Options:  effectiveOptions,
		Plan:     plan,
	}

	return loadedTemplate, effectiveOptions, output
}

func emitJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fail(err)
	}
}

func summarizeRunStatus(results []jobs.ExecutionResult) string {
	for _, result := range results {
		if result.Status == jobs.StatusFailed {
			return "partial"
		}
	}
	return "completed"
}
