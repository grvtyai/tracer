package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/grvtyai/tracer/scanner-core/internal/app"
)

func main() {
	var (
		mode     string
		template string
	)

	flag.StringVar(&mode, "mode", "plan", "execution mode: plan or run")
	flag.StringVar(&template, "template", "examples/phase1-template.json", "path to a JSON template file")
	flag.Parse()

	loadedTemplate, err := app.LoadTemplate(template)
	if err != nil {
		fail(err)
	}

	plan := app.BuildSeedPlan(loadedTemplate)
	output := app.Output{
		Mode:     mode,
		Template: template,
		Plan:     plan,
	}

	switch mode {
	case "plan":
	case "run":
		records, err := app.RunPlan(context.Background(), app.DefaultPlugins(), plan)
		if err != nil {
			fail(err)
		}
		output.Evidence = records
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
