package engine

import (
	"context"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/jobs"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

// Engine dispatches jobs to matching plugins and stores normalized evidence.
type Engine struct {
	plugins []Plugin
	store   storage.EvidenceStore
}

type RunOptions struct {
	ContinueOnError     bool
	RetainPartialResult bool
	ReevaluateFailures  bool
	ReevaluateAfter     string
}

func DefaultRunOptions() RunOptions {
	return RunOptions{
		ContinueOnError:     true,
		RetainPartialResult: true,
		ReevaluateFailures:  true,
		ReevaluateAfter:     "30m",
	}
}

func New(plugins []Plugin, store storage.EvidenceStore) *Engine {
	return &Engine{
		plugins: plugins,
		store:   store,
	}
}

func (e *Engine) Run(ctx context.Context, plan []jobs.Job, options RunOptions) []jobs.ExecutionResult {
	if options.ReevaluateAfter == "" {
		options.ReevaluateAfter = "30m"
	}

	results := make([]jobs.ExecutionResult, 0, len(plan))
	for _, job := range plan {
		startedAt := time.Now().UTC()
		result := jobs.ExecutionResult{
			JobID:     job.ID,
			Kind:      job.Kind,
			Plugin:    job.Plugin,
			Targets:   append([]string{}, job.Targets...),
			Ports:     append([]int{}, job.Ports...),
			StartedAt: startedAt,
		}
		handled := false

		for _, plugin := range e.plugins {
			if job.Plugin != "" && plugin.Name() != job.Plugin {
				continue
			}

			if !plugin.CanRun(job) {
				continue
			}

			records, err := plugin.Run(ctx, job)
			if err != nil {
				result.Plugin = plugin.Name()
				result.Status = jobs.StatusFailed
				result.Error = err.Error()
				result.FinishedAt = time.Now().UTC()
				if options.ReevaluateFailures {
					result.NeedsReevaluation = true
					result.ReevaluationAfter = options.ReevaluateAfter
					result.ReevaluationReason = "job execution failed before the full scan pipeline completed"
				}

				results = append(results, result)
				e.writeJobResult(ctx, result)
				handled = true
				if !options.ContinueOnError {
					return results
				}
				break
			}

			if len(records) > 0 && e.store != nil {
				if err := e.store.WriteEvidence(ctx, records); err != nil {
					result.Plugin = plugin.Name()
					result.Status = jobs.StatusFailed
					result.Error = err.Error()
					result.FinishedAt = time.Now().UTC()
					if options.ReevaluateFailures {
						result.NeedsReevaluation = true
						result.ReevaluationAfter = options.ReevaluateAfter
						result.ReevaluationReason = "persisting partial scan evidence failed"
					}

					results = append(results, result)
					e.writeJobResult(ctx, result)
					handled = true
					if !options.ContinueOnError {
						return results
					}
					break
				}
			}

			result.Plugin = plugin.Name()
			result.Status = jobs.StatusSucceeded
			result.RecordsWritten = len(records)
			result.FinishedAt = time.Now().UTC()
			results = append(results, result)
			e.writeJobResult(ctx, result)
			handled = true
			break
		}

		if !handled {
			result.Status = jobs.StatusFailed
			result.Error = "no plugin registered for this job"
			result.FinishedAt = time.Now().UTC()
			if options.ReevaluateFailures {
				result.NeedsReevaluation = true
				result.ReevaluationAfter = options.ReevaluateAfter
				result.ReevaluationReason = "job could not be dispatched to any registered plugin"
			}

			results = append(results, result)
			e.writeJobResult(ctx, result)
			if !options.ContinueOnError {
				return results
			}
		}
	}

	return results
}

func (e *Engine) writeJobResult(ctx context.Context, result jobs.ExecutionResult) {
	if e.store == nil {
		return
	}

	jobStore, ok := e.store.(storage.JobResultStore)
	if !ok {
		return
	}

	_ = jobStore.WriteJobResults(ctx, []jobs.ExecutionResult{result})
}
