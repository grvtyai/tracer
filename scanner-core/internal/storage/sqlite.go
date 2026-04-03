package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/grvtyai/tracer/scanner-core/internal/analysis"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/ingest"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
	"github.com/grvtyai/tracer/scanner-core/internal/options"
	_ "modernc.org/sqlite"
)

type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RunRecord struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	TemplateName string    `json:"template_name,omitempty"`
	TemplatePath string    `json:"template_path,omitempty"`
	Mode         string    `json:"mode"`
	Status       string    `json:"status"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at,omitempty"`
}

type RunSpec struct {
	TemplateName string
	TemplatePath string
	Mode         string
	Scope        ingest.Scope
	Profile      ingest.RunProfile
	Options      options.EffectiveOptions
}

type RunCompletion struct {
	Status       string
	Plan         []jobs.Job
	Blocking     []analysis.BlockingAssessment
	Reevaluation []analysis.ReevaluationHint
}

type SQLiteRepository struct {
	db   *sql.DB
	path string
}

type SQLiteRunStore struct {
	repo  *SQLiteRepository
	runID string
}

func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "tracer")
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return "data"
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(homeDir, "AppData", "Local", "tracer")
	default:
		return filepath.Join(homeDir, ".local", "share", "tracer")
	}
}

func DefaultDBPath() string {
	return filepath.Join(DefaultDataDir(), "tracer.db")
}

func OpenSQLite(path string) (*SQLiteRepository, error) {
	if path == "" {
		path = DefaultDBPath()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	repo := &SQLiteRepository{
		db:   db,
		path: path,
	}

	if err := repo.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}

	return repo, nil
}

func (r *SQLiteRepository) Path() string {
	return r.path
}

func (r *SQLiteRepository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *SQLiteRepository) EnsureProject(ctx context.Context, name string, description string) (Project, error) {
	now := time.Now().UTC()

	if name == "" {
		name = "default"
	}

	var project Project
	row := r.db.QueryRowContext(ctx, `SELECT id, name, description, created_at, updated_at FROM projects WHERE name = ?`, name)
	var createdAt string
	var updatedAt string
	switch err := row.Scan(&project.ID, &project.Name, &project.Description, &createdAt, &updatedAt); err {
	case nil:
		project.CreatedAt = mustParseTime(createdAt)
		project.UpdatedAt = mustParseTime(updatedAt)
		return project, nil
	case sql.ErrNoRows:
	default:
		return Project{}, fmt.Errorf("query project: %w", err)
	}

	project = Project{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO projects (id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, project.ID, project.Name, project.Description, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Project{}, fmt.Errorf("insert project: %w", err)
	}

	return project, nil
}

func (r *SQLiteRepository) StartRun(ctx context.Context, projectID string, spec RunSpec) (RunRecord, *SQLiteRunStore, error) {
	run := RunRecord{
		ID:           uuid.NewString(),
		ProjectID:    projectID,
		TemplateName: spec.TemplateName,
		TemplatePath: spec.TemplatePath,
		Mode:         spec.Mode,
		Status:       "running",
		StartedAt:    time.Now().UTC(),
	}

	scopeJSON, err := marshalJSON(spec.Scope)
	if err != nil {
		return RunRecord{}, nil, err
	}
	profileJSON, err := marshalJSON(spec.Profile)
	if err != nil {
		return RunRecord{}, nil, err
	}
	optionsJSON, err := marshalJSON(spec.Options)
	if err != nil {
		return RunRecord{}, nil, err
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO runs (
			id, project_id, template_name, template_path, mode, status,
			started_at, scope_json, profile_json, options_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, run.ID, run.ProjectID, run.TemplateName, run.TemplatePath, run.Mode, run.Status, run.StartedAt.Format(time.RFC3339Nano), scopeJSON, profileJSON, optionsJSON)
	if err != nil {
		return RunRecord{}, nil, fmt.Errorf("insert run: %w", err)
	}

	return run, &SQLiteRunStore{repo: r, runID: run.ID}, nil
}

func (r *SQLiteRepository) CompleteRun(ctx context.Context, runID string, completion RunCompletion) error {
	finishedAt := time.Now().UTC()

	planJSON, err := marshalJSON(completion.Plan)
	if err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		UPDATE runs
		SET status = ?, finished_at = ?, plan_json = ?
		WHERE id = ?
	`, completion.Status, finishedAt.Format(time.RFC3339Nano), planJSON, runID); err != nil {
		return fmt.Errorf("update run: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM blocking_assessments WHERE run_id = ?`, runID); err != nil {
		return fmt.Errorf("clear blocking assessments: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM reevaluation_hints WHERE run_id = ?`, runID); err != nil {
		return fmt.Errorf("clear reevaluation hints: %w", err)
	}

	for _, assessment := range completion.Blocking {
		reasonsJSON, err := marshalJSON(assessment.Reasons)
		if err != nil {
			return err
		}
		refsJSON, err := marshalJSON(assessment.EvidenceRefs)
		if err != nil {
			return err
		}
		rawJSON, err := marshalJSON(assessment)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO blocking_assessments (
				run_id, target, port, verdict, confidence, reasons_json, evidence_refs_json, raw_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, runID, assessment.Target, assessment.Port, string(assessment.Verdict), string(assessment.Confidence), reasonsJSON, refsJSON, rawJSON); err != nil {
			return fmt.Errorf("insert blocking assessment: %w", err)
		}
	}

	for _, hint := range completion.Reevaluation {
		sourcesJSON, err := marshalJSON(hint.Sources)
		if err != nil {
			return err
		}
		rawJSON, err := marshalJSON(hint)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO reevaluation_hints (
				run_id, target, port, reason, suggested_after, sources_json, raw_json
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`, runID, hint.Target, hint.Port, hint.Reason, hint.SuggestedAfter, sourcesJSON, rawJSON); err != nil {
			return fmt.Errorf("insert reevaluation hint: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite transaction: %w", err)
	}

	return nil
}

func (s *SQLiteRunStore) WriteEvidence(ctx context.Context, records []evidence.Record) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := s.repo.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evidence transaction: %w", err)
	}
	defer tx.Rollback()

	for _, record := range records {
		attributesJSON, err := marshalJSON(record.Attributes)
		if err != nil {
			return err
		}
		rawJSON, err := marshalJSON(record)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO evidence (
				run_id, record_id, source, kind, target, port, protocol,
				summary, raw_ref, confidence, observed_at, attributes_json, raw_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, s.runID, record.ID, record.Source, record.Kind, record.Target, record.Port, record.Protocol, record.Summary, record.RawRef, string(record.Confidence), record.ObservedAt.Format(time.RFC3339Nano), attributesJSON, rawJSON); err != nil {
			return fmt.Errorf("insert evidence: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evidence transaction: %w", err)
	}

	return nil
}

func (s *SQLiteRunStore) WriteJobResults(ctx context.Context, results []jobs.ExecutionResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := s.repo.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin job result transaction: %w", err)
	}
	defer tx.Rollback()

	for _, result := range results {
		targetsJSON, err := marshalJSON(result.Targets)
		if err != nil {
			return err
		}
		portsJSON, err := marshalJSON(result.Ports)
		if err != nil {
			return err
		}
		rawJSON, err := marshalJSON(result)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO job_results (
				run_id, job_id, kind, plugin, targets_json, ports_json, status, error,
				records_written, started_at, finished_at, needs_reevaluation,
				reevaluation_after, reevaluation_reason, raw_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, s.runID, result.JobID, string(result.Kind), result.Plugin, targetsJSON, portsJSON, string(result.Status), result.Error, result.RecordsWritten, result.StartedAt.Format(time.RFC3339Nano), result.FinishedAt.Format(time.RFC3339Nano), boolToInt(result.NeedsReevaluation), result.ReevaluationAfter, result.ReevaluationReason, rawJSON); err != nil {
			return fmt.Errorf("insert job result: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit job result transaction: %w", err)
	}

	return nil
}

func (r *SQLiteRepository) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL;`,
		`CREATE TABLE IF NOT EXISTS projects (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS runs (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			template_name TEXT NOT NULL DEFAULT '',
			template_path TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL DEFAULT '',
			scope_json TEXT NOT NULL DEFAULT '{}',
			profile_json TEXT NOT NULL DEFAULT '{}',
			options_json TEXT NOT NULL DEFAULT '{}',
			plan_json TEXT NOT NULL DEFAULT '[]',
			FOREIGN KEY(project_id) REFERENCES projects(id)
		);`,
		`CREATE TABLE IF NOT EXISTS job_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			job_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			plugin TEXT NOT NULL,
			targets_json TEXT NOT NULL DEFAULT '[]',
			ports_json TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT '',
			records_written INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			needs_reevaluation INTEGER NOT NULL DEFAULT 0,
			reevaluation_after TEXT NOT NULL DEFAULT '',
			reevaluation_reason TEXT NOT NULL DEFAULT '',
			raw_json TEXT NOT NULL DEFAULT '{}',
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);`,
		`CREATE TABLE IF NOT EXISTS evidence (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			record_id TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL,
			kind TEXT NOT NULL,
			target TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 0,
			protocol TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL,
			raw_ref TEXT NOT NULL DEFAULT '',
			confidence TEXT NOT NULL,
			observed_at TEXT NOT NULL,
			attributes_json TEXT NOT NULL DEFAULT '{}',
			raw_json TEXT NOT NULL DEFAULT '{}',
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);`,
		`CREATE TABLE IF NOT EXISTS blocking_assessments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			target TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 0,
			verdict TEXT NOT NULL,
			confidence TEXT NOT NULL,
			reasons_json TEXT NOT NULL DEFAULT '[]',
			evidence_refs_json TEXT NOT NULL DEFAULT '[]',
			raw_json TEXT NOT NULL DEFAULT '{}',
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);`,
		`CREATE TABLE IF NOT EXISTS reevaluation_hints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id TEXT NOT NULL,
			target TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 0,
			reason TEXT NOT NULL,
			suggested_after TEXT NOT NULL DEFAULT '',
			sources_json TEXT NOT NULL DEFAULT '[]',
			raw_json TEXT NOT NULL DEFAULT '{}',
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_runs_project_id ON runs(project_id);`,
		`CREATE INDEX IF NOT EXISTS idx_job_results_run_id ON job_results(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_run_id ON evidence(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_target_port ON evidence(target, port);`,
	}

	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite database: %w", err)
		}
	}

	return nil
}

func marshalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(data), nil
}

func mustParseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
