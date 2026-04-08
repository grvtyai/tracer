package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
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
	ID            string    `json:"id"`
	PublicID      string    `json:"public_id,omitempty"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	StoragePath   string    `json:"storage_path,omitempty"`
	TargetDBPath  string    `json:"target_db_path,omitempty"`
	OwnerUsername string    `json:"owner_username,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
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

type ProjectSummary struct {
	ID            string    `json:"id"`
	PublicID      string    `json:"public_id,omitempty"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	StoragePath   string    `json:"storage_path,omitempty"`
	TargetDBPath  string    `json:"target_db_path,omitempty"`
	OwnerUsername string    `json:"owner_username,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	RunCount      int       `json:"run_count"`
	LastRunAt     time.Time `json:"last_run_at,omitempty"`
}

type RunSummary struct {
	ID            string    `json:"id"`
	ProjectID     string    `json:"project_id"`
	ProjectName   string    `json:"project_name,omitempty"`
	TemplateName  string    `json:"template_name,omitempty"`
	TemplatePath  string    `json:"template_path,omitempty"`
	Mode          string    `json:"mode"`
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	JobCount      int       `json:"job_count"`
	EvidenceCount int       `json:"evidence_count"`
}

type RunDetails struct {
	Run          RunSummary                    `json:"run"`
	Scope        ingest.Scope                  `json:"scope"`
	Profile      ingest.RunProfile             `json:"profile"`
	Options      options.EffectiveOptions      `json:"options"`
	Plan         []jobs.Job                    `json:"plan,omitempty"`
	JobResults   []jobs.ExecutionResult        `json:"job_results,omitempty"`
	Evidence     []evidence.Record             `json:"evidence,omitempty"`
	Blocking     []analysis.BlockingAssessment `json:"blocking,omitempty"`
	Reevaluation []analysis.ReevaluationHint   `json:"reevaluation,omitempty"`
}

type ChangedEvidence struct {
	Identity  string          `json:"identity"`
	Baseline  evidence.Record `json:"baseline"`
	Candidate evidence.Record `json:"candidate"`
}

type RunDiff struct {
	Baseline        RunSummary        `json:"baseline"`
	Candidate       RunSummary        `json:"candidate"`
	NewEvidence     []evidence.Record `json:"new_evidence,omitempty"`
	MissingEvidence []evidence.Record `json:"missing_evidence,omitempty"`
	ChangedEvidence []ChangedEvidence `json:"changed_evidence,omitempty"`
	NewCount        int               `json:"new_count"`
	MissingCount    int               `json:"missing_count"`
	ChangedCount    int               `json:"changed_count"`
}

func DefaultDataDir() string {
	return defaultDataDir(runtime.GOOS, os.Getenv, os.UserHomeDir, lookupUserHomeDir)
}

func DefaultDBPath() string {
	return filepath.Join(DefaultDataDir(), "tracer.db")
}

func ResolveDBPath(dataDir string, dbPath string) string {
	if strings.TrimSpace(dbPath) != "" {
		return dbPath
	}
	if strings.TrimSpace(dataDir) != "" {
		return filepath.Join(dataDir, "tracer.db")
	}
	return DefaultDBPath()
}

func OpenSQLite(path string) (*SQLiteRepository, error) {
	if path == "" {
		path = DefaultDBPath()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o775); err != nil {
		return nil, fmt.Errorf("create sqlite directory: %w", err)
	}
	if err := adoptSQLiteOwnership(path); err != nil {
		return nil, err
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
	if err := adoptSQLiteOwnership(path); err != nil {
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
	row := r.db.QueryRowContext(ctx, `
		SELECT
			p.id,
			COALESCE(pm.public_id, ''),
			p.name,
			p.description,
			COALESCE(pm.notes, ''),
			COALESCE(pm.storage_path, ''),
			COALESCE(pm.target_db_path, ''),
			COALESCE(pm.owner_username, ''),
			p.created_at,
			p.updated_at
		FROM projects p
		LEFT JOIN project_metadata pm ON pm.project_id = p.id
		WHERE p.name = ?
	`, name)
	var createdAt string
	var updatedAt string
	switch err := row.Scan(&project.ID, &project.PublicID, &project.Name, &project.Description, &project.Notes, &project.StoragePath, &project.TargetDBPath, &project.OwnerUsername, &createdAt, &updatedAt); err {
	case nil:
		project.CreatedAt = mustParseTime(createdAt)
		project.UpdatedAt = mustParseTime(updatedAt)
		if err := r.ensureProjectMetadata(ctx, project.ID, project.Name, firstNonEmptyProject(project.Notes, project.Description)); err != nil {
			return Project{}, err
		}
		if project.PublicID == "" || project.StoragePath == "" || project.TargetDBPath == "" || project.OwnerUsername == "" {
			return r.EnsureProject(ctx, name, description)
		}
		return project, nil
	case sql.ErrNoRows:
	default:
		return Project{}, fmt.Errorf("query project: %w", err)
	}

	project = Project{
		ID:            uuid.NewString(),
		PublicID:      generateProjectPublicID(),
		Name:          name,
		Description:   description,
		Notes:         description,
		StoragePath:   r.defaultProjectStoragePath(name, ""),
		TargetDBPath:  filepath.Join(r.defaultProjectStoragePath(name, ""), "project.sqlite"),
		OwnerUsername: currentOperatorName(),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := os.MkdirAll(project.StoragePath, 0o775); err != nil {
		return Project{}, fmt.Errorf("create project storage path: %w", err)
	}
	if err := adoptProjectPathOwnership(project.StoragePath); err != nil {
		return Project{}, err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, fmt.Errorf("begin project transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO projects (id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, project.ID, project.Name, project.Description, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Project{}, fmt.Errorf("insert project: %w", err)
	}

	if err := upsertProjectMetadataTx(ctx, tx, project); err != nil {
		return Project{}, err
	}

	if err := tx.Commit(); err != nil {
		return Project{}, fmt.Errorf("commit project transaction: %w", err)
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

func (r *SQLiteRepository) BindRunStore(ctx context.Context, runID string) (*SQLiteRunStore, error) {
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT 1 FROM runs WHERE id = ?`, runID).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("run %q not found", runID)
		}
		return nil, fmt.Errorf("bind run store: %w", err)
	}
	return &SQLiteRunStore{repo: r, runID: runID}, nil
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

	if err := r.syncAssetsForRun(ctx, runID); err != nil {
		return err
	}

	return nil
}

func (r *SQLiteRepository) ListProjects(ctx context.Context) ([]ProjectSummary, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			p.id,
			COALESCE(pm.public_id, ''),
			p.name,
			p.description,
			COALESCE(pm.notes, ''),
			COALESCE(pm.storage_path, ''),
			COALESCE(pm.target_db_path, ''),
			COALESCE(pm.owner_username, ''),
			p.created_at,
			p.updated_at,
			COUNT(run.id) AS run_count,
			COALESCE(MAX(run.started_at), '')
		FROM projects p
		LEFT JOIN project_metadata pm ON pm.project_id = p.id
		LEFT JOIN runs run ON run.project_id = p.id
		GROUP BY p.id, pm.public_id, p.name, p.description, pm.notes, pm.storage_path, pm.target_db_path, pm.owner_username, p.created_at, p.updated_at
		ORDER BY p.name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	projects := make([]ProjectSummary, 0)
	for rows.Next() {
		var project ProjectSummary
		var createdAt string
		var updatedAt string
		var lastRunAt string
		if err := rows.Scan(&project.ID, &project.PublicID, &project.Name, &project.Description, &project.Notes, &project.StoragePath, &project.TargetDBPath, &project.OwnerUsername, &createdAt, &updatedAt, &project.RunCount, &lastRunAt); err != nil {
			return nil, fmt.Errorf("scan project summary: %w", err)
		}

		project.CreatedAt = mustParseTime(createdAt)
		project.UpdatedAt = mustParseTime(updatedAt)
		project.LastRunAt = mustParseTime(lastRunAt)
		if err := r.ensureProjectMetadata(ctx, project.ID, project.Name, firstNonEmptyProject(project.Notes, project.Description)); err != nil {
			return nil, err
		}
		if project.PublicID == "" {
			project.PublicID = generateProjectPublicID()
		}
		if project.Notes == "" {
			project.Notes = project.Description
		}
		if project.StoragePath == "" {
			project.StoragePath = r.defaultProjectStoragePath(project.Name, project.PublicID)
		}
		if project.TargetDBPath == "" {
			project.TargetDBPath = filepath.Join(project.StoragePath, "project.sqlite")
		}
		if project.OwnerUsername == "" {
			project.OwnerUsername = currentOperatorName()
		}
		projects = append(projects, project)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate projects: %w", err)
	}

	return projects, nil
}

func (r *SQLiteRepository) ListRuns(ctx context.Context, projectRef string) ([]RunSummary, error) {
	query := `
		SELECT
			run.id,
			run.project_id,
			project.name,
			run.template_name,
			run.template_path,
			run.mode,
			run.status,
			run.started_at,
			run.finished_at,
			COUNT(DISTINCT jr.id) AS job_count,
			COUNT(DISTINCT ev.id) AS evidence_count
		FROM runs run
		INNER JOIN projects project ON project.id = run.project_id
		LEFT JOIN job_results jr ON jr.run_id = run.id
		LEFT JOIN evidence ev ON ev.run_id = run.id
	`
	args := make([]any, 0, 2)
	if trimmed := strings.TrimSpace(projectRef); trimmed != "" {
		query += ` WHERE run.project_id = ? OR project.name = ?`
		args = append(args, trimmed, trimmed)
	}
	query += `
		GROUP BY run.id, run.project_id, project.name, run.template_name, run.template_path, run.mode, run.status, run.started_at, run.finished_at
		ORDER BY run.started_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()

	runs := make([]RunSummary, 0)
	for rows.Next() {
		var run RunSummary
		var startedAt string
		var finishedAt string
		if err := rows.Scan(&run.ID, &run.ProjectID, &run.ProjectName, &run.TemplateName, &run.TemplatePath, &run.Mode, &run.Status, &startedAt, &finishedAt, &run.JobCount, &run.EvidenceCount); err != nil {
			return nil, fmt.Errorf("scan run summary: %w", err)
		}

		run.StartedAt = mustParseTime(startedAt)
		run.FinishedAt = mustParseTime(finishedAt)
		runs = append(runs, run)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs: %w", err)
	}

	return runs, nil
}

func (r *SQLiteRepository) GetRun(ctx context.Context, runID string) (RunDetails, error) {
	var details RunDetails
	row := r.db.QueryRowContext(ctx, `
		SELECT
			run.id,
			run.project_id,
			project.name,
			run.template_name,
			run.template_path,
			run.mode,
			run.status,
			run.started_at,
			run.finished_at,
			run.scope_json,
			run.profile_json,
			run.options_json,
			run.plan_json
		FROM runs run
		INNER JOIN projects project ON project.id = run.project_id
		WHERE run.id = ?
	`, runID)

	var startedAt string
	var finishedAt string
	var scopeJSON string
	var profileJSON string
	var optionsJSON string
	var planJSON string
	if err := row.Scan(
		&details.Run.ID,
		&details.Run.ProjectID,
		&details.Run.ProjectName,
		&details.Run.TemplateName,
		&details.Run.TemplatePath,
		&details.Run.Mode,
		&details.Run.Status,
		&startedAt,
		&finishedAt,
		&scopeJSON,
		&profileJSON,
		&optionsJSON,
		&planJSON,
	); err != nil {
		if err == sql.ErrNoRows {
			return RunDetails{}, fmt.Errorf("run %q not found", runID)
		}
		return RunDetails{}, fmt.Errorf("query run: %w", err)
	}

	details.Run.StartedAt = mustParseTime(startedAt)
	details.Run.FinishedAt = mustParseTime(finishedAt)
	if err := unmarshalJSON(scopeJSON, &details.Scope); err != nil {
		return RunDetails{}, err
	}
	if err := unmarshalJSON(profileJSON, &details.Profile); err != nil {
		return RunDetails{}, err
	}
	if err := unmarshalJSON(optionsJSON, &details.Options); err != nil {
		return RunDetails{}, err
	}
	if err := unmarshalJSON(planJSON, &details.Plan); err != nil {
		return RunDetails{}, err
	}

	jobResults, err := r.loadJobResults(ctx, runID)
	if err != nil {
		return RunDetails{}, err
	}
	evidenceRecords, err := r.loadEvidence(ctx, runID)
	if err != nil {
		return RunDetails{}, err
	}
	blockingAssessments, err := r.loadBlockingAssessments(ctx, runID)
	if err != nil {
		return RunDetails{}, err
	}
	reevaluationHints, err := r.loadReevaluationHints(ctx, runID)
	if err != nil {
		return RunDetails{}, err
	}

	details.JobResults = jobResults
	details.Evidence = evidenceRecords
	details.Blocking = blockingAssessments
	details.Reevaluation = reevaluationHints
	details.Run.JobCount = len(jobResults)
	details.Run.EvidenceCount = len(evidenceRecords)

	return details, nil
}

func (r *SQLiteRepository) DiffRuns(ctx context.Context, baselineRunID string, candidateRunID string) (RunDiff, error) {
	baseline, err := r.GetRun(ctx, baselineRunID)
	if err != nil {
		return RunDiff{}, err
	}
	candidate, err := r.GetRun(ctx, candidateRunID)
	if err != nil {
		return RunDiff{}, err
	}

	baselineByIdentity := make(map[string]evidence.Record)
	for _, record := range baseline.Evidence {
		baselineByIdentity[evidenceIdentity(record)] = record
	}
	candidateByIdentity := make(map[string]evidence.Record)
	for _, record := range candidate.Evidence {
		candidateByIdentity[evidenceIdentity(record)] = record
	}

	diff := RunDiff{
		Baseline:        baseline.Run,
		Candidate:       candidate.Run,
		NewEvidence:     make([]evidence.Record, 0),
		MissingEvidence: make([]evidence.Record, 0),
		ChangedEvidence: make([]ChangedEvidence, 0),
	}

	for identity, baselineRecord := range baselineByIdentity {
		candidateRecord, ok := candidateByIdentity[identity]
		if !ok {
			diff.MissingEvidence = append(diff.MissingEvidence, baselineRecord)
			continue
		}
		if evidenceDetailFingerprint(baselineRecord) != evidenceDetailFingerprint(candidateRecord) {
			diff.ChangedEvidence = append(diff.ChangedEvidence, ChangedEvidence{
				Identity:  identity,
				Baseline:  baselineRecord,
				Candidate: candidateRecord,
			})
		}
	}

	for identity, candidateRecord := range candidateByIdentity {
		if _, ok := baselineByIdentity[identity]; ok {
			continue
		}
		diff.NewEvidence = append(diff.NewEvidence, candidateRecord)
	}

	sortEvidence(diff.NewEvidence)
	sortEvidence(diff.MissingEvidence)
	slices.SortFunc(diff.ChangedEvidence, func(a, b ChangedEvidence) int {
		return strings.Compare(a.Identity, b.Identity)
	})

	diff.NewCount = len(diff.NewEvidence)
	diff.MissingCount = len(diff.MissingEvidence)
	diff.ChangedCount = len(diff.ChangedEvidence)
	return diff, nil
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
		`CREATE TABLE IF NOT EXISTS project_metadata (
			project_id TEXT PRIMARY KEY,
			public_id TEXT NOT NULL UNIQUE,
			notes TEXT NOT NULL DEFAULT '',
			storage_path TEXT NOT NULL DEFAULT '',
			target_db_path TEXT NOT NULL DEFAULT '',
			owner_username TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(project_id) REFERENCES projects(id)
		);`,
		`CREATE TABLE IF NOT EXISTS app_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS assets (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			identity_key TEXT NOT NULL,
			primary_target TEXT NOT NULL,
			current_hostname TEXT NOT NULL DEFAULT '',
			current_os TEXT NOT NULL DEFAULT '',
			current_vendor TEXT NOT NULL DEFAULT '',
			current_product TEXT NOT NULL DEFAULT '',
			current_open_ports_json TEXT NOT NULL DEFAULT '[]',
			device_type_guess TEXT NOT NULL DEFAULT '',
			device_type_confidence TEXT NOT NULL DEFAULT '',
			connection_type_guess TEXT NOT NULL DEFAULT '',
			connection_type_confidence TEXT NOT NULL DEFAULT '',
			manual_display_name TEXT NOT NULL DEFAULT '',
			manual_device_type TEXT NOT NULL DEFAULT '',
			manual_connection_type TEXT NOT NULL DEFAULT '',
			manual_reevaluate INTEGER NOT NULL DEFAULT 0,
			manual_notes TEXT NOT NULL DEFAULT '',
			manual_tags_json TEXT NOT NULL DEFAULT '[]',
			last_run_id TEXT NOT NULL DEFAULT '',
			first_seen_at TEXT NOT NULL DEFAULT '',
			last_seen_at TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(project_id) REFERENCES projects(id)
		);`,
		`CREATE TABLE IF NOT EXISTS asset_observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			asset_id TEXT NOT NULL,
			run_id TEXT NOT NULL,
			target TEXT NOT NULL DEFAULT '',
			hostname TEXT NOT NULL DEFAULT '',
			os_name TEXT NOT NULL DEFAULT '',
			vendor TEXT NOT NULL DEFAULT '',
			product TEXT NOT NULL DEFAULT '',
			open_ports_json TEXT NOT NULL DEFAULT '[]',
			evidence_count INTEGER NOT NULL DEFAULT 0,
			verdict TEXT NOT NULL DEFAULT '',
			confidence TEXT NOT NULL DEFAULT '',
			device_type_guess TEXT NOT NULL DEFAULT '',
			device_type_confidence TEXT NOT NULL DEFAULT '',
			connection_type_guess TEXT NOT NULL DEFAULT '',
			connection_type_confidence TEXT NOT NULL DEFAULT '',
			observed_at TEXT NOT NULL DEFAULT '',
			raw_json TEXT NOT NULL DEFAULT '{}',
			FOREIGN KEY(asset_id) REFERENCES assets(id),
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);`,
		`CREATE TABLE IF NOT EXISTS scheduled_scans (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			source_run_id TEXT NOT NULL DEFAULT '',
			source_asset_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT '',
			scope_input TEXT NOT NULL DEFAULT '',
			execute_at TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			created_at TEXT NOT NULL,
			FOREIGN KEY(project_id) REFERENCES projects(id)
		);`,
		`CREATE TABLE IF NOT EXISTS run_acknowledgements (
			run_id TEXT PRIMARY KEY,
			acknowledged_at TEXT NOT NULL,
			note TEXT NOT NULL DEFAULT '',
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);`,
		`CREATE TABLE IF NOT EXISTS satellites (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT '',
			address TEXT NOT NULL DEFAULT '',
			hostname TEXT NOT NULL DEFAULT '',
			platform TEXT NOT NULL DEFAULT '',
			executor TEXT NOT NULL DEFAULT '',
			last_seen_at TEXT NOT NULL DEFAULT '',
			registration_token_hint TEXT NOT NULL DEFAULT '',
			capabilities_json TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_runs_project_id ON runs(project_id);`,
		`CREATE INDEX IF NOT EXISTS idx_job_results_run_id ON job_results(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_run_id ON evidence(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_target_port ON evidence(target, port);`,
		`CREATE INDEX IF NOT EXISTS idx_project_metadata_public_id ON project_metadata(public_id);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_project_identity ON assets(project_id, identity_key);`,
		`CREATE INDEX IF NOT EXISTS idx_assets_project_last_seen ON assets(project_id, last_seen_at);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_observations_asset_run ON asset_observations(asset_id, run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_asset_observations_run_id ON asset_observations(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scheduled_scans_run ON scheduled_scans(source_run_id, execute_at);`,
		`CREATE INDEX IF NOT EXISTS idx_scheduled_scans_asset ON scheduled_scans(source_asset_id, execute_at);`,
		`CREATE INDEX IF NOT EXISTS idx_satellites_kind_name ON satellites(kind, name);`,
	}

	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite database: %w", err)
		}
	}

	if err := ensureColumnExists(ctx, r.db, "assets", "manual_reevaluate", "ALTER TABLE assets ADD COLUMN manual_reevaluate INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	return nil
}

func ensureColumnExists(ctx context.Context, db *sql.DB, tableName string, columnName string, alterStatement string) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+tableName+")")
	if err != nil {
		return fmt.Errorf("inspect sqlite table %q: %w", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan sqlite table info for %q: %w", tableName, err)
		}
		if strings.EqualFold(name, columnName) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sqlite table info for %q: %w", tableName, err)
	}

	if _, err := db.ExecContext(ctx, alterStatement); err != nil {
		return fmt.Errorf("migrate sqlite column %q on %q: %w", columnName, tableName, err)
	}
	return nil
}

func defaultDataDir(goos string, getenv func(string) string, userHomeDir func() (string, error), lookupUserHome func(string) (string, error)) string {
	if goos == "windows" {
		if localAppData := strings.TrimSpace(getenv("LOCALAPPDATA")); localAppData != "" {
			return filepath.Join(localAppData, "tracer")
		}
	}

	if goos != "windows" {
		if xdgDataHome := strings.TrimSpace(getenv("XDG_DATA_HOME")); xdgDataHome != "" {
			return filepath.Join(xdgDataHome, "tracer")
		}
		if sudoUser := strings.TrimSpace(getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
			if sudoHome, err := lookupUserHome(sudoUser); err == nil && strings.TrimSpace(sudoHome) != "" {
				return filepath.Join(sudoHome, ".local", "share", "tracer")
			}
		}
	}

	homeDir, err := userHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return "data"
	}

	switch goos {
	case "windows":
		return filepath.Join(homeDir, "AppData", "Local", "tracer")
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", "tracer")
	default:
		return filepath.Join(homeDir, ".local", "share", "tracer")
	}
}

func lookupUserHomeDir(username string) (string, error) {
	lookup, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	return lookup.HomeDir, nil
}

func adoptSQLiteOwnership(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	uid, gid, ok := invokingUserIDs(os.Getenv)
	if !ok {
		return nil
	}

	for _, candidate := range []string{
		filepath.Dir(path),
		path,
		path + "-wal",
		path + "-shm",
	} {
		if err := chownIfExists(candidate, uid, gid); err != nil {
			return err
		}
	}

	return nil
}

func invokingUserIDs(getenv func(string) string) (int, int, bool) {
	uidValue := strings.TrimSpace(getenv("SUDO_UID"))
	gidValue := strings.TrimSpace(getenv("SUDO_GID"))
	if uidValue == "" || gidValue == "" {
		return 0, 0, false
	}

	uid, err := strconv.Atoi(uidValue)
	if err != nil {
		return 0, 0, false
	}
	gid, err := strconv.Atoi(gidValue)
	if err != nil {
		return 0, 0, false
	}

	return uid, gid, true
}

func chownIfExists(path string, uid int, gid int) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat sqlite path %q: %w", path, err)
	}

	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("adjust sqlite ownership for %q: %w", path, err)
	}

	mode := os.FileMode(0o664)
	if info.IsDir() {
		mode = 0o775
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("adjust sqlite mode for %q: %w", path, err)
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

func unmarshalJSON[T any](value string, dst *T) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(value), dst); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}
	return nil
}

func mustParseTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
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

func (r *SQLiteRepository) loadJobResults(ctx context.Context, runID string) ([]jobs.ExecutionResult, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT raw_json
		FROM job_results
		WHERE run_id = ?
		ORDER BY started_at ASC, id ASC
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query job results: %w", err)
	}
	defer rows.Close()

	results := make([]jobs.ExecutionResult, 0)
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("scan job result: %w", err)
		}

		var result jobs.ExecutionResult
		if err := unmarshalJSON(rawJSON, &result); err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate job results: %w", err)
	}

	return results, nil
}

func (r *SQLiteRepository) loadEvidence(ctx context.Context, runID string) ([]evidence.Record, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT raw_json
		FROM evidence
		WHERE run_id = ?
		ORDER BY observed_at ASC, id ASC
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()

	records := make([]evidence.Record, 0)
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}

		var record evidence.Record
		if err := unmarshalJSON(rawJSON, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate evidence: %w", err)
	}

	return records, nil
}

func (r *SQLiteRepository) loadBlockingAssessments(ctx context.Context, runID string) ([]analysis.BlockingAssessment, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT raw_json
		FROM blocking_assessments
		WHERE run_id = ?
		ORDER BY target ASC, port ASC, id ASC
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query blocking assessments: %w", err)
	}
	defer rows.Close()

	assessments := make([]analysis.BlockingAssessment, 0)
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("scan blocking assessment: %w", err)
		}

		var assessment analysis.BlockingAssessment
		if err := unmarshalJSON(rawJSON, &assessment); err != nil {
			return nil, err
		}
		assessments = append(assessments, assessment)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blocking assessments: %w", err)
	}

	return assessments, nil
}

func (r *SQLiteRepository) loadReevaluationHints(ctx context.Context, runID string) ([]analysis.ReevaluationHint, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT raw_json
		FROM reevaluation_hints
		WHERE run_id = ?
		ORDER BY target ASC, port ASC, id ASC
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query reevaluation hints: %w", err)
	}
	defer rows.Close()

	hints := make([]analysis.ReevaluationHint, 0)
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("scan reevaluation hint: %w", err)
		}

		var hint analysis.ReevaluationHint
		if err := unmarshalJSON(rawJSON, &hint); err != nil {
			return nil, err
		}
		hints = append(hints, hint)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reevaluation hints: %w", err)
	}

	return hints, nil
}

func evidenceIdentity(record evidence.Record) string {
	parts := []string{
		record.Source,
		record.Kind,
		record.Target,
		strconv.Itoa(record.Port),
		record.Protocol,
	}

	for _, key := range evidenceIdentityAttributeKeys {
		if value := strings.TrimSpace(record.Attributes[key]); value != "" {
			parts = append(parts, key+"="+value)
		}
	}

	return strings.Join(parts, "|")
}

func evidenceDetailFingerprint(record evidence.Record) string {
	parts := []string{
		record.Summary,
		string(record.Confidence),
	}

	keys := make([]string, 0, len(record.Attributes))
	for key := range record.Attributes {
		if evidenceVolatileAttributeKeys[key] {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		parts = append(parts, key+"="+record.Attributes[key])
	}

	return strings.Join(parts, "|")
}

func sortEvidence(records []evidence.Record) {
	slices.SortFunc(records, func(a, b evidence.Record) int {
		if a.Target != b.Target {
			return strings.Compare(a.Target, b.Target)
		}
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}
		return strings.Compare(a.Summary, b.Summary)
	})
}

var evidenceIdentityAttributeKeys = []string{
	"url",
	"uri",
	"host",
	"domain",
	"ip",
	"method",
	"service_name",
	"module",
	"os_name",
}

var evidenceVolatileAttributeKeys = map[string]bool{
	"job_id":                     true,
	"job_kind":                   true,
	"plugin":                     true,
	"host_primary_service_class": true,
	"host_service_classes":       true,
	"uid":                        true,
	"orig_p":                     true,
	"resp_p":                     true,
	"orig_bytes":                 true,
	"resp_bytes":                 true,
	"duration":                   true,
	"input":                      true,
	"reply_size":                 true,
	"reply_ttl":                  true,
	"rtt_ms":                     true,
	"probe_id":                   true,
	"probe_ttl":                  true,
}
