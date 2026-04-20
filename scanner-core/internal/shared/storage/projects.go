package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ProjectCreateInput struct {
	Name          string
	Notes         string
	StoragePath   string
	TargetDBPath  string
	OwnerUsername string
}

type AppSettings struct {
	DefaultProjectID           string `json:"default_project_id,omitempty"`
	DefaultSatelliteID         string `json:"default_satellite_id,omitempty"`
	DefaultScanTag             string `json:"default_scan_tag,omitempty"`
	DefaultPortTemplate        string `json:"default_port_template,omitempty"`
	DefaultActiveInterface     string `json:"default_active_interface,omitempty"`
	DefaultPassiveInterface    string `json:"default_passive_interface,omitempty"`
	DefaultPassiveMode         string `json:"default_passive_mode,omitempty"`
	DefaultZeekLogDir          string `json:"default_zeek_log_dir,omitempty"`
	DefaultRouteSampling       bool   `json:"default_route_sampling"`
	DefaultServiceScan         bool   `json:"default_service_scan"`
	DefaultAvahi               bool   `json:"default_avahi"`
	DefaultTestSSL             bool   `json:"default_testssl"`
	DefaultSNMP                bool   `json:"default_snmp"`
	DefaultPassiveIngest       bool   `json:"default_passive_ingest"`
	DefaultOSDetection         bool   `json:"default_os_detection"`
	DefaultLayer2              bool   `json:"default_layer2"`
	DefaultLargeRangeStrategy  bool   `json:"default_large_range_strategy"`
	DefaultZeekAutoStart       bool   `json:"default_zeek_auto_start"`
	DefaultContinueOnError     bool   `json:"default_continue_on_error"`
	DefaultRetainPartialResult bool   `json:"default_retain_partial_results"`
	DeploymentMode             string `json:"deployment_mode,omitempty"`
}

func (r *SQLiteRepository) CreateProject(ctx context.Context, input ProjectCreateInput) (Project, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Project{}, fmt.Errorf("project name is required")
	}

	var existingID string
	err := r.db.QueryRowContext(ctx, `SELECT id FROM projects WHERE LOWER(name) = LOWER(?)`, name).Scan(&existingID)
	switch err {
	case nil:
		return Project{}, fmt.Errorf("project %q already exists", name)
	case sql.ErrNoRows:
	default:
		return Project{}, fmt.Errorf("query existing project: %w", err)
	}

	now := time.Now().UTC()
	project := Project{
		ID:            uuid.NewString(),
		PublicID:      generateProjectPublicID(),
		Name:          name,
		Description:   strings.TrimSpace(input.Notes),
		Notes:         strings.TrimSpace(input.Notes),
		StoragePath:   strings.TrimSpace(input.StoragePath),
		TargetDBPath:  strings.TrimSpace(input.TargetDBPath),
		OwnerUsername: firstNonEmptyProject(strings.TrimSpace(input.OwnerUsername), currentOperatorName()),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if project.StoragePath == "" {
		project.StoragePath = r.defaultProjectStoragePath(project.Name, project.PublicID)
	}
	if project.TargetDBPath == "" {
		project.TargetDBPath = filepath.Join(project.StoragePath, "project.sqlite")
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

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO projects (id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, project.ID, project.Name, project.Description, project.CreatedAt.Format(time.RFC3339Nano), project.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
		return Project{}, fmt.Errorf("insert project: %w", err)
	}

	if err := upsertProjectMetadataTx(ctx, tx, project); err != nil {
		return Project{}, err
	}

	settings, err := r.GetAppSettings(ctx)
	if err != nil {
		return Project{}, err
	}
	if strings.TrimSpace(settings.DefaultProjectID) == "" {
		if err := setAppSettingTx(ctx, tx, "default_project_id", project.ID); err != nil {
			return Project{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return Project{}, fmt.Errorf("commit project transaction: %w", err)
	}

	return project, nil
}

func (r *SQLiteRepository) GetProject(ctx context.Context, ref string) (ProjectSummary, error) {
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
			p.updated_at,
			COUNT(run.id) AS run_count,
			COALESCE(MAX(run.started_at), '')
		FROM projects p
		LEFT JOIN project_metadata pm ON pm.project_id = p.id
		LEFT JOIN runs run ON run.project_id = p.id
		WHERE p.id = ? OR p.name = ? OR pm.public_id = ?
		GROUP BY p.id, pm.public_id, p.name, p.description, pm.notes, pm.storage_path, pm.target_db_path, pm.owner_username, p.created_at, p.updated_at
	`, ref, ref, ref)

	var project ProjectSummary
	var createdAt string
	var updatedAt string
	var lastRunAt string
	if err := row.Scan(&project.ID, &project.PublicID, &project.Name, &project.Description, &project.Notes, &project.StoragePath, &project.TargetDBPath, &project.OwnerUsername, &createdAt, &updatedAt, &project.RunCount, &lastRunAt); err != nil {
		if err == sql.ErrNoRows {
			return ProjectSummary{}, fmt.Errorf("project %q not found", ref)
		}
		return ProjectSummary{}, fmt.Errorf("query project: %w", err)
	}

	project.CreatedAt = mustParseTime(createdAt)
	project.UpdatedAt = mustParseTime(updatedAt)
	project.LastRunAt = mustParseTime(lastRunAt)
	if err := r.ensureProjectMetadata(ctx, project.ID, project.Name, project.Description); err != nil {
		return ProjectSummary{}, err
	}
	if project.PublicID == "" || project.StoragePath == "" || project.TargetDBPath == "" || project.OwnerUsername == "" {
		return r.GetProject(ctx, ref)
	}
	return project, nil
}

func (r *SQLiteRepository) GetAppSettings(ctx context.Context) (AppSettings, error) {
	settings := defaultAppSettings()
	rows, err := r.db.QueryContext(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return AppSettings{}, fmt.Errorf("query app settings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			return AppSettings{}, fmt.Errorf("scan app setting: %w", err)
		}
		switch strings.TrimSpace(key) {
		case "default_project_id":
			settings.DefaultProjectID = strings.TrimSpace(value)
		case "default_satellite_id":
			settings.DefaultSatelliteID = strings.TrimSpace(value)
		case "default_scan_tag":
			settings.DefaultScanTag = normalizeScanTag(value)
		case "default_port_template":
			settings.DefaultPortTemplate = firstNonEmptySetting(strings.TrimSpace(value), settings.DefaultPortTemplate)
		case "default_active_interface":
			settings.DefaultActiveInterface = strings.TrimSpace(value)
		case "default_passive_interface":
			settings.DefaultPassiveInterface = strings.TrimSpace(value)
		case "default_passive_mode":
			settings.DefaultPassiveMode = normalizePassiveMode(value)
		case "default_zeek_log_dir":
			settings.DefaultZeekLogDir = firstNonEmptySetting(strings.TrimSpace(value), settings.DefaultZeekLogDir)
		case "default_route_sampling":
			settings.DefaultRouteSampling = parseAppSettingBool(value, settings.DefaultRouteSampling)
		case "default_service_scan":
			settings.DefaultServiceScan = parseAppSettingBool(value, settings.DefaultServiceScan)
		case "default_avahi":
			settings.DefaultAvahi = parseAppSettingBool(value, settings.DefaultAvahi)
		case "default_testssl":
			settings.DefaultTestSSL = parseAppSettingBool(value, settings.DefaultTestSSL)
		case "default_snmp":
			settings.DefaultSNMP = parseAppSettingBool(value, settings.DefaultSNMP)
		case "default_passive_ingest":
			settings.DefaultPassiveIngest = parseAppSettingBool(value, settings.DefaultPassiveIngest)
		case "default_os_detection":
			settings.DefaultOSDetection = parseAppSettingBool(value, settings.DefaultOSDetection)
		case "default_layer2":
			settings.DefaultLayer2 = parseAppSettingBool(value, settings.DefaultLayer2)
		case "default_large_range_strategy":
			settings.DefaultLargeRangeStrategy = parseAppSettingBool(value, settings.DefaultLargeRangeStrategy)
		case "default_zeek_auto_start":
			settings.DefaultZeekAutoStart = parseAppSettingBool(value, settings.DefaultZeekAutoStart)
		case "default_continue_on_error":
			settings.DefaultContinueOnError = parseAppSettingBool(value, settings.DefaultContinueOnError)
		case "default_retain_partial_results":
			settings.DefaultRetainPartialResult = parseAppSettingBool(value, settings.DefaultRetainPartialResult)
		case "deployment_mode":
			settings.DeploymentMode = normalizeDeploymentMode(value)
		}
	}
	if err := rows.Err(); err != nil {
		return AppSettings{}, fmt.Errorf("iterate app settings: %w", err)
	}
	return settings, nil
}

func (r *SQLiteRepository) SetDefaultProject(ctx context.Context, projectID string) error {
	settings, err := r.GetAppSettings(ctx)
	if err != nil {
		return err
	}
	settings.DefaultProjectID = strings.TrimSpace(projectID)
	return r.SaveAppSettings(ctx, settings)
}

func (r *SQLiteRepository) SaveAppSettings(ctx context.Context, settings AppSettings) error {
	if trimmed := strings.TrimSpace(settings.DefaultProjectID); trimmed != "" {
		if _, err := r.GetProject(ctx, trimmed); err != nil {
			return err
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin app settings transaction: %w", err)
	}
	defer tx.Rollback()

	pairs := map[string]string{
		"default_project_id":             strings.TrimSpace(settings.DefaultProjectID),
		"default_satellite_id":           strings.TrimSpace(settings.DefaultSatelliteID),
		"default_scan_tag":               normalizeScanTag(settings.DefaultScanTag),
		"default_port_template":          firstNonEmptySetting(strings.TrimSpace(settings.DefaultPortTemplate), defaultAppSettings().DefaultPortTemplate),
		"default_active_interface":       strings.TrimSpace(settings.DefaultActiveInterface),
		"default_passive_interface":      strings.TrimSpace(settings.DefaultPassiveInterface),
		"default_passive_mode":           normalizePassiveMode(settings.DefaultPassiveMode),
		"default_zeek_log_dir":           firstNonEmptySetting(strings.TrimSpace(settings.DefaultZeekLogDir), defaultAppSettings().DefaultZeekLogDir),
		"default_route_sampling":         formatAppSettingBool(settings.DefaultRouteSampling),
		"default_service_scan":           formatAppSettingBool(settings.DefaultServiceScan),
		"default_avahi":                  formatAppSettingBool(settings.DefaultAvahi),
		"default_testssl":                formatAppSettingBool(settings.DefaultTestSSL),
		"default_snmp":                   formatAppSettingBool(settings.DefaultSNMP),
		"default_passive_ingest":         formatAppSettingBool(settings.DefaultPassiveIngest),
		"default_os_detection":           formatAppSettingBool(settings.DefaultOSDetection),
		"default_layer2":                 formatAppSettingBool(settings.DefaultLayer2),
		"default_large_range_strategy":   formatAppSettingBool(settings.DefaultLargeRangeStrategy),
		"default_zeek_auto_start":        formatAppSettingBool(settings.DefaultZeekAutoStart),
		"default_continue_on_error":      formatAppSettingBool(settings.DefaultContinueOnError),
		"default_retain_partial_results": formatAppSettingBool(settings.DefaultRetainPartialResult),
		"deployment_mode":                normalizeDeploymentMode(settings.DeploymentMode),
	}

	for key, value := range pairs {
		if err := setAppSettingTx(ctx, tx, key, value); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit app settings transaction: %w", err)
	}
	return nil
}

func defaultAppSettings() AppSettings {
	return AppSettings{
		DefaultScanTag:             "internal",
		DefaultPortTemplate:        "all-default-ports",
		DefaultPassiveMode:         "auto",
		DefaultZeekLogDir:          "/opt/zeek/logs/current",
		DefaultRouteSampling:       true,
		DefaultServiceScan:         true,
		DefaultAvahi:               false,
		DefaultTestSSL:             false,
		DefaultSNMP:                false,
		DefaultPassiveIngest:       true,
		DefaultOSDetection:         true,
		DefaultLayer2:              false,
		DefaultLargeRangeStrategy:  false,
		DefaultZeekAutoStart:       true,
		DefaultContinueOnError:     true,
		DefaultRetainPartialResult: true,
		DeploymentMode:             "standalone",
	}
}

func normalizeScanTag(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "external":
		return "external"
	default:
		return "internal"
	}
}

func normalizeDeploymentMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "distributed":
		return "distributed"
	default:
		return "standalone"
	}
}

func normalizePassiveMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "off":
		return "off"
	case "always":
		return "always"
	default:
		return "auto"
	}
}

func parseAppSettingBool(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func formatAppSettingBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func firstNonEmptySetting(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (r *SQLiteRepository) ensureProjectMetadata(ctx context.Context, projectID string, projectName string, notes string) error {
	row := r.db.QueryRowContext(ctx, `SELECT 1 FROM project_metadata WHERE project_id = ?`, projectID)
	var marker int
	switch err := row.Scan(&marker); err {
	case nil:
		return nil
	case sql.ErrNoRows:
	default:
		return fmt.Errorf("query project metadata: %w", err)
	}

	project := Project{
		ID:            projectID,
		PublicID:      generateProjectPublicID(),
		Name:          projectName,
		Description:   notes,
		Notes:         notes,
		StoragePath:   r.defaultProjectStoragePath(projectName, ""),
		TargetDBPath:  filepath.Join(r.defaultProjectStoragePath(projectName, ""), "project.sqlite"),
		OwnerUsername: currentOperatorName(),
		UpdatedAt:     time.Now().UTC(),
	}

	if err := os.MkdirAll(project.StoragePath, 0o775); err != nil {
		return fmt.Errorf("create project storage path: %w", err)
	}
	if err := adoptProjectPathOwnership(project.StoragePath); err != nil {
		return err
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO project_metadata (
			project_id, public_id, notes, storage_path, target_db_path, owner_username, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, project.ID, project.PublicID, project.Notes, project.StoragePath, project.TargetDBPath, project.OwnerUsername, project.UpdatedAt.Format(time.RFC3339Nano), project.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("insert project metadata: %w", err)
	}
	return nil
}

func upsertProjectMetadataTx(ctx context.Context, tx *sql.Tx, project Project) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO project_metadata (
			project_id, public_id, notes, storage_path, target_db_path, owner_username, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id) DO UPDATE SET
			public_id = excluded.public_id,
			notes = excluded.notes,
			storage_path = excluded.storage_path,
			target_db_path = excluded.target_db_path,
			owner_username = excluded.owner_username,
			updated_at = excluded.updated_at
	`, project.ID, project.PublicID, project.Notes, project.StoragePath, project.TargetDBPath, project.OwnerUsername, now, now)
	if err != nil {
		return fmt.Errorf("upsert project metadata: %w", err)
	}
	return nil
}

func setAppSettingTx(ctx context.Context, tx *sql.Tx, key string, value string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO app_settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("set app setting: %w", err)
	}
	return nil
}

func generateProjectPublicID() string {
	return "PRJ-" + strings.ToUpper(strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
}

func defaultProjectStoragePath(baseDataDir string, name string, publicID string) string {
	slug := slugifyProjectName(name)
	if slug == "" {
		slug = "project"
	}
	if publicID == "" {
		publicID = strings.ToLower(generateProjectPublicID())
	}
	return filepath.Join(baseDataDir, "projects", slug+"-"+strings.ToLower(publicID))
}

func currentOperatorName() string {
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" {
		return sudoUser
	}
	current, err := user.Current()
	if err != nil {
		return ""
	}
	return current.Username
}

func adoptProjectPathOwnership(path string) error {
	if err := os.Chmod(path, 0o775); err != nil {
		return fmt.Errorf("adjust project path mode: %w", err)
	}
	if uid, gid, ok := invokingUserIDs(os.Getenv); ok {
		if err := chownIfExists(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func slugifyProjectName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	var builder strings.Builder
	lastDash := false
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				builder.WriteRune('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func firstNonEmptyProject(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (r *SQLiteRepository) defaultProjectStoragePath(name string, publicID string) string {
	baseDataDir := filepath.Dir(r.Path())
	if strings.TrimSpace(baseDataDir) == "" {
		baseDataDir = DefaultDataDir()
	}
	return defaultProjectStoragePath(baseDataDir, name, publicID)
}
