package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ScheduledScan struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	SourceRunID  string    `json:"source_run_id,omitempty"`
	SourceAssetID string   `json:"source_asset_id,omitempty"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	ScopeInput   string    `json:"scope_input"`
	ExecuteAt    time.Time `json:"execute_at"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

type ScheduledScanInput struct {
	ProjectID     string
	SourceRunID   string
	SourceAssetID string
	Name          string
	Kind          string
	ScopeInput    string
	ExecuteAt     time.Time
}

func (r *SQLiteRepository) CreateScheduledScan(ctx context.Context, input ScheduledScanInput) (ScheduledScan, error) {
	if strings.TrimSpace(input.ProjectID) == "" {
		return ScheduledScan{}, fmt.Errorf("project_id is required")
	}
	if strings.TrimSpace(input.ScopeInput) == "" {
		return ScheduledScan{}, fmt.Errorf("scope_input is required")
	}
	if input.ExecuteAt.IsZero() {
		return ScheduledScan{}, fmt.Errorf("execute_at is required")
	}

	scheduled := ScheduledScan{
		ID:            uuid.NewString(),
		ProjectID:     strings.TrimSpace(input.ProjectID),
		SourceRunID:   strings.TrimSpace(input.SourceRunID),
		SourceAssetID: strings.TrimSpace(input.SourceAssetID),
		Name:          firstNonEmptyProject(strings.TrimSpace(input.Name), "Scheduled Reevaluation"),
		Kind:          firstNonEmptyProject(strings.TrimSpace(input.Kind), "timebased-reevaluation"),
		ScopeInput:    strings.TrimSpace(input.ScopeInput),
		ExecuteAt:     input.ExecuteAt.UTC(),
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scheduled_scans (
			id, project_id, source_run_id, source_asset_id, name, kind, scope_input, execute_at, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scheduled.ID, scheduled.ProjectID, scheduled.SourceRunID, scheduled.SourceAssetID, scheduled.Name, scheduled.Kind, scheduled.ScopeInput, scheduled.ExecuteAt.Format(time.RFC3339Nano), scheduled.Status, scheduled.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return ScheduledScan{}, fmt.Errorf("insert scheduled scan: %w", err)
	}

	return scheduled, nil
}

func (r *SQLiteRepository) ListScheduledScansByRun(ctx context.Context, runID string) ([]ScheduledScan, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, source_run_id, source_asset_id, name, kind, scope_input, execute_at, status, created_at
		FROM scheduled_scans
		WHERE source_run_id = ?
		ORDER BY execute_at ASC, created_at ASC
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query scheduled scans by run: %w", err)
	}
	defer rows.Close()

	scheduled := make([]ScheduledScan, 0)
	for rows.Next() {
		var item ScheduledScan
		var executeAt string
		var createdAt string
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.SourceRunID, &item.SourceAssetID, &item.Name, &item.Kind, &item.ScopeInput, &executeAt, &item.Status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan scheduled scan: %w", err)
		}
		item.ExecuteAt = mustParseTime(executeAt)
		item.CreatedAt = mustParseTime(createdAt)
		scheduled = append(scheduled, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scheduled scans: %w", err)
	}
	return scheduled, nil
}

func (r *SQLiteRepository) ListScheduledScansByAsset(ctx context.Context, assetID string) ([]ScheduledScan, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, source_run_id, source_asset_id, name, kind, scope_input, execute_at, status, created_at
		FROM scheduled_scans
		WHERE source_asset_id = ?
		ORDER BY execute_at ASC, created_at ASC
	`, assetID)
	if err != nil {
		return nil, fmt.Errorf("query scheduled scans by asset: %w", err)
	}
	defer rows.Close()

	scheduled := make([]ScheduledScan, 0)
	for rows.Next() {
		var item ScheduledScan
		var executeAt string
		var createdAt string
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.SourceRunID, &item.SourceAssetID, &item.Name, &item.Kind, &item.ScopeInput, &executeAt, &item.Status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan scheduled scan: %w", err)
		}
		item.ExecuteAt = mustParseTime(executeAt)
		item.CreatedAt = mustParseTime(createdAt)
		scheduled = append(scheduled, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scheduled scans: %w", err)
	}
	return scheduled, nil
}
