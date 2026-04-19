package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type Satellite struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Kind                  string    `json:"kind"`
	Role                  string    `json:"role"`
	Status                string    `json:"status"`
	Address               string    `json:"address,omitempty"`
	Hostname              string    `json:"hostname,omitempty"`
	Platform              string    `json:"platform,omitempty"`
	Executor              string    `json:"executor,omitempty"`
	LastSeenAt            time.Time `json:"last_seen_at,omitempty"`
	RegistrationTokenHint string    `json:"registration_token_hint,omitempty"`
	TLSFingerprint        string    `json:"tls_fingerprint,omitempty"`
	Capabilities          []string  `json:"capabilities,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type SatelliteUpsertInput struct {
	ID                    string
	Name                  string
	Kind                  string
	Role                  string
	Status                string
	Address               string
	Hostname              string
	Platform              string
	Executor              string
	LastSeenAt            time.Time
	RegistrationTokenHint string
	TLSFingerprint        string
	Capabilities          []string
}

func (r *SQLiteRepository) ListSatellites(ctx context.Context) ([]Satellite, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			id,
			name,
			kind,
			role,
			status,
			address,
			hostname,
			platform,
			executor,
			last_seen_at,
			registration_token_hint,
			tls_fingerprint,
			capabilities_json,
			created_at,
			updated_at
		FROM satellites
		ORDER BY
			CASE WHEN LOWER(kind) = 'nexus' THEN 0 ELSE 1 END,
			name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list satellites: %w", err)
	}
	defer rows.Close()

	satellites := make([]Satellite, 0)
	for rows.Next() {
		var satellite Satellite
		var lastSeenAt string
		var capabilitiesJSON string
		var createdAt string
		var updatedAt string
		if err := rows.Scan(
			&satellite.ID,
			&satellite.Name,
			&satellite.Kind,
			&satellite.Role,
			&satellite.Status,
			&satellite.Address,
			&satellite.Hostname,
			&satellite.Platform,
			&satellite.Executor,
			&lastSeenAt,
			&satellite.RegistrationTokenHint,
			&satellite.TLSFingerprint,
			&capabilitiesJSON,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan satellite: %w", err)
		}
		satellite.LastSeenAt = mustParseTime(lastSeenAt)
		satellite.CreatedAt = mustParseTime(createdAt)
		satellite.UpdatedAt = mustParseTime(updatedAt)
		if err := unmarshalJSON(capabilitiesJSON, &satellite.Capabilities); err != nil {
			return nil, err
		}
		satellites = append(satellites, satellite)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate satellites: %w", err)
	}
	return satellites, nil
}

func (r *SQLiteRepository) GetSatellite(ctx context.Context, id string) (Satellite, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT
			id, name, kind, role, status,
			address, hostname, platform, executor,
			last_seen_at, registration_token_hint,
			tls_fingerprint, capabilities_json, created_at, updated_at
		FROM satellites
		WHERE id = ?
	`, strings.TrimSpace(id))

	var satellite Satellite
	var lastSeenAt, capabilitiesJSON, createdAt, updatedAt string
	if err := row.Scan(
		&satellite.ID, &satellite.Name, &satellite.Kind, &satellite.Role, &satellite.Status,
		&satellite.Address, &satellite.Hostname, &satellite.Platform, &satellite.Executor,
		&lastSeenAt, &satellite.RegistrationTokenHint,
		&satellite.TLSFingerprint, &capabilitiesJSON, &createdAt, &updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return Satellite{}, fmt.Errorf("satellite %q not found", id)
		}
		return Satellite{}, fmt.Errorf("get satellite: %w", err)
	}
	satellite.LastSeenAt = mustParseTime(lastSeenAt)
	satellite.CreatedAt = mustParseTime(createdAt)
	satellite.UpdatedAt = mustParseTime(updatedAt)
	if err := unmarshalJSON(capabilitiesJSON, &satellite.Capabilities); err != nil {
		return Satellite{}, err
	}
	return satellite, nil
}

func (r *SQLiteRepository) UpsertSatellite(ctx context.Context, input SatelliteUpsertInput) (Satellite, error) {
	id := strings.TrimSpace(input.ID)
	if id == "" {
		return Satellite{}, fmt.Errorf("satellite id is required")
	}

	now := time.Now().UTC()
	lastSeenAt := ""
	if !input.LastSeenAt.IsZero() {
		lastSeenAt = input.LastSeenAt.UTC().Format(time.RFC3339Nano)
	}
	capabilitiesJSON, err := marshalJSON(input.Capabilities)
	if err != nil {
		return Satellite{}, err
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO satellites (
			id,
			name,
			kind,
			role,
			status,
			address,
			hostname,
			platform,
			executor,
			last_seen_at,
			registration_token_hint,
			tls_fingerprint,
			capabilities_json,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			kind = excluded.kind,
			role = excluded.role,
			status = excluded.status,
			address = excluded.address,
			hostname = excluded.hostname,
			platform = excluded.platform,
			executor = excluded.executor,
			last_seen_at = excluded.last_seen_at,
			registration_token_hint = excluded.registration_token_hint,
			tls_fingerprint = excluded.tls_fingerprint,
			capabilities_json = excluded.capabilities_json,
			updated_at = excluded.updated_at
	`,
		id,
		strings.TrimSpace(input.Name),
		strings.TrimSpace(input.Kind),
		strings.TrimSpace(input.Role),
		strings.TrimSpace(input.Status),
		strings.TrimSpace(input.Address),
		strings.TrimSpace(input.Hostname),
		strings.TrimSpace(input.Platform),
		strings.TrimSpace(input.Executor),
		lastSeenAt,
		strings.TrimSpace(input.RegistrationTokenHint),
		strings.TrimSpace(input.TLSFingerprint),
		capabilitiesJSON,
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return Satellite{}, fmt.Errorf("upsert satellite: %w", err)
	}

	row := r.db.QueryRowContext(ctx, `
		SELECT
			id,
			name,
			kind,
			role,
			status,
			address,
			hostname,
			platform,
			executor,
			last_seen_at,
			registration_token_hint,
			tls_fingerprint,
			capabilities_json,
			created_at,
			updated_at
		FROM satellites
		WHERE id = ?
	`, id)

	var satellite Satellite
	var lastSeen string
	var registrationTokenHint string
	var tlsFingerprint string
	var capabilitiesStored string
	var createdAt string
	var updatedAt string
	if err := row.Scan(
		&satellite.ID,
		&satellite.Name,
		&satellite.Kind,
		&satellite.Role,
		&satellite.Status,
		&satellite.Address,
		&satellite.Hostname,
		&satellite.Platform,
		&satellite.Executor,
		&lastSeen,
		&registrationTokenHint,
		&tlsFingerprint,
		&capabilitiesStored,
		&createdAt,
		&updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return Satellite{}, fmt.Errorf("satellite %q not found after upsert", id)
		}
		return Satellite{}, fmt.Errorf("query satellite after upsert: %w", err)
	}
	satellite.LastSeenAt = mustParseTime(lastSeen)
	satellite.RegistrationTokenHint = strings.TrimSpace(registrationTokenHint)
	satellite.TLSFingerprint = strings.TrimSpace(tlsFingerprint)
	satellite.CreatedAt = mustParseTime(createdAt)
	satellite.UpdatedAt = mustParseTime(updatedAt)
	if err := unmarshalJSON(capabilitiesStored, &satellite.Capabilities); err != nil {
		return Satellite{}, err
	}
	return satellite, nil
}
