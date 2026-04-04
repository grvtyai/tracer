package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
)

type AssetSummary struct {
	ID                       string    `json:"id"`
	ProjectID                string    `json:"project_id"`
	ProjectName              string    `json:"project_name,omitempty"`
	IdentityKey              string    `json:"identity_key"`
	PrimaryTarget            string    `json:"primary_target"`
	CurrentHostname          string    `json:"current_hostname,omitempty"`
	CurrentOS                string    `json:"current_os,omitempty"`
	CurrentVendor            string    `json:"current_vendor,omitempty"`
	CurrentProduct           string    `json:"current_product,omitempty"`
	CurrentOpenPorts         []int     `json:"current_open_ports,omitempty"`
	DeviceTypeGuess          string    `json:"device_type_guess,omitempty"`
	DeviceTypeConfidence     string    `json:"device_type_confidence,omitempty"`
	ConnectionTypeGuess      string    `json:"connection_type_guess,omitempty"`
	ConnectionTypeConfidence string    `json:"connection_type_confidence,omitempty"`
	ManualDisplayName        string    `json:"manual_display_name,omitempty"`
	ManualDeviceType         string    `json:"manual_device_type,omitempty"`
	ManualConnectionType     string    `json:"manual_connection_type,omitempty"`
	ManualNotes              string    `json:"manual_notes,omitempty"`
	ManualTags               []string  `json:"manual_tags,omitempty"`
	DisplayName              string    `json:"display_name"`
	EffectiveDeviceType      string    `json:"effective_device_type"`
	EffectiveConnectionType  string    `json:"effective_connection_type"`
	Tags                     []string  `json:"tags,omitempty"`
	ObservationCount         int       `json:"observation_count"`
	LastRunID                string    `json:"last_run_id,omitempty"`
	FirstSeenAt              time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt               time.Time `json:"last_seen_at,omitempty"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type AssetObservation struct {
	ID                       int       `json:"id"`
	AssetID                  string    `json:"asset_id"`
	RunID                    string    `json:"run_id"`
	Target                   string    `json:"target"`
	Hostname                 string    `json:"hostname,omitempty"`
	OSName                   string    `json:"os_name,omitempty"`
	Vendor                   string    `json:"vendor,omitempty"`
	Product                  string    `json:"product,omitempty"`
	OpenPorts                []int     `json:"open_ports,omitempty"`
	EvidenceCount            int       `json:"evidence_count"`
	Verdict                  string    `json:"verdict,omitempty"`
	Confidence               string    `json:"confidence,omitempty"`
	DeviceTypeGuess          string    `json:"device_type_guess,omitempty"`
	DeviceTypeConfidence     string    `json:"device_type_confidence,omitempty"`
	ConnectionTypeGuess      string    `json:"connection_type_guess,omitempty"`
	ConnectionTypeConfidence string    `json:"connection_type_confidence,omitempty"`
	ObservedAt               time.Time `json:"observed_at,omitempty"`
}

type AssetDetails struct {
	Asset        AssetSummary       `json:"asset"`
	Observations []AssetObservation `json:"observations,omitempty"`
}

type AssetUpdateInput struct {
	DisplayName    string
	DeviceType     string
	ConnectionType string
	Tags           []string
	Notes          string
}

type observedAsset struct {
	IdentityKey              string
	PrimaryTarget            string
	Hostname                 string
	OSName                   string
	Vendor                   string
	Product                  string
	OpenPorts                []int
	EvidenceCount            int
	Verdict                  string
	Confidence               string
	ObservedAt               time.Time
	DeviceTypeGuess          string
	DeviceTypeConfidence     string
	ConnectionTypeGuess      string
	ConnectionTypeConfidence string
}

func (r *SQLiteRepository) ListAssets(ctx context.Context, projectRef string) ([]AssetSummary, error) {
	assets, err := r.queryAssets(ctx, projectRef)
	if err != nil {
		return nil, err
	}
	if len(assets) > 0 {
		return assets, nil
	}

	if err := r.ensureAssetsForProject(ctx, projectRef); err != nil {
		return nil, err
	}

	return r.queryAssets(ctx, projectRef)
}

func (r *SQLiteRepository) queryAssets(ctx context.Context, projectRef string) ([]AssetSummary, error) {
	query := `
		SELECT
			a.id,
			a.project_id,
			p.name,
			a.identity_key,
			a.primary_target,
			a.current_hostname,
			a.current_os,
			a.current_vendor,
			a.current_product,
			a.current_open_ports_json,
			a.device_type_guess,
			a.device_type_confidence,
			a.connection_type_guess,
			a.connection_type_confidence,
			a.manual_display_name,
			a.manual_device_type,
			a.manual_connection_type,
			a.manual_notes,
			a.manual_tags_json,
			a.last_run_id,
			a.first_seen_at,
			a.last_seen_at,
			a.created_at,
			a.updated_at,
			COUNT(obs.id) AS observation_count
		FROM assets a
		INNER JOIN projects p ON p.id = a.project_id
		LEFT JOIN asset_observations obs ON obs.asset_id = a.id
	`

	args := make([]any, 0, 2)
	if trimmed := strings.TrimSpace(projectRef); trimmed != "" {
		query += ` WHERE a.project_id = ? OR p.name = ?`
		args = append(args, trimmed, trimmed)
	}

	query += `
		GROUP BY
			a.id, a.project_id, p.name, a.identity_key, a.primary_target, a.current_hostname, a.current_os,
			a.current_vendor, a.current_product, a.current_open_ports_json, a.device_type_guess, a.device_type_confidence,
			a.connection_type_guess, a.connection_type_confidence, a.manual_display_name, a.manual_device_type,
			a.manual_connection_type, a.manual_notes, a.manual_tags_json, a.last_run_id, a.first_seen_at,
			a.last_seen_at, a.created_at, a.updated_at
		ORDER BY p.name ASC, a.primary_target ASC
	`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	assets := make([]AssetSummary, 0)
	for rows.Next() {
		asset, err := scanAssetSummary(rows)
		if err != nil {
			return nil, err
		}
		assets = append(assets, hydrateAssetSummary(asset))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}

	return assets, nil
}

func (r *SQLiteRepository) GetAsset(ctx context.Context, assetID string) (AssetDetails, error) {
	var details AssetDetails

	row := r.db.QueryRowContext(ctx, `
		SELECT
			a.id,
			a.project_id,
			p.name,
			a.identity_key,
			a.primary_target,
			a.current_hostname,
			a.current_os,
			a.current_vendor,
			a.current_product,
			a.current_open_ports_json,
			a.device_type_guess,
			a.device_type_confidence,
			a.connection_type_guess,
			a.connection_type_confidence,
			a.manual_display_name,
			a.manual_device_type,
			a.manual_connection_type,
			a.manual_notes,
			a.manual_tags_json,
			a.last_run_id,
			a.first_seen_at,
			a.last_seen_at,
			a.created_at,
			a.updated_at,
			COUNT(obs.id) AS observation_count
		FROM assets a
		INNER JOIN projects p ON p.id = a.project_id
		LEFT JOIN asset_observations obs ON obs.asset_id = a.id
		WHERE a.id = ?
		GROUP BY
			a.id, a.project_id, p.name, a.identity_key, a.primary_target, a.current_hostname, a.current_os,
			a.current_vendor, a.current_product, a.current_open_ports_json, a.device_type_guess, a.device_type_confidence,
			a.connection_type_guess, a.connection_type_confidence, a.manual_display_name, a.manual_device_type,
			a.manual_connection_type, a.manual_notes, a.manual_tags_json, a.last_run_id, a.first_seen_at,
			a.last_seen_at, a.created_at, a.updated_at
	`, assetID)

	asset, err := scanAssetSummaryRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return AssetDetails{}, fmt.Errorf("asset %q not found", assetID)
		}
		return AssetDetails{}, err
	}

	observations, err := r.loadAssetObservations(ctx, assetID)
	if err != nil {
		return AssetDetails{}, err
	}

	details.Asset = hydrateAssetSummary(asset)
	details.Observations = observations
	return details, nil
}

func (r *SQLiteRepository) UpdateAsset(ctx context.Context, assetID string, input AssetUpdateInput) (AssetDetails, error) {
	manualTagsJSON, err := marshalJSON(cleanTags(input.Tags))
	if err != nil {
		return AssetDetails{}, err
	}

	_, err = r.db.ExecContext(ctx, `
		UPDATE assets
		SET manual_display_name = ?, manual_device_type = ?, manual_connection_type = ?,
			manual_notes = ?, manual_tags_json = ?, updated_at = ?
		WHERE id = ?
	`, strings.TrimSpace(input.DisplayName), normalizeEditableType(input.DeviceType), normalizeEditableConnectionType(input.ConnectionType), strings.TrimSpace(input.Notes), manualTagsJSON, time.Now().UTC().Format(time.RFC3339Nano), assetID)
	if err != nil {
		return AssetDetails{}, fmt.Errorf("update asset: %w", err)
	}

	return r.GetAsset(ctx, assetID)
}

func (r *SQLiteRepository) ensureAssetsForProject(ctx context.Context, projectRef string) error {
	runs, err := r.ListRuns(ctx, projectRef)
	if err != nil {
		return err
	}

	for _, run := range runs {
		if err := r.syncAssetsForRun(ctx, run.ID); err != nil {
			return err
		}
	}

	return nil
}

func (r *SQLiteRepository) syncAssetsForRun(ctx context.Context, runID string) error {
	run, err := r.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if run.Run.ProjectID == "" {
		return nil
	}

	observed := deriveObservedAssets(run)
	if len(observed) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin asset sync transaction: %w", err)
	}
	defer tx.Rollback()

	for _, item := range observed {
		currentOpenPortsJSON, err := marshalJSON(item.OpenPorts)
		if err != nil {
			return err
		}

		now := time.Now().UTC().Format(time.RFC3339Nano)
		observedAt := item.ObservedAt.Format(time.RFC3339Nano)
		if item.ObservedAt.IsZero() {
			observedAt = now
		}

		assetID, err := r.upsertAssetTx(ctx, tx, run.Run.ProjectID, run.Run.ProjectName, run.Run.ID, item, currentOpenPortsJSON, observedAt, now)
		if err != nil {
			return err
		}

		if err := r.upsertAssetObservationTx(ctx, tx, assetID, run.Run.ID, item); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit asset sync transaction: %w", err)
	}

	return nil
}

func (r *SQLiteRepository) upsertAssetTx(ctx context.Context, tx *sql.Tx, projectID string, projectName string, runID string, item observedAsset, currentOpenPortsJSON string, observedAt string, now string) (string, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT id
		FROM assets
		WHERE project_id = ? AND identity_key = ?
	`, projectID, item.IdentityKey)

	var assetID string
	switch err := row.Scan(&assetID); err {
	case nil:
	case sql.ErrNoRows:
		assetID = uuid.NewString()
		manualTagsJSON, err := marshalJSON([]string{})
		if err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO assets (
				id, project_id, identity_key, primary_target, current_hostname, current_os, current_vendor,
				current_product, current_open_ports_json, device_type_guess, device_type_confidence,
				connection_type_guess, connection_type_confidence, manual_display_name, manual_device_type,
				manual_connection_type, manual_notes, manual_tags_json, last_run_id, first_seen_at, last_seen_at,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', ?, ?, ?, ?, ?, ?)
		`, assetID, projectID, item.IdentityKey, item.PrimaryTarget, item.Hostname, item.OSName, item.Vendor, item.Product, currentOpenPortsJSON, item.DeviceTypeGuess, item.DeviceTypeConfidence, item.ConnectionTypeGuess, item.ConnectionTypeConfidence, manualTagsJSON, runID, observedAt, observedAt, now, now)
		if err != nil {
			return "", fmt.Errorf("insert asset: %w", err)
		}
	default:
		return "", fmt.Errorf("query asset: %w", err)
	}

	_, err := tx.ExecContext(ctx, `
		UPDATE assets
		SET primary_target = ?, current_hostname = ?, current_os = ?, current_vendor = ?, current_product = ?,
			current_open_ports_json = ?, device_type_guess = ?, device_type_confidence = ?,
			connection_type_guess = ?, connection_type_confidence = ?, last_run_id = ?, last_seen_at = ?, updated_at = ?
		WHERE id = ?
	`, item.PrimaryTarget, item.Hostname, item.OSName, item.Vendor, item.Product, currentOpenPortsJSON, item.DeviceTypeGuess, item.DeviceTypeConfidence, item.ConnectionTypeGuess, item.ConnectionTypeConfidence, runID, observedAt, now, assetID)
	if err != nil {
		return "", fmt.Errorf("update asset: %w", err)
	}

	return assetID, nil
}

func (r *SQLiteRepository) upsertAssetObservationTx(ctx context.Context, tx *sql.Tx, assetID string, runID string, item observedAsset) error {
	openPortsJSON, err := marshalJSON(item.OpenPorts)
	if err != nil {
		return err
	}
	rawJSON, err := marshalJSON(item)
	if err != nil {
		return err
	}

	observedAt := item.ObservedAt.Format(time.RFC3339Nano)
	if item.ObservedAt.IsZero() {
		observedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO asset_observations (
			asset_id, run_id, target, hostname, os_name, vendor, product, open_ports_json, evidence_count,
			verdict, confidence, device_type_guess, device_type_confidence, connection_type_guess,
			connection_type_confidence, observed_at, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(asset_id, run_id) DO UPDATE SET
			target = excluded.target,
			hostname = excluded.hostname,
			os_name = excluded.os_name,
			vendor = excluded.vendor,
			product = excluded.product,
			open_ports_json = excluded.open_ports_json,
			evidence_count = excluded.evidence_count,
			verdict = excluded.verdict,
			confidence = excluded.confidence,
			device_type_guess = excluded.device_type_guess,
			device_type_confidence = excluded.device_type_confidence,
			connection_type_guess = excluded.connection_type_guess,
			connection_type_confidence = excluded.connection_type_confidence,
			observed_at = excluded.observed_at,
			raw_json = excluded.raw_json
	`, assetID, runID, item.PrimaryTarget, item.Hostname, item.OSName, item.Vendor, item.Product, openPortsJSON, item.EvidenceCount, item.Verdict, item.Confidence, item.DeviceTypeGuess, item.DeviceTypeConfidence, item.ConnectionTypeGuess, item.ConnectionTypeConfidence, observedAt, rawJSON)
	if err != nil {
		return fmt.Errorf("upsert asset observation: %w", err)
	}
	return nil
}

func (r *SQLiteRepository) loadAssetObservations(ctx context.Context, assetID string) ([]AssetObservation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, asset_id, run_id, target, hostname, os_name, vendor, product, open_ports_json,
			evidence_count, verdict, confidence, device_type_guess, device_type_confidence,
			connection_type_guess, connection_type_confidence, observed_at
		FROM asset_observations
		WHERE asset_id = ?
		ORDER BY observed_at DESC, id DESC
	`, assetID)
	if err != nil {
		return nil, fmt.Errorf("query asset observations: %w", err)
	}
	defer rows.Close()

	observations := make([]AssetObservation, 0)
	for rows.Next() {
		var observation AssetObservation
		var openPortsJSON string
		var observedAt string
		if err := rows.Scan(&observation.ID, &observation.AssetID, &observation.RunID, &observation.Target, &observation.Hostname, &observation.OSName, &observation.Vendor, &observation.Product, &openPortsJSON, &observation.EvidenceCount, &observation.Verdict, &observation.Confidence, &observation.DeviceTypeGuess, &observation.DeviceTypeConfidence, &observation.ConnectionTypeGuess, &observation.ConnectionTypeConfidence, &observedAt); err != nil {
			return nil, fmt.Errorf("scan asset observation: %w", err)
		}
		if err := unmarshalJSON(openPortsJSON, &observation.OpenPorts); err != nil {
			return nil, err
		}
		observation.ObservedAt = mustParseTime(observedAt)
		observations = append(observations, observation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset observations: %w", err)
	}

	return observations, nil
}

func scanAssetSummary(rows *sql.Rows) (AssetSummary, error) {
	var asset AssetSummary
	var currentOpenPortsJSON string
	var manualTagsJSON string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := rows.Scan(
		&asset.ID,
		&asset.ProjectID,
		&asset.ProjectName,
		&asset.IdentityKey,
		&asset.PrimaryTarget,
		&asset.CurrentHostname,
		&asset.CurrentOS,
		&asset.CurrentVendor,
		&asset.CurrentProduct,
		&currentOpenPortsJSON,
		&asset.DeviceTypeGuess,
		&asset.DeviceTypeConfidence,
		&asset.ConnectionTypeGuess,
		&asset.ConnectionTypeConfidence,
		&asset.ManualDisplayName,
		&asset.ManualDeviceType,
		&asset.ManualConnectionType,
		&asset.ManualNotes,
		&manualTagsJSON,
		&asset.LastRunID,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
		&asset.ObservationCount,
	); err != nil {
		return AssetSummary{}, fmt.Errorf("scan asset summary: %w", err)
	}

	if err := unmarshalJSON(currentOpenPortsJSON, &asset.CurrentOpenPorts); err != nil {
		return AssetSummary{}, err
	}
	if err := unmarshalJSON(manualTagsJSON, &asset.ManualTags); err != nil {
		return AssetSummary{}, err
	}
	asset.FirstSeenAt = mustParseTime(firstSeenAt)
	asset.LastSeenAt = mustParseTime(lastSeenAt)
	asset.CreatedAt = mustParseTime(createdAt)
	asset.UpdatedAt = mustParseTime(updatedAt)
	return asset, nil
}

func scanAssetSummaryRow(row *sql.Row) (AssetSummary, error) {
	var asset AssetSummary
	var currentOpenPortsJSON string
	var manualTagsJSON string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&asset.ID,
		&asset.ProjectID,
		&asset.ProjectName,
		&asset.IdentityKey,
		&asset.PrimaryTarget,
		&asset.CurrentHostname,
		&asset.CurrentOS,
		&asset.CurrentVendor,
		&asset.CurrentProduct,
		&currentOpenPortsJSON,
		&asset.DeviceTypeGuess,
		&asset.DeviceTypeConfidence,
		&asset.ConnectionTypeGuess,
		&asset.ConnectionTypeConfidence,
		&asset.ManualDisplayName,
		&asset.ManualDeviceType,
		&asset.ManualConnectionType,
		&asset.ManualNotes,
		&manualTagsJSON,
		&asset.LastRunID,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
		&asset.ObservationCount,
	); err != nil {
		return AssetSummary{}, err
	}

	if err := unmarshalJSON(currentOpenPortsJSON, &asset.CurrentOpenPorts); err != nil {
		return AssetSummary{}, err
	}
	if err := unmarshalJSON(manualTagsJSON, &asset.ManualTags); err != nil {
		return AssetSummary{}, err
	}
	asset.FirstSeenAt = mustParseTime(firstSeenAt)
	asset.LastSeenAt = mustParseTime(lastSeenAt)
	asset.CreatedAt = mustParseTime(createdAt)
	asset.UpdatedAt = mustParseTime(updatedAt)
	return asset, nil
}

func hydrateAssetSummary(asset AssetSummary) AssetSummary {
	asset.DisplayName = strings.TrimSpace(asset.ManualDisplayName)
	if asset.DisplayName == "" {
		asset.DisplayName = firstNonEmptyAsset(asset.CurrentHostname, asset.PrimaryTarget)
	}

	asset.EffectiveDeviceType = normalizeEditableType(asset.ManualDeviceType)
	if asset.EffectiveDeviceType == "" {
		asset.EffectiveDeviceType = normalizeEditableType(asset.DeviceTypeGuess)
	}
	if asset.EffectiveDeviceType == "" {
		asset.EffectiveDeviceType = "unknown"
	}

	asset.EffectiveConnectionType = normalizeEditableConnectionType(asset.ManualConnectionType)
	if asset.EffectiveConnectionType == "" {
		asset.EffectiveConnectionType = normalizeEditableConnectionType(asset.ConnectionTypeGuess)
	}
	if asset.EffectiveConnectionType == "" {
		asset.EffectiveConnectionType = "unknown"
	}

	asset.Tags = cleanTags(asset.ManualTags)
	return asset
}

func deriveObservedAssets(run RunDetails) []observedAsset {
	perTarget := make(map[string]*observedAsset)
	portSet := make(map[string]map[int]struct{})

	for _, record := range run.Evidence {
		target := normalizeAssetTarget(record.Target)
		if target == "" {
			continue
		}

		entry, ok := perTarget[target]
		if !ok {
			entry = &observedAsset{
				IdentityKey:   target,
				PrimaryTarget: target,
			}
			perTarget[target] = entry
		}

		entry.EvidenceCount++
		if !record.ObservedAt.IsZero() && record.ObservedAt.After(entry.ObservedAt) {
			entry.ObservedAt = record.ObservedAt
		}

		if hostname := strings.TrimSpace(record.Attributes["hostname"]); hostname != "" {
			entry.Hostname = hostname
		}
		if osName := firstNonEmptyAsset(record.Attributes["os_name"], record.Attributes["os_family"], record.Attributes["os_type"]); osName != "" {
			entry.OSName = osName
		}
		if vendor := strings.TrimSpace(record.Attributes["vendor"]); vendor != "" {
			entry.Vendor = vendor
		}
		if product := firstNonEmptyAsset(record.Attributes["product"], record.Attributes["device_type"], record.Attributes["web_server"]); product != "" {
			entry.Product = product
		}
		if record.Port > 0 {
			switch record.Kind {
			case "open_port", "service_fingerprint", "http_probe", "l7_grab":
				if _, ok := portSet[target]; !ok {
					portSet[target] = make(map[int]struct{})
				}
				portSet[target][record.Port] = struct{}{}
			}
		}
	}

	for _, assessment := range run.Blocking {
		target := normalizeAssetTarget(assessment.Target)
		if target == "" || assessment.Port != 0 {
			continue
		}
		entry, ok := perTarget[target]
		if !ok {
			entry = &observedAsset{
				IdentityKey:   target,
				PrimaryTarget: target,
			}
			perTarget[target] = entry
		}
		entry.Verdict = string(assessment.Verdict)
		entry.Confidence = string(assessment.Confidence)
	}

	observed := make([]observedAsset, 0, len(perTarget))
	for target, entry := range perTarget {
		if ports, ok := portSet[target]; ok {
			entry.OpenPorts = make([]int, 0, len(ports))
			for port := range ports {
				entry.OpenPorts = append(entry.OpenPorts, port)
			}
			slices.Sort(entry.OpenPorts)
		}
		if entry.Verdict == "" {
			if len(entry.OpenPorts) > 0 {
				entry.Verdict = string(evidence.VerdictReachable)
				entry.Confidence = string(evidence.ConfidenceConfirmed)
			} else {
				entry.Verdict = "observed"
			}
		}
		entry.DeviceTypeGuess, entry.DeviceTypeConfidence = inferDeviceType(*entry)
		entry.ConnectionTypeGuess, entry.ConnectionTypeConfidence = inferConnectionType(*entry)
		observed = append(observed, *entry)
	}

	slices.SortFunc(observed, func(a, b observedAsset) int {
		return strings.Compare(a.PrimaryTarget, b.PrimaryTarget)
	})
	return observed
}

func inferDeviceType(item observedAsset) (string, string) {
	joined := strings.ToLower(strings.Join([]string{
		item.Hostname,
		item.OSName,
		item.Vendor,
		item.Product,
	}, " "))

	hasPort := func(port int) bool {
		return slices.Contains(item.OpenPorts, port)
	}

	switch {
	case containsAny(joined, "iphone", "android", "pixel", "galaxy", "smartphone", "mobile"):
		return "smartphone", string(evidence.ConfidenceProbable)
	case containsAny(joined, "ipad", "tablet"):
		return "tablet", string(evidence.ConfidenceProbable)
	case containsAny(joined, "printer", "epson", "brother", "hp laser", "laserjet") || hasPort(631) || hasPort(9100) || hasPort(515):
		return "printer", string(evidence.ConfidenceProbable)
	case containsAny(joined, "fritz", "router", "gateway", "access point") || (hasPort(53) && hasPort(80) && hasPort(443)):
		return "router", string(evidence.ConfidenceConfirmed)
	case containsAny(joined, "camera", "chromecast", "sonos", "smart tv", "alexa", "echo", "nest", "iot", "roku"):
		return "iot", string(evidence.ConfidenceProbable)
	case containsAny(joined, "windows", "macos", "laptop", "desktop", "workstation"):
		return "workstation", string(evidence.ConfidenceProbable)
	case containsAny(joined, "ubuntu", "debian", "linux", "server", "nas") || hasPort(22) || hasPort(25):
		return "server", string(evidence.ConfidenceProbable)
	default:
		return "unknown", string(evidence.ConfidenceAmbiguous)
	}
}

func inferConnectionType(item observedAsset) (string, string) {
	deviceType, _ := inferDeviceType(item)
	switch deviceType {
	case "smartphone", "tablet":
		return "wifi", string(evidence.ConfidenceProbable)
	case "server", "router", "printer":
		return "wired", string(evidence.ConfidenceProbable)
	default:
		return "unknown", string(evidence.ConfidenceAmbiguous)
	}
}

func normalizeAssetTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if prefix, err := netip.ParsePrefix(trimmed); err == nil {
		return prefix.String()
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.String()
	}
	return trimmed
}

func normalizeEditableType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown":
		return ""
	case "smartphone", "tablet", "workstation", "server", "iot", "router", "printer":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeEditableConnectionType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown":
		return ""
	case "wifi", "wired":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func cleanTags(tags []string) []string {
	seen := make(map[string]struct{})
	cleaned := make([]string, 0, len(tags))
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, trimmed)
	}
	slices.Sort(cleaned)
	return cleaned
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func firstNonEmptyAsset(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
