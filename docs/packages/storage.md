# Package: internal/shared/storage

SQLite persistence layer for the Nexus. All database access goes through `SQLiteRepository`. The file lives on disk local to the Nexus binary.

## Tables

### projects
```sql
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
)
```

### runs
```sql
CREATE TABLE IF NOT EXISTS runs (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    template_name TEXT NOT NULL DEFAULT '',
    template_path TEXT NOT NULL DEFAULT '',
    mode          TEXT NOT NULL,
    -- additional state/timing columns
)
```

### job_results
Per-job execution results for a run. Linked to `runs.id`.

### evidence
Evidence records stored by the Nexus after fetching from Satellite. One row per `evidence.Record`.

Key columns: `run_id`, `record_id`, `source`, `kind`, `target`, `port`, `protocol`, `summary`, `raw_ref`, `attributes_json`, `confidence`, `observed_at`

### blocking_assessments
Output of the analysis layer. Stores verdict per (run, target, port).

Verdict values: `reachable`, `confirmed_blocked`, `probable_blocked`, `ambiguous`

### reevaluation_hints
Suggestions from the analysis layer to re-run specific targets/ports.

### assets
Tracked assets across runs. An asset is identified by `identity_key` (derived from primary target) and linked to a project.

### asset_observations
One row per run that observed a given asset. Tracks hostname, open ports, last seen state.

### scheduled_scans
Scan schedules (cron-like). Schema exists; scheduling logic is a planned feature.

### satellites
```sql
CREATE TABLE IF NOT EXISTS satellites (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    kind                    TEXT NOT NULL DEFAULT '',
    role                    TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT '',
    address                 TEXT,
    hostname                TEXT,
    platform                TEXT,
    executor                TEXT,
    last_seen_at            TEXT,
    registration_token_hint TEXT,
    tls_fingerprint         TEXT NOT NULL DEFAULT '',
    capabilities_json       TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
)
```

`tls_fingerprint` — SHA-256 hex of the Satellite's leaf cert (DER). Set during TOFU registration. Used by `runnerclient` for cert pinning.
`capabilities_json` — JSON array of capability strings from the last `/capabilities` poll.
`registration_token_hint` — partial token (first/last chars) for operator display only. Full token is not stored.

### app_settings
Key/value store for application-level settings (e.g., operator preferences).

### run_acknowledgements
Operator acknowledgements for completed runs (used to mark runs as reviewed).

## Migrations

Schema migrations run at startup in `sqlite.go`. The `ensureColumnExists` helper is used for additive migrations (ALTER TABLE ADD COLUMN) so that existing databases are upgraded without data loss.

Current additive migrations:
- `assets.manual_reevaluate` INTEGER column
- `satellites.tls_fingerprint` TEXT column

## Timestamps

All timestamps are stored as `TEXT` in RFC3339Nano format (UTC). Read back via `mustParseTime()`.

## Repository Interface

`SQLiteRepository` implements all read/write operations. It is created via `storage.NewSQLiteRepository(dbPath)`.

Key operations:
- `ListSatellites`, `GetSatellite`, `UpsertSatellite`, `DeleteSatellite`
- `ListProjects`, `GetProject`, `CreateProject`
- `ListRuns`, `GetRun`, `CreateRun`, `UpdateRun`
- `ListEvidence`, `InsertEvidence`
- `ListAssets`, `UpsertAsset`
