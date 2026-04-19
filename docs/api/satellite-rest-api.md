# Satellite REST API Reference

API version: `v1`
Base path: `https://<satellite-host>:<port>` (default port: 8765)
Transport: HTTPS only (self-signed cert, see `security/tls-cert-pinning.md`)
Auth: Bearer token on all endpoints except `/health`

## GET /health

Reachability probe. **Unauthenticated.**

Response `200 OK`:
```json
{
  "status": "ok",
  "version": "0.1.0-dev",
  "api_version": "v1",
  "satellite_id": "a3f1...",
  "started_at": "2026-04-19T10:00:00Z"
}
```

Status values: `ok`, `degraded`, `error`

Used by the Nexus during satellite registration (TOFU probe) and for health checks.

---

## GET /capabilities

Returns which scanner plugins are available on this Satellite. **Authenticated.**

Response `200 OK`:
```json
{
  "satellite_id": "a3f1...",
  "version": "0.1.0-dev",
  "api_version": "v1",
  "plugins": [
    {
      "name": "nmap",
      "kinds": ["port-scan"],
      "available": true,
      "version": "7.94"
    },
    {
      "name": "zeek",
      "kinds": ["traffic-analysis"],
      "available": false,
      "reason": "zeek binary not found"
    }
  ]
}
```

The Nexus uses this to determine which scan options to offer in the UI. Plugins with `available: false` must not be included in run requests.

---

## POST /runs

Start a new scan run. **Authenticated.**

Request body:
```json
{
  "project_id": "proj-abc123",
  "template": { ... },
  "overrides": {
    "timeout": "120s"
  }
}
```

- `template` — opaque JSON blob, parsed by the Radar module on the Satellite. Schema defined in `internal/modules/radar`.
- `overrides` — optional key/value pairs to override template defaults.

Response `202 Accepted`:
```json
{
  "run_id": "run-xyz789",
  "accepted_at": "2026-04-19T10:05:00Z"
}
```

The run is started asynchronously. Use `/runs/{id}/events` for live progress or `/runs/{id}/status` for polling.

Error `409 Conflict` — a run with the same ID already exists.
Error `400 Bad Request` — invalid template or missing required fields.
Error `503 Service Unavailable` — Satellite is not ready to accept runs.

---

## GET /runs

List all runs known to this Satellite. **Authenticated.**

Response `200 OK`:
```json
{
  "runs": [
    {
      "run_id": "run-xyz789",
      "project_id": "proj-abc123",
      "state": "running",
      "started_at": "2026-04-19T10:05:00Z",
      "finished_at": null
    }
  ]
}
```

---

## GET /runs/{id}/status

Snapshot status and per-job progress. **Authenticated.**

Response `200 OK`:
```json
{
  "run_id": "run-xyz789",
  "project_id": "proj-abc123",
  "state": "running",
  "started_at": "2026-04-19T10:05:00Z",
  "finished_at": null,
  "jobs": [
    {
      "job_id": "job-1",
      "kind": "port-scan",
      "plugin": "nmap",
      "state": "succeeded",
      "started_at": "2026-04-19T10:05:02Z",
      "finished_at": "2026-04-19T10:05:45Z"
    }
  ],
  "summary": {
    "total": 5,
    "pending": 1,
    "running": 1,
    "succeeded": 3,
    "failed": 0,
    "skipped": 0
  }
}
```

Run states: `pending`, `running`, `completed`, `failed`, `cancelled`
Job states: `pending`, `running`, `succeeded`, `failed`, `skipped`

---

## GET /runs/{id}/events

Live SSE stream of run events. **Authenticated.**
Content-Type: `text/event-stream`

The connection stays open until the run reaches a terminal state or the client disconnects.
Each message is a JSON-encoded `api.Event` envelope. See `api/sse-events.md` for full event type reference.

---

## GET /runs/{id}/evidence

All evidence records collected by this run. **Authenticated.** Available during and after a run.

Response `200 OK`:
```json
{
  "run_id": "run-xyz789",
  "records": [ ... ]
}
```

Each record is an `evidence.Record`. See `packages/evidence.md`.

---

## GET /runs/{id}/jobs

Job plan and execution detail. **Authenticated.**

Returns the full list of jobs that were planned for this run, including plugin assignment and execution timing.

---

## DELETE /runs/{id}

Cancel a running scan. **Authenticated.**

Response `204 No Content` on success.
Error `404 Not Found` if run does not exist.
Error `409 Conflict` if run is already in a terminal state.

---

## Error Responses

All non-2xx responses return:
```json
{
  "code": "not_found",
  "message": "run xyz789 not found",
  "detail": "optional extra context"
}
```

Error codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `unavailable`, `internal`, `plugin_missing`, `invalid_request`
