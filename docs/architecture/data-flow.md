# Data Flow: Scan Request to Evidence

## Full Sequence

```
1. Operator submits scan in Nexus UI
2. Nexus handler calls runnerclient.StartRun(req)
3. runnerclient POSTs to Satellite: POST /runs
4. Satellite apiserver authenticates (Bearer token)
5. Satellite service.StartRun() — builds job plan from template
6. Satellite returns StartRunResponse{RunID, AcceptedAt} (async — run is queued)
7. Nexus stores run record in its SQLite

--- run is executing on Satellite ---

8. Nexus subscribes to events: GET /runs/{id}/events (SSE stream)
9. Satellite emits events:
   - run.state: pending → running
   - job.state: per-job progress (nmap started, nmap succeeded, ...)
   - evidence.new: each evidence record as it is produced
   - heartbeat: periodic keepalive
   - run.state: running → completed / failed / cancelled
10. Nexus receives events, updates its own DB, pushes to UI

--- run finished ---

11. Nexus can fetch full evidence: GET /runs/{id}/evidence
12. Evidence records stored in Nexus SQLite
13. Analysis/blocking assessment runs on stored evidence
```

## Run Template

A run is started with a `template` (JSON blob) that describes:
- Which scan profiles to execute
- Target scope (IPs, CIDRs, hostnames)
- Plugin overrides (timeouts, port lists, etc.)

The template schema is owned by the Radar module on the Satellite side. The Nexus passes it as an opaque `json.RawMessage` in `StartRunRequest`.

## Evidence Records

Each scanner plugin emits `evidence.Record` values. These are:
- Normalized (all plugins emit the same shape)
- Source-tagged (which plugin produced it)
- Confidence-rated (`confirmed`, `probable`, `ambiguous`)
- Time-stamped (`observed_at`)

Records are streamed over SSE as `evidence.new` events during the run, and are also available in bulk via `GET /runs/{id}/evidence` after completion.

## SQLite Ownership

- **Nexus SQLite** — projects, runs, job_results, evidence, blocking_assessments, satellites, schedules. Owned and written by the Nexus.
- **Satellite SQLite** (if present) — local run state on the Satellite side. Not shared over the network. The Nexus never reads it directly; it fetches data via the API.

## Cancellation

The Nexus can cancel a running scan by sending `DELETE /runs/{id}`. The Satellite cancels the running job plan via context cancellation and emits a final `run.state: cancelled` event.
