# SSE Event Stream

## Endpoint

`GET /runs/{id}/events`

Content-Type: `text/event-stream`
Auth: Bearer token required

The connection stays open for the lifetime of the run. When the run reaches a terminal state (`completed`, `failed`, `cancelled`), the server closes the stream.

## Message Format

Each SSE message body is a JSON-encoded `api.Event`:

```json
{
  "type": "run.state",
  "timestamp": "2026-04-19T10:05:01Z",
  "run_id": "run-xyz789",
  "payload": { ... }
}
```

The `payload` field is a `json.RawMessage`. Consumers must switch on `type` to unmarshal the correct payload struct.

---

## Event Types

### `run.state`

Emitted when the overall run lifecycle changes state.

Payload:
```json
{
  "state": "running",
  "error": ""
}
```

State transitions: `pending` → `running` → `completed` / `failed` / `cancelled`

The `error` field is populated on `failed` state.

---

### `job.state`

Emitted when a single job changes state.

Payload:
```json
{
  "job_id": "job-1",
  "kind": "port-scan",
  "plugin": "nmap",
  "state": "succeeded",
  "error": ""
}
```

Job states: `pending` → `running` → `succeeded` / `failed` / `skipped`

---

### `evidence.new`

Emitted each time a scanner plugin produces an evidence record.

Payload:
```json
{
  "job_id": "job-1",
  "record": { ... }
}
```

The `record` field is a JSON-encoded `evidence.Record`. See `packages/evidence.md` for the full schema.

---

### `log`

Operator-visible progress message. Used for tool stdout lines or status messages that don't fit into run/job state events.

Payload:
```json
{
  "job_id": "job-1",
  "level": "info",
  "message": "nmap scan complete: 254 hosts, 3 open ports"
}
```

`job_id` is omitted for run-level log messages.
Log levels: `debug`, `info`, `warn`, `error`

---

### `heartbeat`

Periodic keepalive message to prevent proxy/firewall timeouts on idle streams.
Payload is an empty object `{}`.

Interval: approximately every 15 seconds.

---

## Client Implementation Notes

- Parse each SSE message body as `api.Event`
- Switch on `type` field to route to the correct payload decoder
- Unknown `type` values should be silently ignored (forward compatibility)
- On stream close: check final `run.state` event to determine outcome
- Reconnection: the API does not support SSE `Last-Event-ID` resumption in v1. On reconnect, fetch `/runs/{id}/status` first for a snapshot, then reopen the stream.
