# Startrace Web Architecture

This document captures the first web-facing architecture that will sit on top of `tracer` while we are still working only inside this repository.

## Goal

`tracer` remains the scanning core.
The future product surface for operators will be `startrace`, but the first implementation work happens here so the merge later is mechanical instead of architectural.

## Recommended Runtime Model

For the first GUI generation we use:

- Go for backend and orchestration
- a local HTTP server for the product surface
- server-rendered HTML pages with lightweight JavaScript
- `SQLite` as the shared persistence layer

This gives us:

- one implementation language for runtime and install flow
- no early dependency on a separate frontend toolchain
- easy packaging on Ubuntu
- a direct path to a later desktop shell such as `Wails`

## Planned Layers

### 1. scanner-core

The core remains responsible for:

- template loading
- option resolution
- scan planning
- plugin execution
- evidence normalization
- blocking assessment
- reevaluation hints
- SQLite persistence
- run diffs

### 2. startrace web app

The first product layer is a Go HTTP server that wraps the core.
It is responsible for:

- rendering operator-facing pages
- exposing a JSON API for browser interactions
- reading projects, runs and run details from SQLite
- later starting scans and tracking progress

### 3. web UI

The first UI stays intentionally simple:

- HTML templates
- shared CSS theme
- a small amount of JavaScript for progressive enhancement

This keeps the product easy to evolve while we are still settling the operator flows.

## Initial Repository Shape

Inside `scanner-core/` we add a product-facing web layer:

```text
scanner-core/
|-- cmd/
|   |-- tracer/
|   `-- startrace/
|-- internal/
|   |-- app/
|   |-- storage/
|   `-- web/
|       |-- server.go
|       |-- server_test.go
|       |-- templates/
|       `-- static/
```

## First Screens

The first useful screens are:

1. Landing
2. Projects
3. Project detail with run history
4. Run detail with host overview, evidence, blocking and reevaluation
5. Settings

The first web layer is intentionally read-first.
Creating scans from the browser can come immediately after the browsing model is stable.

## First API Surface

The first API should support the same views:

- `GET /api/health`
- `GET /api/options`
- `GET /api/projects`
- `GET /api/projects/{project_id}/runs`
- `GET /api/runs/{run_id}`
- `GET /api/runs/{run_id}/evidence`
- `GET /api/runs/{run_id}/blocking`
- `GET /api/runs/{run_id}/reevaluation`
- `GET /api/diff?baseline_run=<id>&candidate_run=<id>`

The next write-focused API layer can then add:

- `POST /api/projects`
- `POST /api/runs`
- `GET /api/scan/progress/{run_id}`
- import/export endpoints

## Why Server-Rendered First

We are deliberately starting server-rendered because:

- the product information architecture is still moving
- the scan domain is already complex enough
- we already know the visual direction from the existing Startrace prototype
- installation and packaging stay simpler
- a future migration to a larger frontend remains possible if the UI becomes much richer

The rule of thumb is:

- server-render first
- enrich with targeted JavaScript
- only split into a separate frontend project if the interaction model genuinely demands it

## Merge Direction

Later, when `tracer` and `startrace` are merged, the intended result is:

- `tracer` contributes the mature scanning core and persistence model
- `startrace` contributes the product identity, branding and operator workflows
- both meet in a single Go-hosted application

That means the work done here should stay:

- modular
- reusable
- product-shaped
- but still independent from the current Python/FastAPI prototype
