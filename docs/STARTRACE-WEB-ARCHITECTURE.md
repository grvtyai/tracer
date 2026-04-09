# Startrace Web Architecture

This document captures the current Startrace suite architecture inside the real `Startrace` repository.

## Goal

`Startrace` is the product surface for operators.
`Radar` is the first major module inside it and still contains the current discovery/scanner runtime.

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

### 1. shared core

Shared foundations remain responsible for:

- template loading
- option resolution
- scan planning
- plugin execution
- evidence normalization
- blocking assessment
- reevaluation hints
- SQLite persistence
- run diffs
- project, run and asset data access
- platform/runtime helpers used by multiple modules

### 2. suite shell

The product shell is a Go HTTP server that wraps shared services and registered modules.
It is responsible for:

- rendering operator-facing pages
- exposing a JSON API for browser interactions
- project-aware navigation and shell layout
- shared templates and styling
- shared UI components and page composition
- composing views from module and shared data

### 3. modules

Each module owns its own workflow area inside the suite.
Right now the first live module is `Radar`, but the same split should later apply to `Inventory`, `Security`, `Workbench`, `Automation` and `Help`.

Each module can carry:

- service or runtime logic
- integrations with tools or scanners
- module-specific queries, actions and workflow helpers
- data preparation for the suite layer

The suite remains the place where the browser-facing UI is rendered. A module may justify a specialized view later, but the default rule is that modules provide capabilities and the suite presents them.

This keeps the product easy to evolve without letting one module become the entire app structure or a second frontend.

## Initial Repository Shape

Inside `scanner-core/` the structure now trends toward:

```text
scanner-core/
|-- cmd/
|   |-- st-radar/
|   `-- startrace/
|-- internal/
|   |-- modules/
|   |   `-- radar/
|   |       |-- integrations/
|   |       `-- runtime/
|   |-- shared/
|   |   |-- platform/
|   |   `-- storage/
|   `-- suite/
|       |-- server.go
|       |-- server_test.go
|       |-- components/
|       |-- pages/
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

## Boundary Rules

To keep the suite maintainable as more modules arrive:

- the suite shell owns navigation, layout and global UI concerns
- shared packages own canonical data models and persistence
- modules own workflows, actions, integrations and data preparation
- modules should depend on shared foundations, not directly on each other
- visual consistency should come from the suite layer, not from each module inventing its own UI stack
