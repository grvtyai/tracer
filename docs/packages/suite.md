# Package: internal/suite

HTTP server and web UI layer for the Nexus. Provides the browser-facing interface, all HTML templates, and the `/api/*` JSON endpoints consumed by the frontend.

The package was originally a single large `server.go` file (~5300 lines). It has been split into focused files — all remain in `package suite` with no sub-packages.

## File Layout

| File | Responsibility |
|---|---|
| `server.go` | Core infrastructure: `Options`, `Server`, `NewServer`, `routes`, `render`, `writeJSON`, `loadShellContext`, asset/logo helpers (~260 lines) |
| `types.go` | All page-level structs and shared type definitions used across handlers |
| `handlers_dashboard.go` | Dashboard overview, analytics, chart data helpers |
| `handlers_discovery.go` | Radar / discovery routes (start scan, run detail, template management) |
| `handlers_projects.go` | Project CRUD (create, list, switch, delete) |
| `handlers_runs.go` | Run list, run detail, port sections, reevaluation scheduling |
| `handlers_inventory.go` | Inventory, asset detail, network topology view |
| `handlers_monitoring.go` | Satellites, health checks, job monitoring, satellite registration/refresh |
| `handlers_settings.go` | Settings page, help topics, notice messages, URL/path utility helpers |
| `handlers_api.go` | All `/api/*` JSON endpoints (health, options, preflight, settings, projects, assets, runs, diff) |

## Routing

All routes are registered in `server.go` → `routes()`. HTML routes render via `s.render(w, "template.html", data)`. API routes respond with `s.writeJSON(w, status, value)`.

## Templates

Embedded via `//go:embed templates/*.html static/*` in `server.go`. Templates live in `internal/suite/templates/`. Every HTML page is rendered against `templates/base.html` as the base layout.

## Adding a New Page

1. Add a handler function in the appropriate `handlers_*.go` file (or create a new one for a new module).
2. Register the route in `server.go` → `routes()`.
3. Add a template file under `internal/suite/templates/`.
4. Extend `pageData` in `types.go` if the page needs new fields.
