# scanner-core

`scanner-core` is the runtime core behind `Startrace` and `st-radar`.
It owns the shared scan model, job planning, evidence handling, persistence and the Radar execution flow.

## What lives here

- the Radar runtime and integrations
- shared SQLite persistence for projects, runs, assets and evidence
- run planning, execution results and reevaluation hints
- browser-facing suite handlers and templates
- shared platform helpers for Linux-first execution

## Current focus

- keep `st-radar` reliable as the first major module worker
- keep the suite and CLI writing into the same shared model
- normalize evidence so later modules can build on the same assets and runs
- stay practical for small-network and homelab use on Ubuntu

## Runtime model

- `startrace` is the suite host and browser UI
- `st-radar` is the Radar worker / CLI binary
- `SQLite` is the default shared persistence layer

Both binaries should usually run with elevated privileges on Linux because parts of the toolkit need them.
