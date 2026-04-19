// Package api defines the wire contract between the Nexus (controller) and
// Satellites (runners). It contains only data types — no transport, no handlers,
// no client logic. The goal is a single source of truth for request and response
// shapes that both sides import.
//
// Stability: types here are part of the public wire contract. Changing a field
// name or removing a field is a breaking change for any deployed Satellite that
// has a different version than the Nexus talking to it.
package api

// Version is the current API contract version. Bumped on breaking changes.
const Version = "v1"
