#!/usr/bin/env bash

set -euo pipefail

log() {
  printf '[startrace-run] %s\n' "$*"
}

resolve_home_for_user() {
  local user_name="$1"
  if [[ -z "$user_name" ]]; then
    return 1
  fi

  if command -v getent >/dev/null 2>&1; then
    getent passwd "$user_name" | cut -d: -f6
    return 0
  fi

  eval "printf '%s\n' ~$user_name"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCANNER_CORE_DIR="${REPO_ROOT}/scanner-core"

if [[ ! -d "${SCANNER_CORE_DIR}" ]]; then
  printf '[startrace-run][error] scanner-core directory not found at %s\n' "${SCANNER_CORE_DIR}" >&2
  exit 1
fi

TARGET_USER="${SUDO_USER:-${USER:-}}"
TARGET_HOME="$(resolve_home_for_user "${TARGET_USER}" 2>/dev/null || true)"
if [[ -z "${TARGET_HOME}" ]]; then
  TARGET_HOME="${HOME}"
fi

STARTRACE_LISTEN="${STARTRACE_LISTEN:-0.0.0.0:8080}"
STARTRACE_DATA_DIR="${STARTRACE_DATA_DIR:-}"
STARTRACE_DB_PATH="${STARTRACE_DB_PATH:-}"

STARTRACE_PATH="/usr/local/go/bin:${TARGET_HOME}/go/bin:${TARGET_HOME}/.local/bin:/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd "${SCANNER_CORE_DIR}"

log "Building tracer"
PATH="${STARTRACE_PATH}" go build -o ./bin/tracer ./cmd/tracer

log "Building startrace"
PATH="${STARTRACE_PATH}" go build -o ./bin/startrace ./cmd/startrace

run_args=(./bin/startrace --listen "${STARTRACE_LISTEN}")

if [[ -n "${STARTRACE_DATA_DIR}" ]]; then
  run_args+=(--data-dir "${STARTRACE_DATA_DIR}")
fi

if [[ -n "${STARTRACE_DB_PATH}" ]]; then
  run_args+=(--db-path "${STARTRACE_DB_PATH}")
fi

if [[ "$#" -gt 0 ]]; then
  run_args+=("$@")
fi

log "Starting Startrace on ${STARTRACE_LISTEN}"

if [[ "${EUID}" -eq 0 ]]; then
  PATH="${STARTRACE_PATH}" exec "${run_args[@]}"
fi

exec sudo env "PATH=${STARTRACE_PATH}" "${run_args[@]}"
