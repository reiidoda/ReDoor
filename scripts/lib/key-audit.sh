#!/usr/bin/env bash

new_correlation_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
    return 0
  fi
  openssl rand -hex 16
}

log_key_event() {
  local correlation_id="$1"
  local operation="$2"
  local event="$3"
  local status="$4"
  local details="${5:-}"
  local ts

  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [[ -n "$details" ]]; then
    echo "AUDIT_EVENT ts=${ts} correlation_id=${correlation_id} operation=${operation} event=${event} status=${status} details=${details}" >&2
  else
    echo "AUDIT_EVENT ts=${ts} correlation_id=${correlation_id} operation=${operation} event=${event} status=${status}" >&2
  fi
}

