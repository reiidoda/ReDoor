#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${ROOT}/scripts/lib/key-provider.sh"
source "${ROOT}/scripts/lib/key-audit.sh"

usage() {
  cat <<'USAGE'
Generate a new directory resolve signing key.

Usage:
  rotate-directory-signing-key.sh [--output PATH] [--env-format] [--print] [--new-key-hex KEY] [--key-mode MODE] [--key-env-var NAME] [--provider-cmd CMD] [--correlation-id ID]

Options:
  --output PATH   Write key material to PATH with 0600 permissions
  --env-format    Emit as DIR_SIGNING_KEY_HEX=<hex> instead of raw hex
  --print         Print generated value to stdout even when --output is used
  --new-key-hex   Explicit hex key (64 hex chars)
  --key-mode MODE Key source mode: local|env|provider (default: KEY_MODE env or local)
  --key-env-var   Env var used for env mode (default: KEY_ENV_VAR env or DIR_SIGNING_KEY_HEX)
  --provider-cmd  Provider command for provider mode (default: KEY_PROVIDER_CMD env)
  --correlation-id ID  Correlation ID for audit logs (default: CORRELATION_ID env or generated)
  -h, --help      Show help
USAGE
}

output_file=""
env_format=0
print_value=0
new_key_hex="${NEW_KEY_HEX:-}"
key_mode="${KEY_MODE:-local}"
key_env_var="${KEY_ENV_VAR:-DIR_SIGNING_KEY_HEX}"
provider_cmd="${KEY_PROVIDER_CMD:-}"
correlation_id="${CORRELATION_ID:-}"

generate_directory_key_hex() {
  openssl rand -hex 32 | tr -d '\n'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output_file="$2"
      shift 2
      ;;
    --env-format)
      env_format=1
      shift
      ;;
    --print)
      print_value=1
      shift
      ;;
    --new-key-hex)
      new_key_hex="$2"
      shift 2
      ;;
    --key-mode)
      key_mode="$2"
      shift 2
      ;;
    --key-env-var)
      key_env_var="$2"
      shift 2
      ;;
    --provider-cmd)
      provider_cmd="$2"
      shift 2
      ;;
    --correlation-id)
      correlation_id="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$output_file" ]]; then
  print_value=1
fi

if [[ -z "$correlation_id" ]]; then
  correlation_id="$(new_correlation_id)"
fi

operation_completed=0
trap 'if [[ "$operation_completed" -ne 1 ]]; then log_key_event "$correlation_id" "directory_signing_key_rotate" "abort" "failed" "mode=${key_mode}"; fi' EXIT

log_key_event "$correlation_id" "directory_signing_key_rotate" "start" "ok" "mode=${key_mode}"

new_key_hex="$(resolve_key_material "$key_mode" "$new_key_hex" "$key_env_var" "$provider_cmd" "generate_directory_key_hex" | tr -d '\n')"
if ! [[ "$new_key_hex" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "Directory signing key must be 64 hex characters." >&2
  log_key_event "$correlation_id" "directory_signing_key_rotate" "validate_key" "failed" "reason=invalid_hex"
  exit 1
fi

value="$new_key_hex"
if [[ "$env_format" == "1" ]]; then
  value="DIR_SIGNING_KEY_HEX=${new_key_hex}"
fi

if [[ -n "$output_file" ]]; then
  mkdir -p "$(dirname "$output_file")"
  umask 077
  printf '%s\n' "$value" >"$output_file"
  chmod 600 "$output_file"
  echo "Wrote directory signing key to ${output_file} (0600)." >&2
  log_key_event "$correlation_id" "directory_signing_key_rotate" "persist_key" "ok" "path=${output_file}"
fi

if [[ "$print_value" == "1" ]]; then
  echo "$value"
fi

operation_completed=1
log_key_event "$correlation_id" "directory_signing_key_rotate" "complete" "ok" "mode=${key_mode}"
echo "CORRELATION_ID=${correlation_id}" >&2
