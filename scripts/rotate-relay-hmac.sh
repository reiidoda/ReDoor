#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${ROOT}/scripts/lib/key-provider.sh"
source "${ROOT}/scripts/lib/key-audit.sh"

usage() {
  cat <<'USAGE'
Rotate relay HMAC key via admin endpoint.

Usage:
  rotate-relay-hmac.sh [--relay-url URL] [--admin-token TOKEN] [--new-key-b64 KEY] [--new-key-file PATH] [--key-mode MODE] [--key-env-var NAME] [--provider-cmd CMD] [--correlation-id ID] [--insecure]

Options:
  --relay-url URL      Relay base URL (default: RELAY_URL env or https://localhost:8443)
  --admin-token TOKEN  Admin token (default: ADMIN_TOKEN env)
  --new-key-b64 KEY    Base64 key to apply (default: generate random 32-byte key)
  --new-key-file PATH  Write resulting key to PATH with 0600 permissions
  --key-mode MODE      Key source mode: local|env|provider (default: KEY_MODE env or local)
  --key-env-var NAME   Env var used for env mode (default: KEY_ENV_VAR env or NEW_KEY_B64)
  --provider-cmd CMD   Provider command for provider mode (default: KEY_PROVIDER_CMD env)
  --correlation-id ID  Correlation ID for audit logs (default: CORRELATION_ID env or generated)
  --insecure           Allow insecure TLS (curl -k); use only for local/self-signed testing
  -h, --help           Show help
USAGE
}

relay_url="${RELAY_URL:-https://localhost:8443}"
admin_token="${ADMIN_TOKEN:-}"
new_key_b64="${NEW_KEY_B64:-}"
new_key_file="${NEW_KEY_FILE:-}"
key_mode="${KEY_MODE:-local}"
key_env_var="${KEY_ENV_VAR:-NEW_KEY_B64}"
provider_cmd="${KEY_PROVIDER_CMD:-}"
correlation_id="${CORRELATION_ID:-}"
insecure_tls=0

generate_hmac_key_b64() {
  openssl rand -base64 32 | tr -d '\n'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --relay-url)
      relay_url="$2"
      shift 2
      ;;
    --admin-token)
      admin_token="$2"
      shift 2
      ;;
    --new-key-b64)
      new_key_b64="$2"
      shift 2
      ;;
    --new-key-file)
      new_key_file="$2"
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
    --insecure)
      insecure_tls=1
      shift
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

if [[ -z "$admin_token" ]]; then
  echo "ADMIN_TOKEN (or --admin-token) is required." >&2
  exit 1
fi

if [[ -z "$correlation_id" ]]; then
  correlation_id="$(new_correlation_id)"
fi

operation_completed=0
trap 'if [[ "$operation_completed" -ne 1 ]]; then log_key_event "$correlation_id" "relay_hmac_rotate" "abort" "failed" "mode=${key_mode} relay_url=${relay_url}"; fi' EXIT

log_key_event "$correlation_id" "relay_hmac_rotate" "start" "ok" "mode=${key_mode} relay_url=${relay_url}"

new_key_b64="$(resolve_key_material "$key_mode" "$new_key_b64" "$key_env_var" "$provider_cmd" "generate_hmac_key_b64" | tr -d '\n')"

if ! printf '%s' "$new_key_b64" | openssl base64 -d -A >/dev/null 2>&1; then
  echo "Provided key is not valid base64." >&2
  log_key_event "$correlation_id" "relay_hmac_rotate" "validate_key" "failed" "reason=invalid_base64"
  exit 1
fi

if [[ -n "$new_key_file" ]]; then
  mkdir -p "$(dirname "$new_key_file")"
  umask 077
  printf '%s\n' "$new_key_b64" >"$new_key_file"
  chmod 600 "$new_key_file"
  log_key_event "$correlation_id" "relay_hmac_rotate" "persist_key" "ok" "path=${new_key_file}"
fi

url="${relay_url%/}/admin/hmac"
curl_args=(
  --fail
  --silent
  --show-error
  --request POST
  --header "X-Admin-Token: ${admin_token}"
  --data-binary @-
  "$url"
)

if [[ "$insecure_tls" == "1" ]]; then
  curl_args=(-k "${curl_args[@]}")
fi

response="$(printf '%s' "$new_key_b64" | curl "${curl_args[@]}")"

echo "${response}" >&2
echo "Relay HMAC key rotation request succeeded." >&2
operation_completed=1
log_key_event "$correlation_id" "relay_hmac_rotate" "complete" "ok" "mode=${key_mode}"
echo "CORRELATION_ID=${correlation_id}" >&2

if [[ -n "$new_key_file" ]]; then
  echo "Saved key to ${new_key_file} (0600)." >&2
else
  echo "$new_key_b64"
fi
