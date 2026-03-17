#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${ROOT}/scripts/lib/key-provider.sh"
source "${ROOT}/scripts/lib/key-audit.sh"

usage() {
  cat <<'USAGE'
Rotate TLS certificate/key for relay or directory service.

Usage:
  rotate-service-cert.sh <relay|directory> [--cert-file PATH] [--key-file PATH] [--cn NAME] [--days N] [--key-mode MODE] [--key-env-var NAME] [--provider-cmd CMD] [--correlation-id ID]

Options:
  --cert-file PATH  Output certificate path
  --key-file PATH   Output private key path
  --cn NAME         Certificate common name (default: localhost)
  --days N          Certificate validity days (default: 90)
  --key-mode MODE   Key source mode: local|env|provider (default: KEY_MODE env or local)
  --key-env-var     Env var used for env mode (default: KEY_ENV_VAR env or SERVICE_TLS_KEY_PEM)
  --provider-cmd    Provider command for provider mode (default: KEY_PROVIDER_CMD env)
  --correlation-id ID  Correlation ID for audit logs (default: CORRELATION_ID env or generated)
  -h, --help        Show help
USAGE
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

service="$1"
shift

cn="localhost"
days=90
cert_file=""
key_file=""
key_mode="${KEY_MODE:-local}"
key_env_var="${KEY_ENV_VAR:-SERVICE_TLS_KEY_PEM}"
provider_cmd="${KEY_PROVIDER_CMD:-}"
correlation_id="${CORRELATION_ID:-}"

generate_service_key_pem() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 2>/dev/null
}

case "$service" in
  relay)
    cert_file="$ROOT/relay-node/cert.pem"
    key_file="$ROOT/relay-node/key.pem"
    ;;
  directory)
    cert_file="$ROOT/directory-dht/cert.pem"
    key_file="$ROOT/directory-dht/key.pem"
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Unsupported service: $service" >&2
    usage >&2
    exit 1
    ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cert-file)
      cert_file="$2"
      shift 2
      ;;
    --key-file)
      key_file="$2"
      shift 2
      ;;
    --cn)
      cn="$2"
      shift 2
      ;;
    --days)
      days="$2"
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
    -h|--help)
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

if ! [[ "$days" =~ ^[0-9]+$ ]] || [[ "$days" -le 0 ]]; then
  echo "--days must be a positive integer." >&2
  exit 1
fi

if [[ -z "$correlation_id" ]]; then
  correlation_id="$(new_correlation_id)"
fi

operation_completed=0
trap 'if [[ "$operation_completed" -ne 1 ]]; then log_key_event "$correlation_id" "service_cert_rotate" "abort" "failed" "service=${service} mode=${key_mode}"; fi' EXIT

log_key_event "$correlation_id" "service_cert_rotate" "start" "ok" "service=${service} mode=${key_mode}"

mkdir -p "$(dirname "$cert_file")" "$(dirname "$key_file")"

timestamp="$(date +%Y%m%d%H%M%S)"
if [[ -f "$cert_file" ]]; then
  cp "$cert_file" "${cert_file}.bak.${timestamp}"
fi
if [[ -f "$key_file" ]]; then
  cp "$key_file" "${key_file}.bak.${timestamp}"
fi

key_material="$(resolve_key_material "$key_mode" "" "$key_env_var" "$provider_cmd" "generate_service_key_pem")"
if [[ -z "$key_material" ]]; then
  echo "Key provider returned empty material." >&2
  log_key_event "$correlation_id" "service_cert_rotate" "resolve_key" "failed" "reason=empty_key"
  exit 1
fi

umask 077
printf '%s\n' "$key_material" >"$key_file"
chmod 600 "$key_file"

if ! openssl pkey -in "$key_file" -noout >/dev/null 2>&1; then
  echo "Resolved key material is not a valid private key." >&2
  log_key_event "$correlation_id" "service_cert_rotate" "validate_key" "failed" "reason=invalid_private_key"
  exit 1
fi

openssl req \
  -x509 \
  -new \
  -sha256 \
  -days "$days" \
  -subj "/CN=${cn}" \
  -key "$key_file" \
  -out "$cert_file" \
  >/dev/null 2>&1

chmod 600 "$key_file"
chmod 644 "$cert_file"

echo "Rotated TLS assets for ${service}." >&2
echo "CERT=${cert_file}" >&2
echo "KEY=${key_file}" >&2
operation_completed=1
log_key_event "$correlation_id" "service_cert_rotate" "complete" "ok" "service=${service} mode=${key_mode}"
echo "CORRELATION_ID=${correlation_id}" >&2

echo "Restart the service with the updated certificate files." >&2
