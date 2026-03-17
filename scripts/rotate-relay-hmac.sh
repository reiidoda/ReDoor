#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Rotate relay HMAC key via admin endpoint.

Usage:
  rotate-relay-hmac.sh [--relay-url URL] [--admin-token TOKEN] [--new-key-b64 KEY] [--new-key-file PATH] [--insecure]

Options:
  --relay-url URL      Relay base URL (default: RELAY_URL env or https://localhost:8443)
  --admin-token TOKEN  Admin token (default: ADMIN_TOKEN env)
  --new-key-b64 KEY    Base64 key to apply (default: generate random 32-byte key)
  --new-key-file PATH  Write resulting key to PATH with 0600 permissions
  --insecure           Allow insecure TLS (curl -k); use only for local/self-signed testing
  -h, --help           Show help
USAGE
}

relay_url="${RELAY_URL:-https://localhost:8443}"
admin_token="${ADMIN_TOKEN:-}"
new_key_b64="${NEW_KEY_B64:-}"
new_key_file="${NEW_KEY_FILE:-}"
insecure_tls=0

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
    --insecure)
      insecure_tls=1
      shift
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

if [[ -z "$admin_token" ]]; then
  echo "ADMIN_TOKEN (or --admin-token) is required." >&2
  exit 1
fi

if [[ -z "$new_key_b64" ]]; then
  new_key_b64="$(openssl rand -base64 32 | tr -d '\n')"
fi

if ! printf '%s' "$new_key_b64" | openssl base64 -d -A >/dev/null 2>&1; then
  echo "Provided key is not valid base64." >&2
  exit 1
fi

if [[ -n "$new_key_file" ]]; then
  mkdir -p "$(dirname "$new_key_file")"
  umask 077
  printf '%s\n' "$new_key_b64" >"$new_key_file"
  chmod 600 "$new_key_file"
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

if [[ -n "$new_key_file" ]]; then
  echo "Saved key to ${new_key_file} (0600)." >&2
else
  echo "$new_key_b64"
fi
