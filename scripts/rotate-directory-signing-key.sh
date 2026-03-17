#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Generate a new directory resolve signing key.

Usage:
  rotate-directory-signing-key.sh [--output PATH] [--env-format] [--print]

Options:
  --output PATH   Write key material to PATH with 0600 permissions
  --env-format    Emit as DIR_SIGNING_KEY_HEX=<hex> instead of raw hex
  --print         Print generated value to stdout even when --output is used
  -h, --help      Show help
USAGE
}

output_file=""
env_format=0
print_value=0

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

if [[ -z "$output_file" ]]; then
  print_value=1
fi

new_key_hex="$(openssl rand -hex 32 | tr -d '\n')"
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
fi

if [[ "$print_value" == "1" ]]; then
  echo "$value"
fi
