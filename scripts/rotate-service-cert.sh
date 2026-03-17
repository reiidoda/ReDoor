#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Rotate TLS certificate/key for relay or directory service.

Usage:
  rotate-service-cert.sh <relay|directory> [--cert-file PATH] [--key-file PATH] [--cn NAME] [--days N]

Options:
  --cert-file PATH  Output certificate path
  --key-file PATH   Output private key path
  --cn NAME         Certificate common name (default: localhost)
  --days N          Certificate validity days (default: 90)
  -h, --help        Show help
USAGE
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

service="$1"
shift

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cn="localhost"
days=90
cert_file=""
key_file=""

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

mkdir -p "$(dirname "$cert_file")" "$(dirname "$key_file")"

timestamp="$(date +%Y%m%d%H%M%S)"
if [[ -f "$cert_file" ]]; then
  cp "$cert_file" "${cert_file}.bak.${timestamp}"
fi
if [[ -f "$key_file" ]]; then
  cp "$key_file" "${key_file}.bak.${timestamp}"
fi

openssl req \
  -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -days "$days" \
  -nodes \
  -subj "/CN=${cn}" \
  -keyout "$key_file" \
  -out "$cert_file" \
  >/dev/null 2>&1

chmod 600 "$key_file"
chmod 644 "$cert_file"

echo "Rotated TLS assets for ${service}." >&2
echo "CERT=${cert_file}" >&2
echo "KEY=${key_file}" >&2

echo "Restart the service with the updated certificate files." >&2
