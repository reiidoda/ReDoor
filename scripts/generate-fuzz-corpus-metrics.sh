#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_PATH="${1:-$ROOT/itest/artifacts/fuzz-corpus-metrics.json}"

corpus_root="$ROOT/client/fuzz/corpus"
inbound_dir="$corpus_root/inbound_decode"
handshake_dir="$corpus_root/handshake_nested_json"

if [[ ! -d "$inbound_dir" ]]; then
  echo "missing corpus directory: $inbound_dir" >&2
  exit 1
fi
if [[ ! -d "$handshake_dir" ]]; then
  echo "missing corpus directory: $handshake_dir" >&2
  exit 1
fi

inbound_count="$(find "$inbound_dir" -type f | wc -l | tr -d ' ')"
handshake_count="$(find "$handshake_dir" -type f | wc -l | tr -d ' ')"
total_count=$((inbound_count + handshake_count))

mkdir -p "$(dirname "$OUT_PATH")"

cat >"$OUT_PATH" <<EOF
{
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "corpus_counts": {
    "inbound_decode": $inbound_count,
    "handshake_nested_json": $handshake_count,
    "total": $total_count
  }
}
EOF

echo "wrote fuzz corpus metrics: $OUT_PATH"
