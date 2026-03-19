#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_PATH="${1:-$ROOT/client/artifacts/fuzz/fuzz-corpus-trends.json}"

mkdir -p "$(dirname "$OUT_PATH")"

count_files_and_bytes() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    echo "0 0"
    return
  fi

  local files bytes
  files="$(find "$dir" -type f | wc -l | tr -d ' ')"
  bytes="$(find "$dir" -type f -exec stat -f%z {} \; 2>/dev/null | awk '{sum += $1} END {print sum + 0}')"
  echo "$files $bytes"
}

read -r inbound_files inbound_bytes < <(count_files_and_bytes "$ROOT/client/fuzz/corpus/inbound_decode")
read -r handshake_files handshake_bytes < <(count_files_and_bytes "$ROOT/client/fuzz/corpus/handshake_nested_json")

cat >"$OUT_PATH" <<JSON
{
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "corpus": {
    "inbound_decode": {
      "files": ${inbound_files},
      "bytes": ${inbound_bytes}
    },
    "handshake_nested_json": {
      "files": ${handshake_files},
      "bytes": ${handshake_bytes}
    }
  }
}
JSON

echo "Wrote fuzz corpus trend snapshot: $OUT_PATH"
