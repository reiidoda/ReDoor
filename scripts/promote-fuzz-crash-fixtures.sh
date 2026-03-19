#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="${1:-$ROOT/client/fuzz/artifacts}"
TARGET_DIR="${2:-$ROOT/client/fuzz/corpus/inbound_decode}"
MANIFEST_PATH="${3:-$ROOT/client/artifacts/fuzz/promoted-fixtures.json}"
MAX_BYTES="${REDOOR_PROMOTED_FIXTURE_MAX_BYTES:-262144}"

mkdir -p "$TARGET_DIR"
mkdir -p "$(dirname "$MANIFEST_PATH")"

new_count=0
existing_count=0

while IFS= read -r -d '' crash_file; do
  if [[ ! -f "$crash_file" ]]; then
    continue
  fi

  sha="$(shasum -a 256 "$crash_file" | awk '{print $1}')"
  dst="$TARGET_DIR/promoted-${sha}.bin"

  if [[ -f "$dst" ]]; then
    existing_count=$((existing_count + 1))
    continue
  fi

  # Keep promoted fixtures bounded for deterministic CI/runtime behavior.
  head -c "$MAX_BYTES" "$crash_file" >"$dst"
  chmod 600 "$dst"
  new_count=$((new_count + 1))
done < <(find "$SOURCE_DIR" -type f \( -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' \) -print0 2>/dev/null || true)

total_promoted="$(find "$TARGET_DIR" -type f -name 'promoted-*.bin' | wc -l | tr -d ' ')"

cat >"$MANIFEST_PATH" <<JSON
{
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_dir": "${SOURCE_DIR}",
  "target_dir": "${TARGET_DIR}",
  "new_promoted": ${new_count},
  "existing_promoted": ${existing_count},
  "total_promoted": ${total_promoted}
}
JSON

echo "Promoted ${new_count} new crash fixtures (${existing_count} already present)."
echo "Manifest: ${MANIFEST_PATH}"
