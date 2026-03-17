#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE="$ROOT/client/src/engine.rs"
X3DH="$ROOT/client/src/crypto/x3dh.rs"
INVENTORY="$ROOT/docs/security/PARSER_INVENTORY_MATRIX.md"

fail() {
  echo "::error::$1"
  exit 1
}

assert_contains() {
  local pattern="$1"
  local file="$2"
  local description="$3"
  if ! grep -Eq "$pattern" "$file"; then
    fail "Parser surface policy violation: missing ${description} in ${file}"
  fi
}

echo "Checking parser inventory matrix..."
[[ -f "$INVENTORY" ]] || fail "Missing parser inventory matrix: $INVENTORY"
assert_contains '^# Parser Inventory Matrix' "$INVENTORY" "matrix title"
assert_contains 'envelope_json' "$INVENTORY" "envelope_json class entry"
assert_contains 'inner_payload_json' "$INVENTORY" "inner_payload_json class entry"
assert_contains 'initial_message_json' "$INVENTORY" "initial_message_json class entry"
assert_contains 'default-off' "$INVENTORY" "default-off parser policy"
assert_contains 'Removal / Isolation Plan' "$INVENTORY" "unsafe parser removal plan"

echo "Checking parser allowlist/runtime guards..."
assert_contains 'PARSER_CLASS_ALLOWLIST_ENV' "$ENGINE" "parser class allowlist env guard"
assert_contains 'DEFAULT_PARSER_CLASS_ALLOWLIST' "$ENGINE" "default parser class allowlist"
assert_contains 'validate_untrusted_json_structure' "$ENGINE" "json structural pre-parse validation"
assert_contains 'compressed payloads are not supported in parser boundary' "$ENGINE" "compressed payload rejection"

echo "Checking strict parser schema policy..."
count="$(grep -c 'serde(deny_unknown_fields)' "$X3DH" || true)"
if [[ "$count" -lt 2 ]]; then
  fail "Expected deny_unknown_fields on X3DH parser structs in $X3DH"
fi

echo "Checking parser fuzz corpus baseline..."
for dir in inbound_decode handshake_nested_json; do
  path="$ROOT/client/fuzz/corpus/$dir"
  [[ -d "$path" ]] || fail "Missing parser corpus directory: $path"
  file_count="$(find "$path" -type f | wc -l | tr -d ' ')"
  if [[ "$file_count" == "0" ]]; then
    fail "Parser corpus directory has no fixtures: $path"
  fi
  echo "  - $dir: $file_count fixtures"
done

echo "Checking parser fuzz harness expansion..."
for file in \
  "$ROOT/client/fuzz/fuzz_targets/parser_worker_ipc.rs" \
  "$ROOT/relay-node/src/network/fuzz_untrusted_boundaries_test.go" \
  "$ROOT/relay-node/src/onion/fuzz_mix_layer_test.go"; do
  [[ -f "$file" ]] || fail "Missing fuzz harness: $file"
  echo "  - found $(basename "$file")"
done

echo "PASS: parser surface policy"
