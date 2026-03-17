#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo is required for parser fuzz regression checks"
  exit 1
fi

echo "==> Parser fuzz regression fixtures + deterministic mutation smoke"
(
  cd "$ROOT/client"
  cargo test --test parser_fuzz_regression -- --test-threads=1
)

echo "==> Fuzz target inventory"
required_targets=(
  "envelope.rs"
  "hmac_headers.rs"
  "ratchet.rs"
  "inbound_decode.rs"
  "handshake_nested_json.rs"
  "parser_worker_ipc.rs"
)
for target in "${required_targets[@]}"; do
  if [[ ! -f "$ROOT/client/fuzz/fuzz_targets/$target" ]]; then
    echo "::error::missing fuzz target: client/fuzz/fuzz_targets/$target"
    exit 1
  fi
  echo "  - found $target"
done

echo "==> Go fuzz harness inventory"
required_go_fuzz=(
  "$ROOT/relay-node/src/network/fuzz_untrusted_boundaries_test.go"
  "$ROOT/relay-node/src/onion/fuzz_mix_layer_test.go"
)
for file in "${required_go_fuzz[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "::error::missing Go fuzz harness: $file"
    exit 1
  fi
  echo "  - found $(basename "$file")"
done

echo "==> Corpus pack presence"
required_corpus_dirs=(
  "inbound_decode"
  "handshake_nested_json"
)
for dir in "${required_corpus_dirs[@]}"; do
  path="$ROOT/client/fuzz/corpus/$dir"
  if [[ ! -d "$path" ]]; then
    echo "::error::missing corpus directory: $path"
    exit 1
  fi
  count="$(find "$path" -type f | wc -l | tr -d ' ')"
  if [[ "$count" == "0" ]]; then
    echo "::error::corpus directory has no files: $path"
    exit 1
  fi
  echo "  - $dir: $count files"
done

echo "==> Crash promotion (deterministic fixtures)"
"$ROOT/scripts/promote-fuzz-crash-fixtures.sh" \
  "$ROOT/client/fuzz/artifacts" \
  "$ROOT/client/fuzz/corpus/inbound_decode" \
  "$ROOT/client/fuzz/corpus/promoted-fixtures.json"

echo "==> Corpus trend snapshot"
"$ROOT/scripts/generate-fuzz-corpus-trends.sh" \
  "$ROOT/client/artifacts/fuzz/fuzz-corpus-trends.json"

echo "PASS: parser fuzz regression gate"
