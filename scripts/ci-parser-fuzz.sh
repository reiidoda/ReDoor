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
)
for target in "${required_targets[@]}"; do
  if [[ ! -f "$ROOT/client/fuzz/fuzz_targets/$target" ]]; then
    echo "::error::missing fuzz target: client/fuzz/fuzz_targets/$target"
    exit 1
  fi
  echo "  - found $target"
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

echo "PASS: parser fuzz regression gate"
