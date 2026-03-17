#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Rust fmt/clippy (client, blockchain-node, directory-dht)"
for crate in client blockchain-node directory-dht; do
  (cd "$ROOT/$crate" && cargo fmt --check)
  (cd "$ROOT/$crate" && cargo clippy --quiet -- -D warnings)
done

echo "==> Rust security/advisory scan (cargo-deny if available)"
if command -v cargo-deny >/dev/null 2>&1; then
  (cd "$ROOT" && cargo deny check)
else
  echo "cargo-deny not installed; skipping (install: cargo install cargo-deny)"
fi

if [ "${RUN_FUZZ:-0}" = "1" ]; then
  echo "==> Fuzz smoke (ratchet + envelope) with limited runs"
  (cd "$ROOT/client/fuzz" && cargo +nightly fuzz run ratchet -- -runs=100)
  (cd "$ROOT/client/fuzz" && cargo +nightly fuzz run envelope -- -runs=100)
fi

if [ "${RUN_INTEGRATION:-0}" = "1" ]; then
  echo "==> Ignored integration (requires relay + blockchain running)"
  (cd "$ROOT/itest" && INTEGRATION_RUN=1 cargo test -- --ignored)
fi

echo "==> Go fmt check (relay-node)"
GOFMT_DIFF=$(gofmt -l "$ROOT/relay-node/src" || true)
if [ -n "$GOFMT_DIFF" ]; then
  echo "gofmt needed for files:"
  echo "$GOFMT_DIFF"
  exit 1
fi

echo "==> Go lint (golangci-lint if available)"
if command -v golangci-lint >/dev/null 2>&1; then
  (cd "$ROOT/relay-node" && golangci-lint run ./...)
else
  echo "golangci-lint not installed; skipping (brew install golangci-lint)"
fi

echo "==> Go tests (relay-node)"
(cd "$ROOT/relay-node" && go test ./...)

echo "==> Rust tests (blockchain-node)"
(cd "$ROOT/blockchain-node" && cargo test --tests)

echo "✅ CI checks completed"
