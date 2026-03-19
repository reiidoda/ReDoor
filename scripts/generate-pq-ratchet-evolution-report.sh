#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="docs/security/pq-ratchet-evolution-report.v1.json"

echo "Generating PQ ratchet evolution prototype report..."
cargo run \
  --quiet \
  --manifest-path client/Cargo.toml \
  --bin pq_ratchet_evolution_prototype \
  -- \
  --output "$OUT"

echo "Wrote $OUT"
