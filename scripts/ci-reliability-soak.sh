#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT_DIR="$ROOT/itest/artifacts"
ARTIFACT_PATH="$ARTIFACT_DIR/reliability-soak.json"

for cmd in cargo go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: $cmd is required for reliability soak checks" >&2
    exit 1
  fi
done

mkdir -p "$ARTIFACT_DIR"

echo "==> Running realtime soak + reconnect chaos test"
(
  cd "$ROOT/itest"
  INTEGRATION_RUN=1 \
  RELIABILITY_ARTIFACT_PATH="$ARTIFACT_PATH" \
  RELIABILITY_SOAK_CYCLES="${RELIABILITY_SOAK_CYCLES:-5}" \
  RELIABILITY_SOAK_MESSAGES_PER_CYCLE="${RELIABILITY_SOAK_MESSAGES_PER_CYCLE:-24}" \
  RELIABILITY_RELAY_DOWN_MS="${RELIABILITY_RELAY_DOWN_MS:-900}" \
  RELIABILITY_DELIVERY_TIMEOUT_MS="${RELIABILITY_DELIVERY_TIMEOUT_MS:-6000}" \
  RELIABILITY_RECONNECT_TIMEOUT_MS="${RELIABILITY_RECONNECT_TIMEOUT_MS:-15000}" \
  RELIABILITY_MIN_DELIVERY_RATIO="${RELIABILITY_MIN_DELIVERY_RATIO:-0.99}" \
  RELIABILITY_MAX_RECONNECT_LATENCY_MS="${RELIABILITY_MAX_RECONNECT_LATENCY_MS:-9000}" \
  RELIABILITY_MAX_RUNTIME_GROWTH_BYTES="${RELIABILITY_MAX_RUNTIME_GROWTH_BYTES:-196608}" \
  cargo test realtime_user_to_user_soak_with_reconnect_chaos -- --ignored --nocapture
)

echo "PASS: reliability soak checks passed"
echo "artifact: $ARTIFACT_PATH"
