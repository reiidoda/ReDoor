#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_PATH="${ANONYMITY_BASELINE_PATH:-$ROOT/docs/security/traffic-linkability-baseline.v1.json}"
ARTIFACT_DIR="${ANONYMITY_ARTIFACT_DIR:-$ROOT/client/artifacts/anonymity}"
REPORT_PATH="${ANONYMITY_REPORT_PATH:-$ARTIFACT_DIR/traffic-linkability-report.json}"
EVALUATION_PATH="${ANONYMITY_EVALUATION_PATH:-$ARTIFACT_DIR/traffic-linkability-evaluation.json}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required for anonymity regression checks" >&2
  exit 1
fi

if [[ ! -f "$BASELINE_PATH" ]]; then
  echo "ERROR: baseline file not found at $BASELINE_PATH" >&2
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"

seed_args=()
if [[ -n "${ANONYMITY_SEED:-}" ]]; then
  seed_args=(--seed "$ANONYMITY_SEED")
fi

echo "==> Anonymity regression gate"
(
  cd "$ROOT/client"
  if [[ ${#seed_args[@]} -gt 0 ]]; then
    cargo run --quiet --bin traffic_linkability_gate -- \
      --baseline "$BASELINE_PATH" \
      --report "$REPORT_PATH" \
      --evaluation "$EVALUATION_PATH" \
      "${seed_args[@]}"
  else
    cargo run --quiet --bin traffic_linkability_gate -- \
      --baseline "$BASELINE_PATH" \
      --report "$REPORT_PATH" \
      --evaluation "$EVALUATION_PATH"
  fi
)

echo "PASS: anonymity regression gate passed"
echo "report: $REPORT_PATH"
echo "evaluation: $EVALUATION_PATH"
