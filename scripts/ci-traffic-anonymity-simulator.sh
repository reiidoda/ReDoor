#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required for traffic-anonymity simulator checks" >&2
  exit 1
fi

echo "==> Traffic-analysis simulator regressions (client diagnostics)"
(
  cd "$ROOT/client"
  cargo test --lib diagnostics::tests::test_traffic_analysis_simulator_is_deterministic -- --test-threads=1
  cargo test --lib diagnostics::tests::test_traffic_analysis_simulator_covers_required_scenarios -- --test-threads=1
  cargo test --lib diagnostics::tests::test_traffic_analysis_simulator_regression_expectations_hold -- --test-threads=1
  cargo test --lib ffi::tests::test_traffic_linkability_benchmark_returns_versioned_report -- --test-threads=1
)

echo "PASS: traffic-analysis simulator regressions passed"
