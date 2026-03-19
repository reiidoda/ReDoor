#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required for memory regression checks" >&2
  exit 1
fi

echo "==> Rust memory budget regressions (client diagnostics)"
(
  cd "$ROOT/client"
  cargo test --lib diagnostics::tests::test_memory_budget_benchmark_regression_checks_pass -- --test-threads=1
  cargo test --lib diagnostics::tests::test_storage_usage_snapshot_increases_with_fixture -- --test-threads=1
  cargo test --lib ffi::tests::test_memory_budget_benchmark_reports_passing_regression -- --test-threads=1
  cargo test --lib ffi::tests::test_storage_usage_reports_consistent_totals -- --test-threads=1
)

echo "PASS: memory budget regressions passed"
