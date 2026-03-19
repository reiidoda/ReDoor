#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required for memory hygiene checks" >&2
  exit 1
fi

echo "==> Rust memory hygiene regression tests"
(
  cd "$ROOT/client"
  cargo test --lib engine::tests::secure_wipe_zeroizes_sensitive_collections_and_tracks_report -- --test-threads=1
  cargo test --lib service::tests::test_wipe_sensitive_state_clears_memory_structures -- --test-threads=1
  cargo test --lib ffi::tests::test_delete_all_messages_zeroizes_buffers -- --test-threads=1
  cargo test --lib ffi::tests::test_crash_hygiene_wipe_clears_sensitive_state -- --test-threads=1
)

echo "==> Swift memory hygiene policy checks"
SECURE_STORAGE_SWIFT="$ROOT/RedoorApp/RedoorApp/Core/SecureStorage.swift"
REDOOR_TESTS_SWIFT="$ROOT/RedoorApp/RedoorAppTests/RedoorAppTests.swift"
CHAT_SERVICE_SWIFT="$ROOT/RedoorApp/RedoorApp/Services/ChatService.swift"

grep -q "final class ZeroizableSecureBuffer" "$SECURE_STORAGE_SWIFT"
grep -q "existing\\.wipe()" "$SECURE_STORAGE_SWIFT"
grep -q "func testBackgroundTransitionWipesHMACSecureBuffer" "$REDOOR_TESTS_SWIFT"
grep -q "func testDuressWipesHMACSecureBuffer" "$REDOOR_TESTS_SWIFT"
grep -q "func testSecureStorageClearAllZeroizesBuffers" "$REDOOR_TESTS_SWIFT"
grep -q "willResignActiveNotification" "$CHAT_SERVICE_SWIFT"
grep -q "willTerminateNotification" "$CHAT_SERVICE_SWIFT"

echo "PASS: memory hygiene regressions passed"
