#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT_FFI="$ROOT/client/src/ffi.rs"
SWIFT_MESSAGING="$ROOT/RedoorApp/RedoorApp/Services/RedoorService.swift"
SWIFT_APP_ROOT="$ROOT/RedoorApp/RedoorApp"

fail() {
  echo "::error::$1"
  exit 1
}

assert_contains() {
  local pattern="$1"
  local file="$2"
  local description="$3"
  if ! grep -Eq "$pattern" "$file"; then
    fail "Auto-processing lockdown violation: missing ${description} in ${file}"
  fi
}

echo "Checking attachment/media auto-processing lockdown policy..."

assert_contains 'pub extern "C" fn redoor_send_file' "$CLIENT_FFI" "redoor_send_file symbol"
assert_contains 'File sending is disabled' "$CLIENT_FFI" "disabled file-send guard"
assert_contains 'pub extern "C" fn redoor_decrypt_file' "$CLIENT_FFI" "redoor_decrypt_file symbol"
assert_contains 'File decryption is disabled' "$CLIENT_FFI" "disabled file-decrypt guard"
assert_contains 'msg\.msg_type\.isEmpty \|\| msg\.msg_type == "text"' "$SWIFT_MESSAGING" "Swift text-only filter"

if grep -R -nE --include='*.swift' '^import (AVFoundation|PhotosUI|QuickLook|PDFKit|WebKit)' "$SWIFT_APP_ROOT" >/dev/null 2>&1; then
  echo "::error::Auto-processing lockdown violation: media/document frameworks detected under ${SWIFT_APP_ROOT}"
  grep -R -nE --include='*.swift' '^import (AVFoundation|PhotosUI|QuickLook|PDFKit|WebKit)' "$SWIFT_APP_ROOT" || true
  exit 1
fi

echo "Auto-processing lockdown policy passed."
