#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_ROOT="$ROOT/RedoorApp"
PROJECT_FILE="$APP_ROOT/RedoorApp.xcodeproj/project.pbxproj"
STUB_SOURCE="$APP_ROOT/RedoorStubs.c"
FFI_FILE="$APP_ROOT/RedoorApp/Core/RedoorFFI.swift"

for cmd in rg grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for iOS runtime wiring guard"
    exit 1
  fi
done

if [[ -e "$STUB_SOURCE" ]]; then
  echo "::error::Production stub source must not exist: $STUB_SOURCE"
  exit 1
fi

if [[ ! -f "$PROJECT_FILE" ]]; then
  echo "::error::Missing Xcode project file: $PROJECT_FILE"
  exit 1
fi

if [[ ! -f "$FFI_FILE" ]]; then
  echo "::error::Missing Swift FFI binding file: $FFI_FILE"
  exit 1
fi

stub_refs="$(rg -n 'RedoorStubs\.c' "$APP_ROOT" || true)"
if [[ -n "$stub_refs" ]]; then
  echo "::error::Found production-path stub references:"
  echo "$stub_refs"
  exit 1
fi

ffi_exports=(
  "redoor_init_runtime"
  "redoor_send_message"
  "redoor_poll_messages"
)

for symbol in "${ffi_exports[@]}"; do
  if ! grep -q "@_silgen_name(\"${symbol}\")" "$FFI_FILE"; then
    echo "::error::Missing required Rust FFI binding for symbol ${symbol} in $FFI_FILE"
    exit 1
  fi
done

echo "iOS runtime wiring guard passed."
