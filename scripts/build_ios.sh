#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT_DIR="$REPO_ROOT/client"
OUT_DIR="$CLIENT_DIR/target"

echo "==> Building Rust staticlib for iOS (device + sim)"
cd "$CLIENT_DIR"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim >/dev/null

cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

echo "==> Generating C header via cbindgen"
cbindgen --config "$CLIENT_DIR/cbindgen.toml" --crate redoor-client --output "$OUT_DIR/redoor.h"

echo "==> Creating xcframework"
xcodebuild -create-xcframework \
  -library "$OUT_DIR/aarch64-apple-ios/release/libredoor_client.a" -headers "$OUT_DIR/redoor.h" \
  -library "$OUT_DIR/aarch64-apple-ios-sim/release/libredoor_client.a" -headers "$OUT_DIR/redoor.h" \
  -output "$OUT_DIR/redoor_client.xcframework"

echo "==> Staging header and modulemap for Xcode consumers"
STAGE_DIR="$OUT_DIR/ios-dist"
mkdir -p "$STAGE_DIR"
cp "$OUT_DIR/redoor.h" "$STAGE_DIR/"
cp "$CLIENT_DIR/ios/module.modulemap" "$STAGE_DIR/"
echo "Header + modulemap staged at $STAGE_DIR (copy into your Xcode project)"

echo "✅ xcframework ready at $OUT_DIR/redoor_client.xcframework"
