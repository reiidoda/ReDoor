#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT_DIR="$REPO_ROOT/client"
OUT_DIR="$CLIENT_DIR/target"
IOS_DEPLOYMENT_TARGET="17.0"

echo "==> Building Rust staticlib for iOS (device + sim)"
cd "$CLIENT_DIR"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim >/dev/null

export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"
export CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS="-C link-arg=-miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}"
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS="-C link-arg=-mios-simulator-version-min=${IOS_DEPLOYMENT_TARGET}"

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
