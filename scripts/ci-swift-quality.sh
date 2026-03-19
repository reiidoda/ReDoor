#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IOS_DEPLOYMENT_TARGET="17.0"

for cmd in swiftlint swiftformat xcodebuild git; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for Swift quality gates"
    exit 1
  fi
done

cd "$ROOT"

changed_swift_files=()
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
  base_ref="origin/${GITHUB_BASE_REF}"
  git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF}" >/dev/null 2>&1 || true

  diff_range="${base_ref}...HEAD"
  if ! git merge-base "${base_ref}" HEAD >/dev/null 2>&1; then
    echo "==> No merge-base for ${diff_range}; falling back to ${base_ref}..HEAD"
    diff_range="${base_ref}..HEAD"
  fi

  while IFS= read -r file; do
    [[ -n "$file" ]] && changed_swift_files+=("$file")
  done < <(git diff --name-only "${diff_range}" -- ':(glob)RedoorApp/**/*.swift' 2>/dev/null || true)
else
  while IFS= read -r file; do
    [[ -n "$file" ]] && changed_swift_files+=("$file")
  done < <(git diff --name-only HEAD~1...HEAD -- ':(glob)RedoorApp/**/*.swift' 2>/dev/null || true)
fi

if [[ "${#changed_swift_files[@]}" -eq 0 ]]; then
  echo "==> Swift format/lint: no changed Swift files detected, skipping file-scoped checks"
else
  echo "==> SwiftFormat lint (changed files)"
  swiftformat --lint --config "$ROOT/.swiftformat" "${changed_swift_files[@]}"

  echo "==> SwiftLint (changed files)"
  for file in "${changed_swift_files[@]}"; do
    swiftlint lint --strict --config "$ROOT/.swiftlint.yml" --path "$file"
  done
fi

echo "==> RAM-only policy (Swift paths)"
"$ROOT/scripts/check-ram-only-policy.sh"

echo "==> Auto-processing lockdown policy"
"$ROOT/scripts/check-auto-processing-lockdown.sh"

echo "==> iOS runtime wiring guard"
"$ROOT/scripts/check-ios-runtime-wiring.sh"

echo "==> iOS deployment target guard"
"$ROOT/scripts/check-ios-deployment-target.sh"

IOS_SIM_LIB="$ROOT/client/target/aarch64-apple-ios-sim/release/libredoor_client.a"
echo "==> Building iOS simulator staticlib (deployment target ${IOS_DEPLOYMENT_TARGET})"

for cmd in cargo rustup; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required to build $IOS_SIM_LIB"
    exit 1
  fi
done

(
  cd "$ROOT/client"
  rustup target add aarch64-apple-ios-sim >/dev/null
  export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"
  export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS="-C link-arg=-mios-simulator-version-min=${IOS_DEPLOYMENT_TARGET}"
  cargo build --release --target aarch64-apple-ios-sim
)

if [[ ! -f "$IOS_SIM_LIB" ]]; then
  echo "::error::Missing required static library: $IOS_SIM_LIB"
  exit 1
fi

echo "==> Xcode static analysis"
xcodebuild \
  -project "$ROOT/RedoorApp/RedoorApp.xcodeproj" \
  -scheme RedoorApp \
  -sdk iphonesimulator \
  -destination "generic/platform=iOS Simulator" \
  -configuration Debug \
  CODE_SIGNING_ALLOWED=NO \
  analyze

echo "✅ Swift quality gates passed"
