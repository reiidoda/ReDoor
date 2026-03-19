#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PBXPROJ="$ROOT/RedoorApp/RedoorApp.xcodeproj/project.pbxproj"

if [[ ! -f "$PBXPROJ" ]]; then
  echo "::error::Missing Xcode project file: $PBXPROJ"
  exit 1
fi

for cmd in xcodebuild awk sed sort grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for iOS deployment-target guard"
    exit 1
  fi
done

sdk_versions=()
while IFS= read -r line; do
  sdk_versions+=("$line")
done < <(
  xcodebuild -showsdks 2>/dev/null |
    sed -nE 's/.*-sdk iphonesimulator([0-9]+(\.[0-9]+)?).*/\1/p'
)

if [[ "${#sdk_versions[@]}" -eq 0 ]]; then
  echo "::error::Unable to detect iOS simulator SDK version from xcodebuild -showsdks"
  exit 1
fi

max_sdk="$(printf '%s\n' "${sdk_versions[@]}" | sort -V | tail -n 1)"

deployment_targets=()
while IFS= read -r line; do
  deployment_targets+=("$line")
done < <(
  grep -E 'IPHONEOS_DEPLOYMENT_TARGET = [0-9]+(\.[0-9]+)?;' "$PBXPROJ" |
    sed -E 's/.*IPHONEOS_DEPLOYMENT_TARGET = ([0-9]+(\.[0-9]+)?);/\1/' |
    sort -Vu
)

if [[ "${#deployment_targets[@]}" -eq 0 ]]; then
  echo "::error::No IPHONEOS_DEPLOYMENT_TARGET entries found in $PBXPROJ"
  exit 1
fi

if [[ "${#deployment_targets[@]}" -ne 1 ]]; then
  echo "::error::Inconsistent deployment targets detected: ${deployment_targets[*]}"
  exit 1
fi

target="${deployment_targets[0]}"

if [[ "$(printf '%s\n%s\n' "$target" "$max_sdk" | sort -V | tail -n 1)" != "$max_sdk" ]]; then
  echo "::error::Deployment target $target exceeds max installed iOS simulator SDK $max_sdk"
  exit 1
fi

echo "iOS deployment target guard passed (target=$target, max_sim_sdk=$max_sdk)."
