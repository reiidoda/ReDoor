#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_SCRIPT="$ROOT/scripts/release-build-core.sh"
ARTIFACT_BASENAME="redoor-core-linux-amd64.tar.gz"

if [[ ! -x "$BUILD_SCRIPT" ]]; then
  echo "::error::Missing executable build script at $BUILD_SCRIPT" >&2
  exit 1
fi

for cmd in mktemp awk diff; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for reproducibility verification" >&2
    exit 1
  fi
done

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --pretty=%ct)}"
export SOURCE_DATE_EPOCH

RUN1_DIR="$(mktemp -d)"
RUN2_DIR="$(mktemp -d)"
trap 'rm -rf "$RUN1_DIR" "$RUN2_DIR"' EXIT

echo "==> Reproducibility run #1"
"$BUILD_SCRIPT" --output-dir "$RUN1_DIR"
echo "==> Reproducibility run #2"
"$BUILD_SCRIPT" --output-dir "$RUN2_DIR"

SUM1="$(awk '{print $1}' "$RUN1_DIR/${ARTIFACT_BASENAME}.sha256")"
SUM2="$(awk '{print $1}' "$RUN2_DIR/${ARTIFACT_BASENAME}.sha256")"

if [[ "$SUM1" != "$SUM2" ]]; then
  echo "::error::Reproducibility check failed: artifact hashes differ" >&2
  echo "run1: $SUM1" >&2
  echo "run2: $SUM2" >&2
  echo "--- run1 SHA256SUMS ---" >&2
  cat "$RUN1_DIR/SHA256SUMS" >&2
  echo "--- run2 SHA256SUMS ---" >&2
  cat "$RUN2_DIR/SHA256SUMS" >&2
  exit 1
fi

if ! diff -u "$RUN1_DIR/SHA256SUMS" "$RUN2_DIR/SHA256SUMS" >/dev/null; then
  echo "::error::Reproducibility check failed: per-file checksums differ" >&2
  diff -u "$RUN1_DIR/SHA256SUMS" "$RUN2_DIR/SHA256SUMS" >&2 || true
  exit 1
fi

echo "PASS: reproducible build hashes match"
echo "artifact sha256: $SUM1"
