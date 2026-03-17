#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_MODULE_DIR="$ROOT/relay-node"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 1
  fi
}

require_cmd git
require_cmd go
require_cmd gofmt
require_cmd golangci-lint
require_cmd govulncheck

DIFF_RANGE=""

resolve_diff_range() {
  local base_ref="$1"
  if git -C "$ROOT" rev-parse --verify "$base_ref" >/dev/null 2>&1; then
    if git -C "$ROOT" merge-base "$base_ref" HEAD >/dev/null 2>&1; then
      DIFF_RANGE="${base_ref}...HEAD"
    else
      echo "warning: no merge base for ${base_ref}...HEAD; falling back to ${base_ref}..HEAD" >&2
      DIFF_RANGE="${base_ref}..HEAD"
    fi
  fi
}

if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
  resolve_diff_range "origin/${GITHUB_BASE_REF}"
fi

if [[ -z "$DIFF_RANGE" ]]; then
  resolve_diff_range "origin/main"
fi

CHANGED_GO_FILES=()
if [[ -n "$DIFF_RANGE" ]]; then
  while IFS= read -r path; do
    [[ -n "$path" ]] && CHANGED_GO_FILES+=("$path")
  done < <(
    git -C "$ROOT" diff --name-only --diff-filter=ACMR "$DIFF_RANGE" \
      | grep -E '^relay-node/.*\.go$' || true
  )
else
  while IFS= read -r path; do
    [[ -n "$path" ]] && CHANGED_GO_FILES+=("${path#"$ROOT"/}")
  done < <(find "$GO_MODULE_DIR" -type f -name '*.go')
fi

if [[ ${#CHANGED_GO_FILES[@]} -eq 0 ]]; then
  echo "==> Go format: no changed Go files detected, skipping file-scoped check"
else
  echo "==> Go format check (changed files)"
  pushd "$ROOT" >/dev/null
  GOFMT_DIFF="$(gofmt -l "${CHANGED_GO_FILES[@]}" || true)"
  popd >/dev/null

  if [[ -n "$GOFMT_DIFF" ]]; then
    echo "ERROR: gofmt required for:" >&2
    echo "$GOFMT_DIFF" >&2
    exit 1
  fi
fi

echo "==> Go vet"
(
  cd "$GO_MODULE_DIR"
  go vet ./...
)

echo "==> golangci-lint"
(
  cd "$GO_MODULE_DIR"
  golangci-lint run ./...
)

echo "==> Go tests"
(
  cd "$GO_MODULE_DIR"
  go test ./...
)

echo "==> govulncheck"
(
  cd "$GO_MODULE_DIR"
  govulncheck ./...
)

echo "✅ Go quality gates passed"
