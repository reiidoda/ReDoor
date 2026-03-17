#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

STRICT="${REDOOR_SCAN_STRICT:-0}"
INCLUDE_SWIFT="${REDOOR_SCAN_INCLUDE_SWIFT:-0}"
SUMMARY_JSON="${REDOOR_SCAN_SUMMARY_JSON:-}"

usage() {
  cat <<'EOF'
Usage: ./scripts/ci-bugscan.sh [options]

SpotBugs-like multi-language scanner for ReDoor.

Options:
  --strict            fail if optional scanner tools are missing
  --include-swift     run Swift scanner script (slow)
  --summary-json PATH write machine-readable summary JSON
  -h, --help          show this help

Environment:
  REDOOR_SCAN_STRICT=1            same as --strict
  REDOOR_SCAN_INCLUDE_SWIFT=1     same as --include-swift
  REDOOR_SCAN_SUMMARY_JSON=path   same as --summary-json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      STRICT=1
      shift
      ;;
    --include-swift)
      INCLUDE_SWIFT=1
      shift
      ;;
    --summary-json)
      SUMMARY_JSON="${2:-}"
      if [[ -z "$SUMMARY_JSON" ]]; then
        echo "ERROR: --summary-json requires a path" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

steps_total=0
steps_passed=0
steps_failed=0
steps_skipped=0

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

step_rows=()

record_step() {
  local name="$1"
  local status="$2"
  local detail="$3"
  local escaped_name escaped_status escaped_detail
  escaped_name="$(json_escape "$name")"
  escaped_status="$(json_escape "$status")"
  escaped_detail="$(json_escape "$detail")"
  step_rows+=("{\"name\":\"$escaped_name\",\"status\":\"$escaped_status\",\"detail\":\"$escaped_detail\"}")
}

run_step() {
  local name="$1"
  shift
  steps_total=$((steps_total + 1))
  echo "==> [scan] $name"
  if "$@"; then
    steps_passed=$((steps_passed + 1))
    record_step "$name" "pass" ""
    echo "PASS: $name"
  else
    steps_failed=$((steps_failed + 1))
    record_step "$name" "fail" "command returned non-zero"
    echo "FAIL: $name" >&2
  fi
}

skip_step() {
  local name="$1"
  local reason="$2"
  steps_total=$((steps_total + 1))
  steps_skipped=$((steps_skipped + 1))
  record_step "$name" "skip" "$reason"
  echo "SKIP: $name ($reason)"
}

require_or_skip() {
  local step_name="$1"
  shift
  local missing=0
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=1
      if [[ "$STRICT" == "1" ]]; then
        echo "ERROR: '$cmd' is required for '$step_name'" >&2
      else
        echo "WARN: '$cmd' missing; '$step_name' will be skipped" >&2
      fi
    fi
  done
  if [[ "$missing" == "1" && "$STRICT" != "1" ]]; then
    skip_step "$step_name" "missing toolchain command"
    return 1
  fi
  return 0
}

run_rust_scan() {
  run_step "Rust quality + security" "$ROOT/scripts/ci-rust-quality.sh"
}

run_go_scan() {
  run_step "Go quality + security" "$ROOT/scripts/ci-go-quality.sh"
}

run_shell_scan() {
  local shell_files=()
  while IFS= read -r file; do
    shell_files+=("$file")
  done < <(find "$ROOT/scripts" -type f -name '*.sh' | sort)

  if [[ ${#shell_files[@]} -eq 0 ]]; then
    skip_step "Shell format (shfmt)" "no shell files found"
    skip_step "Shell lint (shellcheck)" "no shell files found"
    return
  fi

  if require_or_skip "Shell format (shfmt)" shfmt; then
    run_step "Shell format (shfmt)" shfmt -d -i 2 -ci "${shell_files[@]}"
  fi

  if require_or_skip "Shell lint (shellcheck)" shellcheck; then
    run_step "Shell lint (shellcheck)" shellcheck -x "${shell_files[@]}"
  fi
}

run_swift_scan() {
  if [[ "$INCLUDE_SWIFT" != "1" ]]; then
    skip_step "Swift quality + static analysis" "disabled (set --include-swift or REDOOR_SCAN_INCLUDE_SWIFT=1)"
    return
  fi
  run_step "Swift quality + static analysis" "$ROOT/scripts/ci-swift-quality.sh"
}

write_summary_json() {
  local path="$1"
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"

  local status="pass"
  if [[ "$steps_failed" -gt 0 ]]; then
    status="fail"
  elif [[ "$steps_skipped" -gt 0 ]]; then
    status="partial"
  fi

  {
    printf '{\n'
    printf '  "status": "%s",\n' "$status"
    printf '  "strict": %s,\n' "$([[ "$STRICT" == "1" ]] && echo true || echo false)"
    printf '  "steps_total": %d,\n' "$steps_total"
    printf '  "steps_passed": %d,\n' "$steps_passed"
    printf '  "steps_failed": %d,\n' "$steps_failed"
    printf '  "steps_skipped": %d,\n' "$steps_skipped"
    printf '  "steps": [\n'
    local i
    for i in "${!step_rows[@]}"; do
      printf '    %s' "${step_rows[$i]}"
      if [[ "$i" -lt $((${#step_rows[@]} - 1)) ]]; then
        printf ','
      fi
      printf '\n'
    done
    printf '  ]\n'
    printf '}\n'
  } > "$path"
}

main() {
  echo "==> ReDoor multi-language bug scan"
  echo "Strict mode: $STRICT"

  if [[ "$STRICT" == "1" ]]; then
    command -v git >/dev/null 2>&1 || {
      echo "ERROR: git is required" >&2
      exit 1
    }
  fi

  run_rust_scan
  run_go_scan
  run_shell_scan
  run_swift_scan

  if [[ -n "$SUMMARY_JSON" ]]; then
    write_summary_json "$SUMMARY_JSON"
    echo "Summary written to: $SUMMARY_JSON"
  fi

  echo "==> Scan summary: total=$steps_total passed=$steps_passed failed=$steps_failed skipped=$steps_skipped"

  if [[ "$steps_failed" -gt 0 ]]; then
    exit 1
  fi

  if [[ "$steps_skipped" -gt 0 ]]; then
    echo "WARNING: scanner coverage is partial (some steps skipped)."
    if [[ "$STRICT" == "1" ]]; then
      exit 1
    fi
  fi

  echo "✅ Multi-language bug scan passed"
}

main "$@"

