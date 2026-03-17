#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

for cmd in cargo cargo-deny cargo-audit git rustfmt jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for Rust quality gates"
    exit 1
  fi
done

RUST_CRATES=(client blockchain-node directory-dht itest)
RUST_DENY_CRATES=(client blockchain-node directory-dht)
AUDIT_LOCKFILES=(client/Cargo.lock blockchain-node/Cargo.lock directory-dht/Cargo.lock itest/Cargo.lock)

changed_rust_files=()
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
  base_ref="origin/${GITHUB_BASE_REF}"
  git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF}" >/dev/null 2>&1 || true

  diff_range="${base_ref}...HEAD"
  if ! git merge-base "${base_ref}" HEAD >/dev/null 2>&1; then
    echo "==> No merge-base for ${diff_range}; falling back to ${base_ref}..HEAD"
    diff_range="${base_ref}..HEAD"
  fi

  while IFS= read -r file; do
    [[ -n "$file" ]] && changed_rust_files+=("$file")
  done < <(git diff --name-only "${diff_range}" -- ':(glob)**/*.rs' 2>/dev/null || true)
else
  while IFS= read -r file; do
    [[ -n "$file" ]] && changed_rust_files+=("$file")
  done < <(git diff --name-only HEAD~1...HEAD -- ':(glob)**/*.rs' 2>/dev/null || true)
fi

if [[ "${#changed_rust_files[@]}" -eq 0 ]]; then
  echo "==> Rustfmt: no changed Rust files detected, skipping file-scoped check"
else
  echo "==> Rustfmt --check (changed files)"
  rustfmt --edition 2021 --check "${changed_rust_files[@]}"
fi

echo "==> Auto-processing lockdown policy"
"$ROOT/scripts/check-auto-processing-lockdown.sh"

echo "==> Untrusted parser boundary policy"
"$ROOT/scripts/check-untrusted-parser-boundary.sh"

echo "==> Parser surface policy"
"$ROOT/scripts/check-parser-surface-policy.sh"

# Transitional baseline exceptions.
# Policy remains blocking via -D warnings; these lints are temporarily allowed
# until legacy cleanup is completed.
CLIPPY_BASELINE_ALLOW=(
  -A dead_code
  -A unused_imports
  -A unused_variables
  -A clippy::await_holding_lock
  -A clippy::cast_slice_from_raw_parts
  -A clippy::clone_on_copy
  -A clippy::collapsible_else_if
  -A clippy::collapsible_if
  -A clippy::derivable_impls
  -A clippy::duplicated_attributes
  -A clippy::empty_line_after_outer_attr
  -A clippy::items_after_test_module
  -A clippy::needless_borrow
  -A clippy::needless_borrows_for_generic_args
  -A clippy::needless_return
  -A clippy::new_without_default
  -A clippy::nonminimal_bool
  -A clippy::not_unsafe_ptr_arg_deref
  -A clippy::redundant_closure
  -A clippy::redundant_field_names
  -A clippy::redundant_guards
  -A clippy::redundant_pattern_matching
  -A clippy::single_component_path_imports
  -A clippy::single_match
  -A clippy::too_many_arguments
  -A clippy::unnecessary_unwrap
  -A clippy::useless_conversion
)

# Keep smoke/regression test output focused on real gate failures while legacy
# dead_code/unused cleanup is still tracked separately.
RUST_TEST_WARNING_ALLOW_FLAGS="-A dead_code -A unused_imports -A unused_variables"

echo "==> Clippy policy (blocking)"
for crate in "${RUST_CRATES[@]}"; do
  if [[ ! -f "$ROOT/$crate/Cargo.toml" ]]; then
    continue
  fi

  echo "Running clippy for ${crate}"
  (
    cd "$ROOT/$crate"
    cargo clippy --quiet --all-targets -- \
      -D warnings \
      -D clippy::dbg_macro \
      -D clippy::todo \
      -D clippy::unimplemented \
      "${CLIPPY_BASELINE_ALLOW[@]}"
  )
done

echo "==> PQ handshake policy matrix regression"
(
  cd "$ROOT/client"
  RUSTFLAGS="${RUSTFLAGS:-} ${RUST_TEST_WARNING_ALLOW_FLAGS}" cargo test --quiet handshake_policy_matrix_interop -- --nocapture
  RUSTFLAGS="${RUSTFLAGS:-} ${RUST_TEST_WARNING_ALLOW_FLAGS}" cargo test --quiet required_policy_rejects_downgraded_hybrid_message -- --nocapture
)

echo "==> Realtime delivery SLO regression smoke"
(
  cd "$ROOT/itest"
  INTEGRATION_RUN=1 RUSTFLAGS="${RUSTFLAGS:-} ${RUST_TEST_WARNING_ALLOW_FLAGS}" cargo test --quiet realtime_user_to_user_single_message -- --ignored --nocapture
  INTEGRATION_RUN=1 RUSTFLAGS="${RUSTFLAGS:-} ${RUST_TEST_WARNING_ALLOW_FLAGS}" cargo test --quiet realtime_user_to_user_burst_delivery -- --ignored --nocapture
)

echo "==> cargo-deny policy (bans/licenses/sources)"
for crate in "${RUST_DENY_CRATES[@]}"; do
  manifest="$ROOT/$crate/Cargo.toml"
  if [[ ! -f "$manifest" ]]; then
    continue
  fi

  echo "Running cargo-deny for ${crate}"
  cargo deny \
    --manifest-path "$manifest" \
    check \
    --config "$ROOT/deny.toml" \
    bans licenses sources
done

echo "==> cargo-audit policy (high/critical)"
audit_failed=0
for lock in "${AUDIT_LOCKFILES[@]}"; do
  if [[ ! -f "$ROOT/$lock" ]]; then
    continue
  fi

  echo "Auditing ${lock}"
  out="$(mktemp)"
  cargo audit --file "$ROOT/$lock" --json >"$out" || true
  count="$(jq '[((.vulnerabilities.list // [])[] | (.advisory.severity // "" | ascii_downcase) | select(. == "high" or . == "critical"))] | length' "$out")"
  echo "  high/critical advisories: ${count}"
  if [[ "${count}" != "0" ]]; then
    echo "::error::High/Critical Rust advisory findings in ${lock}"
    jq -r '
      (.vulnerabilities.list // [])
      | map(select((.advisory.severity // "" | ascii_downcase) == "high" or (.advisory.severity // "" | ascii_downcase) == "critical"))
      | .[]
      | "- \(.advisory.id): \(.advisory.package) \(.advisory.title) [\(.advisory.severity // "unknown")]"
    ' "$out"
    audit_failed=1
  fi
done

if [[ "$audit_failed" -ne 0 ]]; then
  exit 1
fi

echo "✅ Rust quality gates passed"
