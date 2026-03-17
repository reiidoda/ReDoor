#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/redoor-ci-drill.XXXXXX")"

cleanup() {
  rm -rf "$workspace"
}
trap cleanup EXIT

echo "==> Rollback rehearsal drill harness"
"$ROOT/scripts/drill-rollback-rehearsal.sh" --workspace "$workspace" --keep-workspace

summary_md="$workspace/evidence/rollback-rehearsal-summary.md"
summary_json="$workspace/evidence/rollback-rehearsal-summary.json"
baseline_manifest="$workspace/evidence/baseline.sha256"
rotated_manifest="$workspace/evidence/rotated.sha256"
rollback_manifest="$workspace/evidence/rollback.sha256"
post_manifest="$workspace/evidence/post-rollback.sha256"

for file in "$summary_md" "$summary_json" "$baseline_manifest" "$rotated_manifest" "$rollback_manifest" "$post_manifest"; do
  if [[ ! -s "$file" ]]; then
    echo "Missing expected drill artifact: $file" >&2
    exit 1
  fi
done

if cmp -s "$baseline_manifest" "$rotated_manifest"; then
  echo "Baseline and rotated manifests should differ" >&2
  exit 1
fi

if ! cmp -s "$baseline_manifest" "$rollback_manifest"; then
  echo "Rollback manifest should match baseline" >&2
  exit 1
fi

if cmp -s "$baseline_manifest" "$post_manifest"; then
  echo "Post-rollback manifest should differ from baseline" >&2
  exit 1
fi

echo "✅ Rollback rehearsal harness passed"
