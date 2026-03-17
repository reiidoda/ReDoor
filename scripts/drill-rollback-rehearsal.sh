#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Create an isolated rollback rehearsal environment for relay/directory cert + relay HMAC rotation drills.

Usage:
  drill-rollback-rehearsal.sh [--workspace PATH] [--keep-workspace] [--relay-cn NAME] [--directory-cn NAME] [--days N]

Options:
  --workspace PATH     Use a fixed workspace path (default: auto temp dir)
  --keep-workspace     Do not delete workspace on exit
  --relay-cn NAME      Relay certificate CN for rehearsal rotations (default: relay-drill.local)
  --directory-cn NAME  Directory certificate CN for rehearsal rotations (default: directory-drill.local)
  --days N             Certificate validity days for rehearsal rotations (default: 14)
  -h, --help           Show this help
USAGE
}

workspace=""
keep_workspace=0
relay_cn="relay-drill.local"
directory_cn="directory-drill.local"
days=14

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      workspace="$2"
      shift 2
      ;;
    --keep-workspace)
      keep_workspace=1
      shift
      ;;
    --relay-cn)
      relay_cn="$2"
      shift 2
      ;;
    --directory-cn)
      directory_cn="$2"
      shift 2
      ;;
    --days)
      days="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "$days" =~ ^[0-9]+$ ]] || [[ "$days" -le 0 ]]; then
  echo "--days must be a positive integer" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
rotate_script="$ROOT/scripts/rotate-service-cert.sh"

if [[ -z "$workspace" ]]; then
  workspace="$(mktemp -d "${TMPDIR:-/tmp}/redoor-rollback-drill.XXXXXX")"
else
  mkdir -p "$workspace"
fi

cleanup() {
  if [[ "$keep_workspace" -eq 0 ]]; then
    rm -rf "$workspace"
  fi
}
trap cleanup EXIT

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() {
    sha256sum "$1" | awk '{print $1}'
  }
else
  hash_file() {
    shasum -a 256 "$1" | awk '{print $1}'
  }
fi

generate_hmac_key() {
  openssl rand -base64 32 | tr -d '\n'
}

copy_if_present() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$dst"
    return 0
  fi
  return 1
}

assert_changed() {
  local lhs="$1"
  local rhs="$2"
  local label="$3"
  if cmp -s "$lhs" "$rhs"; then
    echo "Expected '${label}' to change during rotation" >&2
    exit 1
  fi
}

assert_same() {
  local lhs="$1"
  local rhs="$2"
  local label="$3"
  if ! cmp -s "$lhs" "$rhs"; then
    echo "Expected '${label}' to match baseline after rollback" >&2
    exit 1
  fi
}

write_manifest() {
  local root_dir="$1"
  local output_file="$2"
  (
    cd "$root_dir"
    find . -type f | sort | while read -r file; do
      file="${file#./}"
      printf '%s  %s\n' "$(hash_file "$root_dir/$file")" "$file"
    done
  ) >"$output_file"
}

start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
baseline_dir="$workspace/baseline"
active_dir="$workspace/active"
rotated_dir="$workspace/rotated"
post_dir="$workspace/post-rollback"
evidence_dir="$workspace/evidence"

mkdir -p "$baseline_dir/relay" "$baseline_dir/directory" "$evidence_dir"

if ! copy_if_present "$ROOT/relay-node/cert.pem" "$baseline_dir/relay/cert.pem" || \
   ! copy_if_present "$ROOT/relay-node/key.pem" "$baseline_dir/relay/key.pem"; then
  "$rotate_script" relay \
    --cert-file "$baseline_dir/relay/cert.pem" \
    --key-file "$baseline_dir/relay/key.pem" \
    --cn "$relay_cn" \
    --days "$days" \
    >/dev/null
fi

if ! copy_if_present "$ROOT/directory-dht/cert.pem" "$baseline_dir/directory/cert.pem" || \
   ! copy_if_present "$ROOT/directory-dht/key.pem" "$baseline_dir/directory/key.pem"; then
  "$rotate_script" directory \
    --cert-file "$baseline_dir/directory/cert.pem" \
    --key-file "$baseline_dir/directory/key.pem" \
    --cn "$directory_cn" \
    --days "$days" \
    >/dev/null
fi

umask 077
printf '%s\n' "$(generate_hmac_key)" >"$baseline_dir/relay/hmac.key.b64"
chmod 600 "$baseline_dir/relay/hmac.key.b64"

rm -rf "$active_dir"
cp -R "$baseline_dir" "$active_dir"

"$rotate_script" relay \
  --cert-file "$active_dir/relay/cert.pem" \
  --key-file "$active_dir/relay/key.pem" \
  --cn "$relay_cn" \
  --days "$days" \
  >/dev/null
"$rotate_script" directory \
  --cert-file "$active_dir/directory/cert.pem" \
  --key-file "$active_dir/directory/key.pem" \
  --cn "$directory_cn" \
  --days "$days" \
  >/dev/null
printf '%s\n' "$(generate_hmac_key)" >"$active_dir/relay/hmac.key.b64"
chmod 600 "$active_dir/relay/hmac.key.b64"

assert_changed "$baseline_dir/relay/cert.pem" "$active_dir/relay/cert.pem" "relay cert"
assert_changed "$baseline_dir/relay/key.pem" "$active_dir/relay/key.pem" "relay key"
assert_changed "$baseline_dir/directory/cert.pem" "$active_dir/directory/cert.pem" "directory cert"
assert_changed "$baseline_dir/directory/key.pem" "$active_dir/directory/key.pem" "directory key"
assert_changed "$baseline_dir/relay/hmac.key.b64" "$active_dir/relay/hmac.key.b64" "relay hmac"

rm -rf "$rotated_dir"
cp -R "$active_dir" "$rotated_dir"

cp "$baseline_dir/relay/cert.pem" "$active_dir/relay/cert.pem"
cp "$baseline_dir/relay/key.pem" "$active_dir/relay/key.pem"
cp "$baseline_dir/directory/cert.pem" "$active_dir/directory/cert.pem"
cp "$baseline_dir/directory/key.pem" "$active_dir/directory/key.pem"
cp "$baseline_dir/relay/hmac.key.b64" "$active_dir/relay/hmac.key.b64"

assert_same "$baseline_dir/relay/cert.pem" "$active_dir/relay/cert.pem" "relay cert rollback"
assert_same "$baseline_dir/relay/key.pem" "$active_dir/relay/key.pem" "relay key rollback"
assert_same "$baseline_dir/directory/cert.pem" "$active_dir/directory/cert.pem" "directory cert rollback"
assert_same "$baseline_dir/directory/key.pem" "$active_dir/directory/key.pem" "directory key rollback"
assert_same "$baseline_dir/relay/hmac.key.b64" "$active_dir/relay/hmac.key.b64" "relay hmac rollback"

rm -rf "$post_dir"
cp -R "$active_dir" "$post_dir"
"$rotate_script" relay \
  --cert-file "$post_dir/relay/cert.pem" \
  --key-file "$post_dir/relay/key.pem" \
  --cn "$relay_cn" \
  --days "$days" \
  >/dev/null
"$rotate_script" directory \
  --cert-file "$post_dir/directory/cert.pem" \
  --key-file "$post_dir/directory/key.pem" \
  --cn "$directory_cn" \
  --days "$days" \
  >/dev/null
printf '%s\n' "$(generate_hmac_key)" >"$post_dir/relay/hmac.key.b64"
chmod 600 "$post_dir/relay/hmac.key.b64"

assert_changed "$baseline_dir/relay/cert.pem" "$post_dir/relay/cert.pem" "post-rollback relay cert"
assert_changed "$baseline_dir/relay/key.pem" "$post_dir/relay/key.pem" "post-rollback relay key"
assert_changed "$baseline_dir/directory/cert.pem" "$post_dir/directory/cert.pem" "post-rollback directory cert"
assert_changed "$baseline_dir/directory/key.pem" "$post_dir/directory/key.pem" "post-rollback directory key"
assert_changed "$baseline_dir/relay/hmac.key.b64" "$post_dir/relay/hmac.key.b64" "post-rollback relay hmac"

find "$baseline_dir" "$active_dir" "$rotated_dir" "$post_dir" -type f -name '*.bak.*' -delete

write_manifest "$baseline_dir" "$evidence_dir/baseline.sha256"
write_manifest "$rotated_dir" "$evidence_dir/rotated.sha256"
write_manifest "$active_dir" "$evidence_dir/rollback.sha256"
write_manifest "$post_dir" "$evidence_dir/post-rollback.sha256"

end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"$evidence_dir/rollback-rehearsal-summary.md" <<EOF
# Rollback Rehearsal Summary

- Started (UTC): ${start_ts}
- Finished (UTC): ${end_ts}
- Workspace: ${workspace}

## Steps Executed

1. Baseline snapshot prepared in isolated workspace.
2. Rotation rehearsal completed for relay cert/key, directory cert/key, and relay HMAC key.
3. Rollback rehearsal restored all active assets to baseline state.
4. Post-rollback rotation completed to validate recovery readiness.

## Evidence Artifacts

- Baseline manifest: ${evidence_dir}/baseline.sha256
- Rotated-state manifest: ${evidence_dir}/rotated.sha256
- Rollback-state manifest: ${evidence_dir}/rollback.sha256
- Post-rollback manifest: ${evidence_dir}/post-rollback.sha256
- Summary: ${evidence_dir}/rollback-rehearsal-summary.md
EOF

{
  printf '{\n'
  printf '  "started_at_utc": "%s",\n' "$start_ts"
  printf '  "finished_at_utc": "%s",\n' "$end_ts"
  printf '  "workspace": "%s",\n' "$workspace"
  printf '  "evidence": {\n'
  printf '    "baseline_manifest": "%s",\n' "$evidence_dir/baseline.sha256"
  printf '    "rotated_manifest": "%s",\n' "$evidence_dir/rotated.sha256"
  printf '    "rollback_manifest": "%s",\n' "$evidence_dir/rollback.sha256"
  printf '    "post_rollback_manifest": "%s",\n' "$evidence_dir/post-rollback.sha256"
  printf '    "summary_markdown": "%s"\n' "$evidence_dir/rollback-rehearsal-summary.md"
  printf '  }\n'
  printf '}\n'
} >"$evidence_dir/rollback-rehearsal-summary.json"

echo "Rollback rehearsal completed successfully." >&2
echo "Workspace: $workspace" >&2
echo "Evidence summary: $evidence_dir/rollback-rehearsal-summary.md" >&2

if [[ "$keep_workspace" -eq 1 ]]; then
  trap - EXIT
fi
