#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_PATH=""
CHECKSUM_PATH=""
REPO=""
SIGNER_WORKFLOW=""
SOURCE_REF=""

usage() {
  cat <<'EOF'
Usage:
  ./scripts/verify-release-integrity.sh \
    --artifact <path/to/redoor-core-linux-amd64.tar.gz> \
    [--checksum <path/to/redoor-core-linux-amd64.tar.gz.sha256>] \
    [--repo <owner/repo>] \
    [--signer-workflow <owner/repo/.github/workflows/release-integrity.yml>] \
    [--source-ref <git-ref>]

Examples:
  ./scripts/verify-release-integrity.sh \
    --artifact dist/release/redoor-core-linux-amd64.tar.gz \
    --checksum dist/release/redoor-core-linux-amd64.tar.gz.sha256

  ./scripts/verify-release-integrity.sh \
    --artifact redoor-core-linux-amd64.tar.gz \
    --repo reiidoda/redoor \
    --signer-workflow reiidoda/redoor/.github/workflows/release-integrity.yml
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --checksum)
      CHECKSUM_PATH="$2"
      shift 2
      ;;
    --repo)
      REPO="$2"
      shift 2
      ;;
    --signer-workflow)
      SIGNER_WORKFLOW="$2"
      shift 2
      ;;
    --source-ref)
      SOURCE_REF="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ARTIFACT_PATH" ]]; then
  echo "::error::--artifact is required" >&2
  usage
  exit 1
fi

if [[ ! -f "$ARTIFACT_PATH" ]]; then
  echo "::error::Artifact not found: $ARTIFACT_PATH" >&2
  exit 1
fi

if [[ -z "$CHECKSUM_PATH" ]]; then
  CHECKSUM_PATH="${ARTIFACT_PATH}.sha256"
fi

if [[ ! -f "$CHECKSUM_PATH" ]]; then
  echo "::error::Checksum file not found: $CHECKSUM_PATH" >&2
  exit 1
fi

for cmd in sha256sum awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for integrity verification" >&2
    exit 1
  fi
done

EXPECTED_SHA="$(awk '{print $1; exit}' "$CHECKSUM_PATH")"
ACTUAL_SHA="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"

if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
  echo "::error::Checksum verification failed" >&2
  echo "expected: $EXPECTED_SHA" >&2
  echo "actual:   $ACTUAL_SHA" >&2
  exit 1
fi

echo "PASS: checksum verified"
echo "sha256: $ACTUAL_SHA"

if [[ -n "$REPO" ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "::error::gh CLI is required for provenance verification with --repo" >&2
    exit 1
  fi

  cmd=(gh attestation verify "$ARTIFACT_PATH" --repo "$REPO")
  if [[ -n "$SIGNER_WORKFLOW" ]]; then
    cmd+=(--signer-workflow "$SIGNER_WORKFLOW")
  fi
  if [[ -n "$SOURCE_REF" ]]; then
    cmd+=(--source-ref "$SOURCE_REF")
  fi

  echo "==> Verifying signed provenance attestation"
  "${cmd[@]}"
  echo "PASS: provenance attestation verified"
else
  echo "Skipping provenance verification (set --repo to enforce signer identity checks)."
fi
