#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_PATH=""
CHECKSUM_PATH=""
REPO=""
SIGNER_WORKFLOW=""
SOURCE_REF=""
SBOM_PATH=""
REQUIRE_SBOM=0
REQUIRE_SIGNATURES=0
COSIGN_CERT_IDENTITY_REGEX=""
COSIGN_OIDC_ISSUER=""

usage() {
  cat <<'EOF'
Usage:
  ./scripts/verify-release-integrity.sh \
    --artifact <path/to/redoor-core-linux-amd64.tar.gz> \
    [--checksum <path/to/redoor-core-linux-amd64.tar.gz.sha256>] \
    [--sbom <path/to/redoor-core-linux-amd64.sbom.cdx.json>] \
    [--require-sbom] \
    [--require-signatures] \
    [--cosign-cert-identity-regex <regex>] \
    [--cosign-oidc-issuer <issuer>] \
    [--repo <owner/repo>] \
    [--signer-workflow <owner/repo/.github/workflows/release-integrity.yml>] \
    [--source-ref <git-ref>]

Examples:
  ./scripts/verify-release-integrity.sh \
    --artifact dist/release/redoor-core-linux-amd64.tar.gz \
    --checksum dist/release/redoor-core-linux-amd64.tar.gz.sha256 \
    --sbom dist/release/redoor-core-linux-amd64.sbom.cdx.json \
    --require-sbom \
    --require-signatures

  ./scripts/verify-release-integrity.sh \
    --artifact redoor-core-linux-amd64.tar.gz \
    --require-signatures \
    --cosign-cert-identity-regex '^https://github.com/reiidoda/ReDoor/.github/workflows/release-integrity.yml@refs/tags/.*$' \
    --cosign-oidc-issuer https://token.actions.githubusercontent.com \
    --repo reiidoda/ReDoor \
    --signer-workflow reiidoda/ReDoor/.github/workflows/release-integrity.yml
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
    --sbom)
      SBOM_PATH="$2"
      shift 2
      ;;
    --require-sbom)
      REQUIRE_SBOM=1
      shift
      ;;
    --require-signatures)
      REQUIRE_SIGNATURES=1
      shift
      ;;
    --cosign-cert-identity-regex)
      COSIGN_CERT_IDENTITY_REGEX="$2"
      shift 2
      ;;
    --cosign-oidc-issuer)
      COSIGN_OIDC_ISSUER="$2"
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
    -h | --help)
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

if [[ -z "$SBOM_PATH" ]]; then
  SBOM_PATH="${ARTIFACT_PATH%.tar.gz}.sbom.cdx.json"
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

if [[ "$REQUIRE_SIGNATURES" == "1" ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "::error::cosign is required with --require-signatures" >&2
    exit 1
  fi
fi

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

if [[ "$REQUIRE_SBOM" == "1" && ! -f "$SBOM_PATH" ]]; then
  echo "::error::SBOM file not found: $SBOM_PATH" >&2
  exit 1
fi

if [[ -f "$SBOM_PATH" ]]; then
  echo "PASS: SBOM present at $SBOM_PATH"
fi

verify_signature_for_file() {
  local target_file="$1"
  local signature_file="${target_file}.sig"
  local certificate_file="${target_file}.pem"

  if [[ ! -f "$signature_file" || ! -f "$certificate_file" ]]; then
    if [[ "$REQUIRE_SIGNATURES" == "1" ]]; then
      echo "::error::Missing signature or certificate for $target_file" >&2
      exit 1
    fi
    echo "Skipping signature verification for $target_file (signature/certificate not found)."
    return
  fi

  local cmd=(cosign verify-blob "$target_file" --signature "$signature_file" --certificate "$certificate_file")
  if [[ -n "$COSIGN_CERT_IDENTITY_REGEX" ]]; then
    cmd+=(--certificate-identity-regexp "$COSIGN_CERT_IDENTITY_REGEX")
  fi
  if [[ -n "$COSIGN_OIDC_ISSUER" ]]; then
    cmd+=(--certificate-oidc-issuer "$COSIGN_OIDC_ISSUER")
  fi

  echo "==> Verifying cosign signature for $(basename "$target_file")"
  "${cmd[@]}"
  echo "PASS: signature verified for $(basename "$target_file")"
}

verify_signature_for_file "$ARTIFACT_PATH"
verify_signature_for_file "$CHECKSUM_PATH"
if [[ -f "$SBOM_PATH" ]]; then
  verify_signature_for_file "$SBOM_PATH"
fi
MANIFEST_PATH="$(dirname "$CHECKSUM_PATH")/SHA256SUMS"
if [[ -f "$MANIFEST_PATH" ]]; then
  verify_signature_for_file "$MANIFEST_PATH"
fi

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
