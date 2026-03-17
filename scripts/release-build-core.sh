#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT_DIR="$ROOT/dist/release"
RELEASE_REQUIRE_SBOM="${RELEASE_REQUIRE_SBOM:-0}"
RELEASE_SIGN_WITH_COSIGN="${RELEASE_SIGN_WITH_COSIGN:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--output-dir <path>]" >&2
      exit 1
      ;;
  esac
done

if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$ROOT/$OUT_DIR"
fi

for cmd in cargo go git sha256sum tar gzip mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::$cmd is required for release build generation" >&2
    exit 1
  fi
done

if [[ "$RELEASE_REQUIRE_SBOM" == "1" ]] && ! command -v syft >/dev/null 2>&1; then
  echo "::error::syft is required when RELEASE_REQUIRE_SBOM=1" >&2
  exit 1
fi

if [[ "$RELEASE_SIGN_WITH_COSIGN" == "1" ]] && ! command -v cosign >/dev/null 2>&1; then
  echo "::error::cosign is required when RELEASE_SIGN_WITH_COSIGN=1" >&2
  exit 1
fi

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --pretty=%ct)}"
GIT_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
GIT_SHORT="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
ARTIFACT_BASENAME="redoor-core-linux-amd64"

mkdir -p "$OUT_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

export TZ=UTC
export LC_ALL=C
export SOURCE_DATE_EPOCH

RUSTFLAGS_REPRO="--remap-path-prefix=$ROOT=. -C debuginfo=0"
if [[ "$(uname -s)" == "Linux" ]]; then
  RUSTFLAGS_REPRO="$RUSTFLAGS_REPRO -C link-arg=-Wl,--build-id=none"
fi
if [[ -n "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="$RUSTFLAGS_REPRO $RUSTFLAGS"
else
  export RUSTFLAGS="$RUSTFLAGS_REPRO"
fi

build_rust_binary() {
  local crate_dir="$1"
  local bin_name="$2"
  (
    cd "$ROOT/$crate_dir"
    CARGO_INCREMENTAL=0 cargo build --release --locked --bin "$bin_name"
  )
  cp "$ROOT/$crate_dir/target/release/$bin_name" "$WORK_DIR/$bin_name"
}

echo "==> Building Rust core binaries"
build_rust_binary "client" "redoor-client"
build_rust_binary "blockchain-node" "redoor-blockchain"
build_rust_binary "directory-dht" "redoor-directory"

echo "==> Building Go relay binary"
(
  cd "$ROOT/relay-node"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS="-trimpath -buildvcs=false" \
    go build -ldflags="-buildid= -s -w" -o "$WORK_DIR/redoor-relay" ./src/main.go
)

chmod 0755 \
  "$WORK_DIR/redoor-client" \
  "$WORK_DIR/redoor-relay" \
  "$WORK_DIR/redoor-blockchain" \
  "$WORK_DIR/redoor-directory"

cat > "$WORK_DIR/BUILD_INFO.txt" <<EOF
artifact=${ARTIFACT_BASENAME}
git_commit=${GIT_COMMIT}
git_short=${GIT_SHORT}
source_date_epoch=${SOURCE_DATE_EPOCH}
EOF

ARTIFACT_PATH="$OUT_DIR/${ARTIFACT_BASENAME}.tar.gz"
TAR_PATH="$OUT_DIR/${ARTIFACT_BASENAME}.tar"
CHECKSUM_PATH="$OUT_DIR/${ARTIFACT_BASENAME}.tar.gz.sha256"
MANIFEST_PATH="$OUT_DIR/SHA256SUMS"
SBOM_PATH="$OUT_DIR/${ARTIFACT_BASENAME}.sbom.cdx.json"

echo "==> Packaging deterministic tarball"
if date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S >/dev/null 2>&1; then
  TOUCH_TS="$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)"
else
  TOUCH_TS="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)"
fi
touch -t "$TOUCH_TS" \
  "$WORK_DIR/BUILD_INFO.txt" \
  "$WORK_DIR/redoor-blockchain" \
  "$WORK_DIR/redoor-client" \
  "$WORK_DIR/redoor-directory" \
  "$WORK_DIR/redoor-relay"

if tar --sort=name --version >/dev/null 2>&1; then
  (
    cd "$WORK_DIR"
    tar \
      --sort=name \
      --mtime="@${SOURCE_DATE_EPOCH}" \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf "$TAR_PATH" \
      BUILD_INFO.txt \
      redoor-blockchain \
      redoor-client \
      redoor-directory \
      redoor-relay
  )
else
  (
    cd "$WORK_DIR"
    tar -cf "$TAR_PATH" \
      BUILD_INFO.txt \
      redoor-blockchain \
      redoor-client \
      redoor-directory \
      redoor-relay
  )
fi

gzip -n -f "$TAR_PATH"

echo "==> Writing checksums"
sha256sum "$ARTIFACT_PATH" | awk '{print $1 "  '"${ARTIFACT_BASENAME}"'.tar.gz"}' > "$CHECKSUM_PATH"
{
  (
    cd "$WORK_DIR"
    sha256sum \
      BUILD_INFO.txt \
      redoor-blockchain \
      redoor-client \
      redoor-directory \
      redoor-relay
  )
  sha256sum "$ARTIFACT_PATH" | awk '{print $1 "  '"${ARTIFACT_BASENAME}"'.tar.gz"}'
} > "$MANIFEST_PATH"

if command -v syft >/dev/null 2>&1; then
  echo "==> Generating CycloneDX SBOM"
  syft "$ARTIFACT_PATH" -o "cyclonedx-json=$SBOM_PATH"
elif [[ "$RELEASE_REQUIRE_SBOM" == "1" ]]; then
  echo "::error::SBOM generation required but syft was not found" >&2
  exit 1
else
  echo "Skipping SBOM generation (install syft or set RELEASE_REQUIRE_SBOM=1 to enforce)."
fi

if [[ "$RELEASE_SIGN_WITH_COSIGN" == "1" ]]; then
  echo "==> Signing release artifacts with cosign"
  sign_blob() {
    local file="$1"
    local sig_path="${file}.sig"
    local cert_path="${file}.pem"
    if [[ -n "${COSIGN_KEY:-}" ]]; then
      cosign sign-blob --yes --key env://COSIGN_KEY --output-signature "$sig_path" --output-certificate "$cert_path" "$file"
    else
      cosign sign-blob --yes --output-signature "$sig_path" --output-certificate "$cert_path" "$file"
    fi
  }

  sign_blob "$ARTIFACT_PATH"
  sign_blob "$CHECKSUM_PATH"
  sign_blob "$MANIFEST_PATH"
  if [[ -f "$SBOM_PATH" ]]; then
    sign_blob "$SBOM_PATH"
  fi
fi

echo "Built release artifacts:"
echo "  - $ARTIFACT_PATH"
echo "  - $CHECKSUM_PATH"
echo "  - $MANIFEST_PATH"
if [[ -f "$SBOM_PATH" ]]; then
  echo "  - $SBOM_PATH"
fi
