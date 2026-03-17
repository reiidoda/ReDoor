# Release Integrity and Provenance

This project provides a deterministic release pipeline for core Linux artifacts:

- `redoor-client` (Rust)
- `redoor-relay` (Go)
- `redoor-blockchain` (Rust)
- `redoor-directory` (Rust)

Release bundle name:
- `redoor-core-linux-amd64.tar.gz`

## 1. Deterministic Build Generation

Generate release artifacts locally:

```bash
cd <repo-root>
./scripts/release-build-core.sh --output-dir dist/release
```

Outputs:
- `dist/release/redoor-core-linux-amd64.tar.gz`
- `dist/release/redoor-core-linux-amd64.tar.gz.sha256`
- `dist/release/redoor-core-linux-amd64.sbom.cdx.json` (when `syft` is installed)
- `dist/release/SHA256SUMS`
- `*.sig` and `*.pem` signature artifacts (when `RELEASE_SIGN_WITH_COSIGN=1`)

The build script hardens reproducibility by:
- setting `SOURCE_DATE_EPOCH` from git commit time (or env override);
- using Rust path remapping and Linux build-id suppression;
- using Go `-trimpath` and deterministic linker flags;
- creating a normalized tarball (fixed mtime and stable file ordering; GNU tar also applies normalized owner/group metadata).

## 2. Reproducibility Check (Hash Consistency)

Run two independent rebuilds and compare resulting hashes:

```bash
cd <repo-root>
./scripts/verify-reproducible-build.sh
```

Pass criteria:
- artifact SHA256 must match across rebuilds;
- per-file `SHA256SUMS` manifests must be identical.

## 3. Release Provenance in CI

Workflow: `.github/workflows/release-integrity.yml`

Trigger:
- tag push (`v*`)
- manual dispatch

The job:
- verifies reproducibility (`verify-reproducible-build.sh`);
- builds release artifacts with enforced SBOM and Cosign signatures (`release-build-core.sh`);
- uploads bundle + checksums;
- emits signed provenance attestations via `actions/attest-build-provenance@v1`;
- publishes release assets for tag builds.

## 4. Operator/User Verification

Verify checksum (and optionally GitHub attestation signer identity):

```bash
cd <repo-root>
./scripts/verify-release-integrity.sh \
  --artifact dist/release/redoor-core-linux-amd64.tar.gz \
  --checksum dist/release/redoor-core-linux-amd64.tar.gz.sha256 \
  --sbom dist/release/redoor-core-linux-amd64.sbom.cdx.json \
  --require-sbom \
  --require-signatures \
  --cosign-cert-identity-regex '^https://github.com/reiidoda/ReDoor/.github/workflows/release-integrity.yml@refs/(heads/main|tags/.*)$' \
  --cosign-oidc-issuer https://token.actions.githubusercontent.com \
  --repo reiidoda/redoor \
  --signer-workflow reiidoda/redoor/.github/workflows/release-integrity.yml
```

`--repo` and `--signer-workflow` enforce actor identity when verifying provenance.
`--require-sbom` and `--require-signatures` enforce SBOM/signature presence for release assets.
