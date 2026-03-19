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

## 3. Trusted Build Environment and Isolation Assumptions

This repository treats the following as trusted build assumptions for public releases:

- release builds run on a clean, ephemeral CI runner or a freshly prepared local environment;
- pinned toolchains and repository-managed build scripts are used;
- the release output directory starts empty;
- signing/provenance material is never committed to the repository;
- provenance, reproducibility, and signature verification failures are release blockers.

If any of these assumptions are violated, the release should be treated as not ready for publication.

## 4. Release Provenance in CI

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

## 5. Release Sign-Off Workflow

Public releases require:

- `Release Lead` sign-off
  - confirms reproducible-build and artifact-verification checks passed
- `Security Lead` sign-off
  - confirms security gates are green and no unresolved blocker or override remains

Fallback delegate policy:
- another maintainer may act as delegate when a primary role is unavailable
- the delegate must explicitly record which role they covered

Sign-off evidence must be recorded in:
- the release PR, release-prep issue, or release notes
- linked verification commands and artifact references

## 6. Operator/User Verification

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
  --repo reiidoda/ReDoor \
  --signer-workflow reiidoda/ReDoor/.github/workflows/release-integrity.yml
```

`--repo` and `--signer-workflow` enforce actor identity when verifying provenance.
`--require-sbom` and `--require-signatures` enforce SBOM/signature presence for release assets.

Operator guidance:
- verify the artifact checksum before attestation checks,
- verify the attestation identity against the expected workflow path,
- reject releases missing signatures, SBOMs, or provenance when those are required by policy.
