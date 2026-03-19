# Open Source Status

This document is the contributor-facing live status board for the public repository.

## Source Of Truth

- Canonical tracker: `https://github.com/reiidoda/ReDoor/issues`
- Public roadmap: `docs/ROADMAP.md`
- Last synced: `2026-03-19`
- Update owner: `maintainers`
- Sync cadence:
  - after issue open/close events that change public priorities,
  - before tagged releases,
  - at least once per week while active development continues.

## Recently Completed

- `#1` iOS runtime wiring now uses real Rust FFI and production stub linkage is guarded in CI.
- `#2` Relay connection metrics now expose runtime-derived values in FFI with tests.
- `#4` Active workflows now use current action versions compatible with the Node 24 transition.
- `#5` Enterprise M1 was decomposed into scoped implementation issues (`#28`..`#31`).
- `#6` PIR/proxy graduation planning was documented and split into follow-up tasks (`#23`..`#26`).
- `#7` Contributor-facing status, roadmap, and governance docs were normalized for the public repo.
- `#14` Fuzz matrix and nightly coverage tracking were expanded.
- `#16` Relay/directory anomaly detection and response-playbook linkage were added.
- `#35` Release role sign-off workflow and fallback delegate policy were documented.
- `#36` Security-relevant PR checklist enforcement and control-matrix maintenance were added.
- `#37` Build-isolation assumptions, provenance requirements, and release blockers were documented.

## Active Public Work

### Standards Alignment and Contributor Hardening
- `#38` Auth hardening: ASVS-V2 mapped tests for admin and scoped credentials
- `#39` Validation hardening: ASVS-V5 replay and malformed-input negative-path coverage
- `#40` Mobile hardening: MASVS resilience evidence for runtime compromise conditions

### Key Management and Release Hardening
- `#15` KMS/HSM-backed signing and rotation path

### Privacy Track
- `#23` PIR/proxy benchmark gates and CI evidence
- `#24` Proxy trust controls and jurisdiction-split model
- `#25` PIR/proxy abuse controls and response playbooks
- `#26` PIR/proxy pilot rollout and rollback gate

### Enterprise M1 Execution
- `#28` OpenAPI contracts and strict request validation
- `#29` mTLS service-plane identity and certificate rotation
- `#30` KMS/bootstrap key management and staged rotation framework
- `#31` Security event taxonomy and structured audit-log rollout

## Contributor Entry Points

- `README.md`
- `CONTRIBUTING.md`
- `docs/ROADMAP.md`
- `docs/security/STANDARDS_PROFILE.md`
- `docs/security/control-matrix.csv`

## Update Policy

Keep this file aligned with:
- `README.md`
- `CONTRIBUTING.md`
- `GOVERNANCE.md`
- `docs/ROADMAP.md`
- `docs/security/STANDARDS_PROFILE.md`
- `docs/security/ADVANCED_MESSAGE_SECURITY.md`
- `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`
