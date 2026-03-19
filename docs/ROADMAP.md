# Public Roadmap

This roadmap is the contributor-facing plan for ReDoor after the public repository reset.

Use this document together with:
- `docs/OPEN_SOURCE_STATUS.md` for the live status board
- `docs/security/STANDARDS_PROFILE.md` for adopted security frameworks
- `docs/security/control-matrix.csv` for evidence tracking

## Current Focus

### 1. Security Standards and Contributor Hardening
- `#38` Auth hardening: ASVS-V2 negative-path coverage for admin and scoped credentials
- `#39` Validation hardening: ASVS-V5 replay and malformed-input coverage
- `#40` Mobile hardening: MASVS resilience evidence for runtime compromise conditions

### 2. Key Management and Release Hardening
- `#15` KMS/HSM-backed signing and rotation path

### 3. Privacy Track Execution
- `#23` PIR/proxy benchmark gates and CI evidence
- `#24` Proxy trust controls and jurisdiction split
- `#25` PIR/proxy abuse controls and response playbooks
- `#26` PIR/proxy pilot rollout and rollback gate

### 4. Enterprise M1 Execution
- `#28` OpenAPI contracts and strict request validation
- `#29` mTLS service-plane identity and certificate rotation
- `#30` KMS/bootstrap key management and staged rotation framework
- `#31` Security event taxonomy and structured audit-log rollout

## Milestone Map

- `M4 - Standards Alignment and Contributor Hardening`
  - closes public-process gaps around SSDF, SLSA, ASVS, and MASVS alignment
- `M5 - Privacy and Enterprise Execution`
  - tracks privacy rollout work, key custody, and enterprise service hardening

## Contributor Entry Points

- `good first issue`: small, self-contained onboarding work
- `help wanted`: maintainers want external contribution on this issue
- `documentation`: docs/process changes
- `enhancement`: implementation work or roadmap delivery

## Working Agreements

- Open an issue or confirm an existing issue before broad cross-component changes.
- Keep security-relevant PRs aligned with `docs/security/control-matrix.csv`.
- Update docs in the same PR when behavior, policy, or contributor workflow changes.
