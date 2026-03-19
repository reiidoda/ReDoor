# Governance

## Project Model

Redoor is a maintainer-led open-source project.

Maintainers are responsible for:
- roadmap prioritization,
- review and merge decisions,
- release decisions,
- security and reliability gatekeeping,
- moderation and community standards enforcement.

## Maintainer Roles

- `Maintainer`
  - general review, triage, and roadmap stewardship
- `Security Lead`
  - control-matrix ownership, security triage, release security approval
- `Release Lead`
  - release readiness, provenance/reproducibility sign-off, release publication

One maintainer may temporarily serve in more than one role, but release evidence should still record which role approved which gate.

## Decision Process

- Normal changes are discussed in GitHub issues and reviewed in PRs.
- Major cross-component changes should have a tracked issue and linked docs updates.
- Security-sensitive changes require explicit risk context, evidence, and control-matrix maintenance.
- Public roadmap and status changes should stay aligned with `docs/ROADMAP.md` and `docs/OPEN_SOURCE_STATUS.md`.

## Source of Truth

- Roadmap: `docs/ROADMAP.md`
- Live status board: `docs/OPEN_SOURCE_STATUS.md`
- Contribution process: `CONTRIBUTING.md`
- Security standards profile: `docs/security/STANDARDS_PROFILE.md`
- Security reporting: `SECURITY.md`

## Change Completion Policy

A change is considered complete when:
- code and tests are merged,
- relevant docs are updated,
- mapped security/process controls are updated when applicable,
- impacted gates remain green in CI policy.
