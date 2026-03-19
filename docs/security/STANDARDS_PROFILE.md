# Security Standards Profile

This document defines the public security standards baseline for ReDoor and the evidence expected for contributor-facing changes.

## Adopted Frameworks

- `NIST CSF 2.0`
  - top-level governance and risk-management frame for identify/protect/detect/respond/recover work
- `NIST SSDF 1.1`
  - secure software development process baseline for planning, implementation, review, release, and maintenance
- `OWASP ASVS 5.0`
  - application verification baseline for relay, directory, blockchain, and shared Rust runtime boundaries
- `OWASP MASVS 2.1`
  - mobile verification baseline for the iOS app and mobile runtime posture checks
- `SLSA 1.2`
  - release provenance, build-isolation, and artifact-verification baseline

## Roles and Ownership

- `Maintainers`
  - roadmap prioritization, review, release, and community moderation
- `Security Lead`
  - security triage, control-matrix ownership, release security approval
- `Release Lead`
  - release readiness, reproducibility/provenance verification, release publication
- `Component Leads`
  - domain-specific ownership for client, mobile, relay, directory, blockchain, and privacy track changes

One maintainer may temporarily hold multiple roles, but release evidence must still record which role approved which gate.

## Evidence Model

Primary evidence locations:
- `docs/security/control-matrix.csv`
- component tests and CI scripts
- release verification artifacts
- threat model / runbook / release docs when behavior or operational response changes

Every security-relevant change should leave behind:
- test evidence or an explicit gap note,
- updated operational guidance when responders/operators are affected,
- updated control mapping when a standard-aligned control changes status.

## Security-Relevant Change Categories

Treat a PR as security-relevant when it changes any of the following:
- authentication, authorization, scoped credentials, or admin surfaces
- cryptography, key custody, secret handling, or lifecycle wipe logic
- parser boundaries, input validation, replay handling, or abuse controls
- privacy posture, onion routing, metadata resistance, or anonymity gates
- release integrity, provenance, signing, or reproducibility controls
- mobile runtime hardening, lockdown behavior, or compromise posture checks

## Pull Request Policy

Security-relevant PRs must:
- complete the security section in `.github/PULL_REQUEST_TEMPLATE.md`
- update `docs/security/control-matrix.csv`, or explicitly state why no mapped control changed
- document rollback or containment considerations when operational behavior changes
- call out telemetry and runbook impact when detections, alerts, or incident handling change

The PR policy workflow blocks security-relevant PRs whose checklist is incomplete.

## Release Sign-Off Workflow

Before a tagged release is published, the following approvals are required:
- `Release Lead`
  - confirms reproducible-build and provenance checks passed
- `Security Lead`
  - confirms security gates are green and no unresolved blocker remains

Fallback delegate policy:
- if a primary role is unavailable, another maintainer may act as delegate
- the delegate must record which role they covered
- the delegate record must be visible in the release PR or release notes

Required sign-off evidence:
- link to the release PR or release preparation issue
- commands run and artifact references
- any incident override or exception ID, if used

Evidence storage locations:
- release PR body or comment thread
- release notes for the tag
- attached verification artifacts when applicable

## Standards Review Cadence

- update this profile when a framework version changes or a new baseline is adopted
- update `docs/security/control-matrix.csv` when a mapped control changes status
- review the profile before each public release and after major security incidents
