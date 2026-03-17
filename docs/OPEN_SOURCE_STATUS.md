# Open Source Status

This document is the contributor-facing status board for what is complete and what still needs implementation.

## Current Active Milestone

- `M27 - Open Source Readiness & Unfinished Work`

## Governance and Community Baseline

- `CONTRIBUTING.md` published
- `SECURITY.md` published
- `SUPPORT.md` published
- `GOVERNANCE.md` published

## Open Implementation Work (Tracked)

- `#212` iOS runtime integration: remove production linker stubs and wire real Rust FFI
- `#213` Telemetry: implement real relay connection metrics in Rust runtime + FFI
- `#214` Reliability: de-risk ignored integration tests and promote deterministic E2E CI coverage
- `#215` Documentation governance: reconcile roadmap status with closed/open GitHub workstreams
- `#216` Enterprise roadmap M1: break candidate scope into implementation-ready public issues
- `#217` Privacy research track: define PIR/proxy deployability gates and graduation plan
- `#218` Open source governance: contributor workflow, issue taxonomy, and templates

## Context

Recent security workstreams `#196` through `#204` are closed under milestone `M26`.
Some repository docs still include stale wording that implies parts of M26 are pending; issue `#215` tracks reconciliation.

## How This File Is Updated

Update this file when:
- a milestone is added/closed,
- a tracked open-work issue is created/closed,
- contributor priorities change.

Keep this file aligned with:
- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `SUPPORT.md`
- `GOVERNANCE.md`
- `docs/security/ADVANCED_MESSAGE_SECURITY.md`
- `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`

