# Open Source Status

This document is the contributor-facing status board for what is complete and what still needs implementation.

## Source Of Truth

- Canonical tracker: `https://github.com/reiidoda/ReDoor/issues`
- Open implementation query: `https://github.com/reiidoda/ReDoor/issues?q=is%3Aissue+is%3Aopen`
- Last synced: `2026-03-17`
- Update owner: `maintainers (docs governance)`
- Sync cadence:
  - at least once per week,
  - on every issue open/close affecting contributor-facing status,
  - before release-tag PRs.

## Governance and Community Baseline

- `CONTRIBUTING.md` published
- `SECURITY.md` published
- `SUPPORT.md` published
- `GOVERNANCE.md` published

## Open Implementation Work (Repository Tracker)

- `#1` iOS: replace linker stubs with real Rust FFI and remove `RedoorStubs.c`
- `#2` Runtime telemetry: implement non-placeholder relay connection metrics in FFI
- `#4` CI/workflows: upgrade actions/workflows for Node 24 compatibility
- `#5` Roadmap: decompose enterprise M1 candidate scope into implementation tasks
- `#6` Privacy track: define PIR/proxy deployability graduation plan
  - plan doc: `docs/security/PIR_PROXY_DEPLOYABILITY_GRADUATION_PLAN.md`
  - follow-up tasks: `#23`, `#24`, `#25`, `#26`
- `#7` Docs governance: keep open-source status board synchronized with repository tracker
- `#14` Security testing: expand fuzzing matrix and nightly coverage tracking
- `#15` Key management: introduce KMS/HSM-backed signing and rotation path
- `#16` Security ops: add relay/directory anomaly detection and response playbooks

## How This File Is Updated

Update this file when:
- contributor-facing open-work issues are created/closed,
- issue titles/scope materially change,
- contributor priorities change.

Keep this file aligned with:
- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `SUPPORT.md`
- `GOVERNANCE.md`
- `docs/security/ADVANCED_MESSAGE_SECURITY.md`
- `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`

