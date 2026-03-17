# Contributing to Redoor

Thanks for helping improve Redoor.

## Before You Start

- Read `README.md` for repository scope and local setup.
- Read `CODE_OF_CONDUCT.md`.
- Read `LICENSE` (MIT terms).
- Review current open work in `docs/OPEN_SOURCE_STATUS.md`.

## Where to Pick Work

Primary active milestone:
- `M27 - Open Source Readiness & Unfinished Work`

Current tracked issues in that milestone:
- #212 iOS Runtime Integration: remove production linker stubs
- #213 Telemetry: implement real relay connection metrics
- #214 Reliability: promote deterministic E2E tests in CI
- #215 Documentation Governance: roadmap status reconciliation
- #216 Enterprise Roadmap M1 decomposition
- #217 PIR/proxy deployability graduation plan
- #218 Open-source governance and templates

## Contribution Flow

1. Create or pick an issue.
2. Confirm scope and acceptance criteria in the issue body.
3. Create a branch from `main`.
4. Implement with tests.
5. Update docs when behavior or policy changes.
6. Open a PR and reference the issue (`Fixes #<number>` when appropriate).

## PR Expectations

- Keep changes focused and reviewable.
- Include tests for new behavior when feasible.
- Do not weaken fail-closed security paths.
- By contributing, you acknowledge contributions are governed by the repository license terms.
- For security-sensitive changes, include:
  - threat/failure mode notes,
  - rollback or kill-switch notes,
  - diagnostics/telemetry impact,
  - docs update references.

## Local Validation

Use project quality gates before opening a PR:

```bash
cd <repo-root>
make ci
```

If full CI is heavy, run targeted checks for touched components and explain what was run in the PR.

## Security Reports

Do not open public issues for sensitive vulnerabilities.

Use coordinated disclosure channels described in `CODE_OF_CONDUCT.md` and `docs/security-runbook.md`.

