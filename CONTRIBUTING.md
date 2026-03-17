# Contributing to Redoor

Thanks for helping improve Redoor.

## Before You Start

- Read `README.md` for repository scope and local setup.
- Read `CODE_OF_CONDUCT.md`.
- Read `LICENSE` (MIT terms).
- Review current open work in `docs/OPEN_SOURCE_STATUS.md`.

## Where to Pick Work

- Canonical status board: `docs/OPEN_SOURCE_STATUS.md`
- Repository issue tracker: `https://github.com/reiidoda/ReDoor/issues`

Use the status board as source of truth for current priorities and ownership cadence.

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
cd /Users/aidei/Documents/github/redoor
make ci
```

If full CI is heavy, run targeted checks for touched components and explain what was run in the PR.

## Security Reports

Do not open public issues for sensitive vulnerabilities.

Use coordinated disclosure channels described in `CODE_OF_CONDUCT.md` and `docs/security-runbook.md`.

