# Contributing to Redoor

Thanks for helping improve Redoor.

## Start Here

- Read `README.md` for repository scope and local setup.
- Read `CODE_OF_CONDUCT.md`.
- Read `docs/ROADMAP.md` for current priorities.
- Read `docs/OPEN_SOURCE_STATUS.md` for the live status board.
- Read `docs/security/STANDARDS_PROFILE.md` if your change touches security-sensitive surfaces.

## How To Pick Work

- Browse the issue tracker: `https://github.com/reiidoda/ReDoor/issues`
- Prefer issues labeled `good first issue` for onboarding.
- Use `help wanted` for maintainers' current external contribution needs.
- Review `documentation` and `enhancement` labels for docs/process vs implementation work.

If you want to work on something broad or cross-component, open or comment on an issue first so scope and acceptance criteria are explicit.

## Contribution Flow

1. Pick or open an issue.
2. Confirm acceptance criteria in the issue body.
3. Branch from `main`.
4. Implement with tests and docs updates where applicable.
5. Run relevant local validation.
6. Open a PR and link the issue (`Fixes #<number>` when appropriate).

## Pull Request Expectations

- Keep changes focused and reviewable.
- Include tests for new behavior when feasible.
- Update docs when behavior, policy, or contributor workflow changes.
- Do not weaken fail-closed security paths.
- Use `.github/PULL_REQUEST_TEMPLATE.md`.

Security-relevant PRs must also:
- update `docs/security/control-matrix.csv`, or explain why no mapped control changed,
- document rollback or containment considerations,
- call out telemetry/observability impact,
- update threat model, runbook, release, or standards docs when affected.

The `PR Policy` workflow enforces the security checklist when a PR is marked security-relevant.

## Local Validation

Run the relevant gates before opening a PR:

```bash
cd <repo-root>
make ci
./scripts/ci-bugscan.sh --include-swift
```

If full CI is heavier than needed, run targeted checks for the touched components and list exactly what you ran in the PR.

## Security Reports

Do not open public issues for sensitive vulnerabilities.

Use the private reporting path documented in `SECURITY.md`. For incident handling and response context, see `docs/security-runbook.md`.
