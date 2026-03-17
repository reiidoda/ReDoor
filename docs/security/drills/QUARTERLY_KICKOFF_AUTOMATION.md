# Quarterly Drill Kickoff Automation

Date: 2026-03-13  
Issue: #188  
Workflow: `.github/workflows/security-drill-kickoff.yml`

## Objective

Automatically create one quarterly kickoff issue with:
- a fixed readiness checklist;
- explicit owner assignments;
- explicit due dates;
- links to current drill governance docs.

## Trigger Model

- Scheduled trigger: first day of each month at `09:15 UTC`.
- Guardrail: scheduled runs create issues only in quarter-start months (`Jan`, `Apr`, `Jul`, `Oct`).
- Manual trigger: `workflow_dispatch` can run on-demand and creates the current quarter kickoff item if missing.

## Owner Assignment

Owner list source:
- repository variable `SECURITY_DRILL_OWNERS` (comma-separated GitHub usernames, optional `@` prefix).

Fallback:
- if `SECURITY_DRILL_OWNERS` is not configured, repository owner is assigned.

Role mapping:
- first owner: incident commander;
- second owner (or fallback first): security lead;
- third owner (or fallback first): operations lead;
- fourth owner (or fallback first): scribe.

## Due-Date Policy

Relative due dates are generated from kickoff creation date (UTC):
- checklist + role assignment: `+3` days;
- scenario freeze + evidence snapshot: `+10` days;
- live drill execution: `+35` days;
- retrospective closure: `+42` days.

## Idempotency

- Issue title key: `Quarterly Security Drill Kickoff <year> Q<quarter>`.
- If an open issue with the same title already exists, workflow exits without creating duplicates.

## Linked Artifacts

Every generated issue links to:
- `docs/security/drills/QUARTERLY_DRILL_PROGRAM.md`
- `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`
- `docs/security/drills/FIRST_DRILL_RETROSPECTIVE_TEMPLATE.md`
