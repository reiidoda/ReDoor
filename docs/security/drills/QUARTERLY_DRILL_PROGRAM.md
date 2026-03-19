# Quarterly Security Incident Drill Program

Date: 2026-03-12  
Issue: #166  
Milestone: M25 - Independent Security Assurance

## Objective

Institutionalize recurring operational drills for:
- key compromise response;
- relay compromise containment;
- emergency rollback and credential rotation.

## Quarterly Calendar (Rolling)

| Quarter | Scenario Focus | Target Window | Primary Owner | SLA Target |
| --- | --- | --- | --- | --- |
| Q1 | Key compromise + forced rekey | Week 6-8 | Security lead | containment plan in <= 30 min |
| Q2 | Relay compromise + isolation | Week 6-8 | Infra lead | suspect relay isolated in <= 20 min |
| Q3 | Emergency rollback + cert/HMAC rotation | Week 6-8 | Release lead | rollback and re-issue complete in <= 45 min |
| Q4 | Combined multi-incident tabletop | Week 6-8 | Incident commander | comms + mitigation timeline validated end-to-end |

Execution cadence:
- one live drill per quarter;
- one tabletop review for unresolved actions between drills.

## Program Artifacts

- Drill runbook:
  - `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`
- Retrospective template:
  - `docs/security/drills/FIRST_DRILL_RETROSPECTIVE_TEMPLATE.md`
- Kickoff automation:
  - `docs/security/drills/QUARTERLY_KICKOFF_AUTOMATION.md`
  - `.github/workflows/security-drill-kickoff.yml`

## Governance Rules

1. Every drill must produce:
   - timeline,
   - decision log,
   - mitigation actions with owners/dates.
2. Critical process gaps become follow-up GitHub issues before drill closure.
3. No quarter can be skipped without documented risk acceptance.

## Kickoff Automation (Implemented)

Issue `#188` is implemented with scheduled GitHub automation that:
- creates one kickoff issue per quarter (`Q1/Q2/Q3/Q4`) with an idempotent title key;
- assigns owners from repository variable `SECURITY_DRILL_OWNERS` (or repository-owner fallback);
- sets explicit due dates and role ownership directly in checklist items;
- links the active runbook and retrospective template in every kickoff item.

## Isolated Rollback Rehearsal Environment (Implemented)

Issue `#189` is implemented with reproducible drill harness and CI validation:
- isolation harness script:
  - `scripts/drill-rollback-rehearsal.sh`
- CI validation gate:
  - `scripts/ci-drill-rehearsal.sh`
  - `.github/workflows/security-gates.yml` (`Rollback Drill Rehearsal` job)
- environment specification and artifact contract:
  - `docs/security/drills/ISOLATED_ROLLBACK_REHEARSAL_ENVIRONMENT.md`
- runbook-integrated evidence checklist:
  - `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`

## Unresolved Actions (Tracked)

- No open follow-up actions.
