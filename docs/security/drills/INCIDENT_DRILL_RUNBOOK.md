# Incident Drill Runbook

Date: 2026-03-12  
Program: Quarterly Security Incident Drill Program (`#166`)

## 1. Scope

This runbook covers simulation and readiness checks for:
- key material compromise response;
- relay compromise containment;
- emergency rollback and credential rotation.

## 2. Pre-Drill Checklist

1. Assign roles:
   - incident commander,
   - operations lead,
   - security lead,
   - scribe.
2. Freeze drill scope and success criteria.
3. Snapshot current runbooks/config references.
4. Confirm communication channels and fallback contacts.

## 3. Scenario Playbooks

## 3.1 Key Compromise Drill

Target outcomes:
- identify blast radius and affected identities;
- execute forced session rekey path;
- verify stale credentials are revoked.

Evidence to collect:
- rekey command timeline,
- impacted component list,
- post-rotation validation checks.

## 3.2 Relay Compromise Drill

Target outcomes:
- isolate suspect relay quickly;
- reroute traffic through safe topology;
- validate no unsafe fallback path activates.

Evidence to collect:
- isolation timestamp,
- route re-selection logs,
- post-isolation health checks.

## 3.3 Emergency Rollback Drill

Target outcomes:
- execute rollback under controlled window;
- rotate certs/HMAC secrets after rollback;
- confirm clients recover without unsafe behavior.

Evidence to collect:
- rollback start/end timestamps,
- credential rotation proof,
- post-rollback connectivity/security checks.

## 3.4 Isolated Rehearsal Checklist (Rollback + Rotation)

Reference environment and harness:
- `docs/security/drills/ISOLATED_ROLLBACK_REHEARSAL_ENVIRONMENT.md`
- `scripts/drill-rollback-rehearsal.sh`
- `scripts/ci-drill-rehearsal.sh`

Evidence checklist (must be attached to drill issue):
- [ ] `baseline.sha256`
- [ ] `rotated.sha256`
- [ ] `rollback.sha256`
- [ ] `post-rollback.sha256`
- [ ] `rollback-rehearsal-summary.md`
- [ ] `rollback-rehearsal-summary.json`

Verification gates:
1. Rotated manifest differs from baseline.
2. Rollback manifest matches baseline exactly.
3. Post-rollback manifest differs from baseline.

## 4. Success Metrics

- Time to containment (TTC) against scenario SLA.
- Time to validated recovery (TTR).
- Number of manual error-prone steps observed.
- Number of unresolved action items.

## 5. Post-Drill Requirements

1. Fill retrospective template:
   - `docs/security/drills/FIRST_DRILL_RETROSPECTIVE_TEMPLATE.md`
2. Create follow-up issues for unresolved actions.
3. Update relevant docs:
   - runbook,
   - threat model,
   - security changelog.
