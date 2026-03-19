# M1 Implementation Decomposition

Date: 2026-03-17
Parent issue: #5

## 1. Goal

Break Enterprise Milestone M1 from candidate-only scope into execution-ready tasks contributors can pick directly from tracker.

Milestone M1 scope:
- API contracts and strict validation
- mTLS service identity
- KMS/bootstrap key management and rotation
- security event taxonomy and structured audit logging

## 2. Task Matrix (Tracker-First)

| Order | Task | Tracker Issue | Depends On | Acceptance Summary |
|---|---|---|---|---|
| 1 | OpenAPI contracts + strict request validation | #28 | none | service surfaces mapped, schema strategy documented, version policy defined |
| 2 | mTLS service-plane identity + cert rotation | #29 | #28 | identity model documented, rotation/rollback flow documented, verification checklist exists |
| 3 | KMS/bootstrap key management + staged rotation | #30 | #29 | key ownership map documented, staged rotation checkpoints defined, rollback references linked |
| 4 | Security event taxonomy + structured audit logs | #31 | #28, #30 | taxonomy coverage defined, structured fields + exclusions documented, rollout validation checklist defined |

## 3. Dependency Graph

```text
#28 (OpenAPI/contracts)
  -> #29 (mTLS identity + cert rotation)
      -> #30 (KMS/bootstrap + staged rotation)
#28 + #30
  -> #31 (security event taxonomy + structured audit logs)
```

## 4. Contributor Pick-Up Rules

A task is considered pick-up-ready when its tracker issue includes:
- explicit problem statement;
- bounded scope bullets;
- dependency list with blocking issue IDs;
- measurable acceptance criteria;
- target docs/code areas.

## 5. Milestone Exit Criteria (M1)

M1 is considered execution-ready (not complete) when:
- all decomposition tasks exist in tracker (`#28`..`#31`);
- each task has owner assignment and dependency wiring;
- roadmap docs and status board link directly to task issues.

M1 is considered complete when:
- `#28`, `#29`, `#30`, and `#31` are closed with acceptance evidence;
- changelog and runbook references are updated for all resulting behavior changes.

## 6. Current Status

- Decomposition complete: yes
- Tracker tasks created: yes (`#28`, `#29`, `#30`, `#31`)
- Remaining work: implementation and closure of decomposition tasks

