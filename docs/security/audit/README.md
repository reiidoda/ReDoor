# External Cryptography Audit Engagement Pack

Date: 2026-03-12  
Issue: #164  
Milestone: M25 - Independent Security Assurance

## Purpose

This package gives external cryptographers and security reviewers a stable entry point
to evaluate Redoor protocol/security claims and report findings with a consistent workflow.

## Package Contents

- `CRYPTOGRAPHIC_PROTOCOL_SNAPSHOT.md`:
  - current protocol design, assumptions, and out-of-scope boundaries.
- `SECURITY_CLAIMS_TO_TESTS_MATRIX.md`:
  - mapping of high-level security claims to concrete tests/scripts/artifacts.
- `EXTERNAL_REVIEWER_CHECKLIST.md`:
  - ready-to-run reviewer checklist for protocol, implementation, and ops controls.
- `REMEDIATION_WORKFLOW.md`:
  - severity model, SLAs, and closure criteria for audit findings.

## Reviewer Starting Point

1. Read `docs/protocol.md` and `docs/threat_model.md`.
2. Review this pack in order:
   - snapshot,
   - claims matrix,
   - checklist,
   - remediation workflow.
3. Re-run evidence commands from the matrix before reporting findings.

## Integrity Notes

- This pack documents current behavior; it is not a formal proof.
- Any critical/high finding should block security milestone closure until remediated
  or explicitly accepted by documented risk exception.
