# External Reviewer Checklist

Date: 2026-03-12  
Use this checklist for third-party cryptography and protocol audits.

## A. Threat Model and Scope

- [ ] Confirm in-scope/out-of-scope boundaries in `docs/threat_model.md`.
- [ ] Validate adversary classes and assumptions are realistic.
- [ ] Verify no security claim exceeds the documented threat model.

## B. Handshake and Key Agreement

- [ ] Review handshake mode negotiation and downgrade resistance behavior.
- [ ] Verify transcript/KDF context binds relevant negotiation bits.
- [ ] Validate failure handling for PQ-required posture (fail-closed).

## C. Ratchet and Message Protection

- [ ] Inspect ratchet state transitions for forward secrecy consistency.
- [ ] Review AEAD usage, key separation, and nonce/state discipline.
- [ ] Validate deniability-mode behavior against non-repudiation risk.

## D. Replay, Ordering, and Relay Path

- [ ] Evaluate anti-replay windows and nonce/timestamp handling.
- [ ] Verify relay auth controls and key rotation workflow.
- [ ] Confirm strict-anonymity mode blocks unsafe direct transport paths.

## E. Metadata and Anonymity Posture

- [ ] Review traffic-linkability baseline assumptions and metric definitions.
- [ ] Evaluate route diversity constraints and anti-correlation controls.
- [ ] Validate multi-relay retrieval threat/benefit tradeoffs.

## F. Endpoint and Memory Safety Controls

- [ ] Validate RAM-only storage policy enforcement in client paths.
- [ ] Review memory-zeroization controls and regression coverage.
- [ ] Check parser isolation/lockdown guardrails for untrusted content.

## G. Operational Security Controls

- [ ] Confirm incident runbooks are actionable and current.
- [ ] Verify release integrity/provenance checks are reproducible.
- [ ] Check drill plan and ownership for unresolved security actions.

## H. Audit Output Requirements

- [ ] Findings are categorized (critical/high/medium/low/informational).
- [ ] Each finding includes:
  - affected component and threat impact,
  - reproducibility steps,
  - remediation recommendation.
- [ ] Residual-risk statement is updated for all accepted (unfixed) findings.

## I. Escalation Rules

- [ ] Critical findings block release until remediated or formally accepted by risk owner.
- [ ] High findings require remediation plan with owner and due date before milestone closure.
- [ ] Medium/low findings are tracked with explicit backlog priority and target release.
