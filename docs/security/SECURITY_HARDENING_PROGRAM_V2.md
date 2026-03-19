# Security Hardening Program v2

Date: 2026-03-13  
Milestone: `M26 - Security Hardening Program v2`

## Program Goal

Move Redoor from an advanced secure prototype to a production-grade platform resilient against:
- endpoint/zero-click compromise;
- parser exploitation;
- metadata correlation;
- protocol-state downgrade or recovery failures;
- supply-chain tampering;
- abuse/flood pressure without identity.

## Execution Order

1. `#196` Endpoint zero-click isolation boundary
2. `#197` Parser attack-surface reduction and inventory
3. `#198` Production PQ ratchet evolution + forced rekey
4. `#199` Metadata-correlation resistance v3
5. `#200` Anonymous anti-DoS and abuse economics
6. `#201` Supply-chain integrity (repro + attestations + provenance)
7. `#202` Formal verification depth
8. `#203` External assurance pipeline
9. `#204` PIR/private retrieval deployability track

## Non-Negotiable Security Rules

- No temporary bypasses around security boundaries.
- No silent fallback to weaker privacy/security behavior.
- No merge without tests, telemetry, and rollback path.
- Every security boundary must define:
  - invariants,
  - adversary model,
  - failure modes,
  - observability.

## Mandatory Delivery Format (Per Task)

Each issue/PR in this milestone must include:

1. Architecture/design changes.
2. Concrete code changes by module/file.
3. Migration/rollout considerations.
4. Tests added.
5. Telemetry/observability added.
6. Security risks if partially implemented.
7. Recommended PR breakdown.

## Release Gating

A workstream is not complete until all are true:
- invariants are encoded in tests/policy checks;
- rollback/kill-switch behavior is documented and tested;
- operations runbook is updated;
- diagnostics and alerting signals are live;
- threat-model delta is documented.

## Tracking

- Milestone board: `M26 - Security Hardening Program v2`
- Issues: `#196`..`#204`
- Completed workstreams:
  - `#196` Endpoint zero-click isolation boundary
  - `#197` Parser attack-surface reduction and inventory
  - `#198` Production PQ ratchet evolution and forced rekey
  - `#199` Metadata-correlation resistance v3
  - `#200` Anonymous anti-DoS and abuse economics
  - `#201` Supply-chain integrity (repro + attestations + provenance)
  - `#202` Formal verification depth
  - `#203` External assurance pipeline
  - `#204` PIR/private retrieval deployability track
- Contributor-facing execution tracking:
  - `docs/ROADMAP.md`
  - `docs/OPEN_SOURCE_STATUS.md`
- Program updates must also update:
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/CHANGELOG.md`
