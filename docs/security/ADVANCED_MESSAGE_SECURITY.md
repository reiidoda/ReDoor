# Advanced Message Security Roadmap

This document defines how Redoor can be hardened against high-capability adversaries (state surveillance, intelligence services, well-funded attackers), while preserving the project goals:
- no centralized user verification authority;
- RAM-first client behavior;
- strict onion/mix usage for sensitive traffic.

## 1. Important Reality Check

No internet messaging system can guarantee absolute, universal "100% untraceable" behavior against all adversaries and all endpoints.  
The goal is to continuously reduce attack surface, increase attack cost, and fail closed under unsafe conditions.

## 2. Current Strong Points (Already Implemented)

- X3DH + Double Ratchet session model.
- Strict anonymity mode with onion/mix enforcement.
- Constant-rate send/poll loops and cover traffic controls.
- Rotating mailbox handles + decoy/batch fetch mode.
- Anonymous scoped relay credentials and spend-unit abuse governance.
- Relay mix chaff, per-hop replay defense, and route diversity policy.
- Blockchain Merkle batching + optional delegated threshold submitter.
- Deterministic anonymity simulator and CI regression gate for linkability.
- PQ handshake policy gating (`prefer/required/disabled`) with explicit handshake-mode negotiation.
- Hybrid handshake KDF transcript binding now includes mode + OPK usage + PQ usage bits (downgrade-hardening).
- Prekey PQ secret material stored as wipeable bytes to improve memory zeroization behavior.
- AS-level route diversity enforcement in mix path selection.
- Multi-relay split mailbox retrieval (configurable mirrored fetch targets).
- Startup phase randomization for fixed polling and constant-rate loops.
- Deniability-safe default where per-message signatures are optional (ratchet AEAD remains primary authenticity layer).
- Deniability signature policy decision record with enforce-only opt-in mode:
  - `docs/security/DENIABILITY_SIGNATURE_DECISION.md`
- Lockdown compatibility profile (`standard`/`strict`) with strict fail-closed checks and telemetry in iOS settings.

## 3. Highest-Value Security Improvements (Next)

## 3.1 Cryptographic and Protocol Hardening

1. Hybrid post-quantum session bootstrap:
- Keep X25519 path and add PQ KEM hybrid (e.g., ML-KEM/Kyber class) in authenticated handshake.
- Derive root secrets from combined classical + PQ inputs.
- Status (2026-03-12): mainline profile finalized with explicit policy controls across runtime/FFI/iOS:
  - `docs/security/PQ_HANDSHAKE_MIGRATION_NOTES.md`

2. Post-compromise recovery strengthening:
- Move toward triple-ratchet-style evolution (classical ratchet + PQ ratchet component).
- Add explicit key-update cadence and forced rekey after suspicious events.
- Status (2026-03-13): production baseline for versioned forced-rekey policy merged under `#198`:
  - `docs/security/PQ_RATCHET_EVOLUTION_AND_FORCED_REKEY.md`
  - `docs/security/PQ_RATCHET_EVOLUTION_PROTOTYPE.md`
  - `docs/security/pq-ratchet-evolution-report.v1.json`

3. Deniability review:
- Re-evaluate per-message long-term signatures in content payload.
- Prefer deniable authenticated channels over globally verifiable transcript signatures.
- Status (2026-03-12): decision accepted, deniable default retained, enforce mode opt-in only.

## 3.2 Metadata Resistance and Network Privacy

1. Path diversity expansion:
- Enforce AS-level / operator / jurisdiction anti-correlation constraints.
- Add route scoring that penalizes repeated infrastructure overlap.
- Status (2026-03-13): v2 anti-correlation scoring implemented:
  - `docs/security/ROUTE_ANTI_CORRELATION_SCORING_V2.md`

2. PIR-style mailbox retrieval research track:
- Evaluate private-information-retrieval or proxy retrieval variants for reducing receiver-interest leakage.
- Status (2026-03-12): feasibility spike completed with benchmark + recommendation:
  - `docs/security/PIR_PROXY_MAILBOX_RETRIEVAL_SPIKE.md`
  - `docs/security/pir-proxy-feasibility-report.v1.json`
  - current decision: no mandatory rollout yet; keep as opt-in research profile.

3. Traffic-shape hardening:
- Introduce bounded randomized schedule windows that preserve constant-rate envelopes but reduce predictable phase alignment.
- Status (2026-03-12): implemented per-loop seeded bounded jitter streams:
  - `docs/security/SCHEDULE_JITTER_HARDENING.md`

4. Multi-relay receipt blending:
- Split retrieval across independently operated relays and combine client-side.
- Status (2026-03-12): quorum blend retrieval controls documented/implemented:
  - `docs/security/MULTI_RELAY_QUORUM_BLEND_RETRIEVAL.md`

Assessment reference:
- `docs/security/TRAFFIC_CORRELATION_RED_TEAM_ASSESSMENT.md`

## 3.3 Client and Endpoint Hardening

0. Endpoint zero-click isolation boundary:
- Treat all untrusted ingest parsing as hostile and isolate it in a dedicated low-privilege process boundary.
- Status (2026-03-13): boundary implementation + policy gates merged under `#196`:
  - `docs/security/ENDPOINT_ZERO_CLICK_ISOLATION_ARCHITECTURE.md`
  - `docs/security/UNTRUSTED_PARSER_IPC_CONTRACT.md`
  - `docs/security/ZERO_CLICK_INGESTION_THREAT_MODEL.md`
  - `scripts/check-untrusted-parser-boundary.sh`

0.1 Parser attack-surface reduction and inventory:
- Keep parser classes explicit and allowlisted (`envelope_json`, `inner_payload_json`, `initial_message_json`).
- Enforce default-off behavior for media/attachment/preview parser surfaces.
- Status (2026-03-13): parser inventory + policy gate + structural pre-parse limits merged under `#197`:
  - `docs/security/PARSER_INVENTORY_MATRIX.md`
  - `scripts/check-parser-surface-policy.sh`

1. Strong secure-enclave usage on iOS:
- Store long-lived identity secrets in hardware-backed key slots when compatible with threat model.

2. Memory hygiene hardening:
- Expand zeroization audits and crash-safe wipe tests.
- Add anti-snapshot/forensic checks where platform permits.

3. Build integrity:
- Reproducible builds and signed release provenance (SLSA-style attestations).

## 3.4 Operational Security

1. Mandatory security response drills:
- Quarterly key compromise + emergency override drill.
- Status (2026-03-13):
  - `docs/security/drills/QUARTERLY_DRILL_PROGRAM.md`
  - `docs/security/drills/QUARTERLY_KICKOFF_AUTOMATION.md`
  - `docs/security/drills/ISOLATED_ROLLBACK_REHEARSAL_ENVIRONMENT.md`
  - `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`
  - `docs/security/drills/FIRST_DRILL_RETROSPECTIVE_TEMPLATE.md`
  - follow-up actions: none currently open

2. Independent audits:
- External cryptographic review and red-team traffic-correlation assessment.
- Status (2026-03-12): external cryptography audit engagement pack published:
  - `docs/security/audit/README.md`
  - `docs/security/audit/EXTERNAL_REVIEWER_CHECKLIST.md`
  - `.github/ISSUE_TEMPLATE/crypto-remediation.yml`

3. Runtime attestation (optional future):
- Evaluate remote attestation for service binaries/config integrity in production.

## 4. OpenPGP / PGP Decision

Short answer: **do not use OpenPGP as the primary real-time message encryption protocol** for Redoor.

Why:
- OpenPGP is not optimized for modern asynchronous ratcheting chat flows.
- It does not naturally provide the same post-compromise recovery model as a ratchet protocol.
- Operational key management/rotation UX is heavy and failure-prone for chat at scale.

Where OpenPGP can still help:
- signed release artifacts and update manifests;
- optional out-of-band key export/import bundles;
- operator-to-operator administrative communications (non-chat plane).

Recommended direction for Redoor message security:
- continue with ratchet-based chat cryptography and add hybrid PQ evolution rather than replacing message encryption with OpenPGP.

## 5. Priority Plan

Execution milestone mapping (2026-03-17):
- `M26 - Security Hardening Program v2`
- `#196` Endpoint zero-click isolation boundary
- `#197` Parser attack-surface reduction and inventory
- `#198` Production PQ ratchet evolution and forced rekey
- `#199` Metadata-correlation resistance v3
- `#200` Anonymous anti-DoS and abuse economics
- `#201` Supply-chain integrity and provenance
- `#202` Formal state-machine and invariant verification
- `#203` External assurance program
- `#204` PIR/private retrieval deployability track

Completed in M26:
- `#196` Endpoint zero-click isolation boundary
- `#197` Parser attack-surface reduction and inventory
- `#198` Production PQ ratchet evolution and forced rekey
- `#199` Metadata-correlation resistance v3
- `#200` Anonymous anti-DoS and abuse economics
- `#201` Supply-chain integrity and provenance
- `#202` Formal state-machine and invariant verification
- `#203` External assurance program
- `#204` PIR/private retrieval deployability track

Next execution board:
- `M27 - Open Source Readiness & Unfinished Work` (`#212`..`#218`)

### P0 (Immediate)
- lock in anonymity regression thresholds and keep artifact review mandatory in CI;
- add documented incident override expiry policy (already in runbook);
- complete deniability review for signed payload fields.

### P1 (Near-term)
- implement route scoring for AS/operator/jurisdiction diversity beyond minimum-set constraints;
- add red-team scenario fixtures to anonymity simulator.
- formalize multi-relay blending strategy (parallel/quorum retrieval trade-offs).

### P2 (Mid-term)
- prototype PIR/proxy mailbox retrieval and benchmark trade-offs;
- add secure-enclave-backed identity key mode;
- add reproducible build attestations.

### P3 (Long-term)
- full post-quantum ratchet evolution;
- optional production attestation pipeline;
- external formal protocol review.
