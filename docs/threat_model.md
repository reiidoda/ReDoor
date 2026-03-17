# Redoor Threat Model

## 1. Scope

In scope:
- Rust client runtime and FFI bridge
- iOS application behavior and lifecycle
- relay transport and mailbox handling
- blockchain evidence path
- directory key discovery path

Out of scope:
- compromised kernel/baseband/hardware trust root
- physical coercion against unlocked user
- side-channel attacks outside process-level mitigations

## 2. Primary Security Goals

1. Protect message confidentiality from infrastructure operators.
2. Reduce social-graph leakage at the relay boundary.
3. Keep client-side sensitive state in volatile memory.
4. Detect tampering/reordering through hash evidence.
5. Enforce strict transport hardening (TLS + pinning + auth).

## 3. Adversary Classes

### A. Local Device Adversary
Capabilities:
- device access after theft/seizure
- app state scraping attempts

Mitigations:
- RAM-only storage policy in Swift code
- wipe on background/resign/terminate
- duress mode + explicit runtime wipe APIs

### B. Network Adversary
Capabilities:
- passive capture of transport metadata
- active tampering/replay attempts

Mitigations:
- TLS mandatory for relay in production posture
- HMAC request auth and anti-replay on relay paths
- optional cover traffic and fixed polling
- onion/mix path with strict anonymity mode
- startup phase randomization to reduce synchronized polling/send cadence
- iOS lockdown compatibility profile with strict fail-closed checks for high-risk posture

### C. Relay Adversary
Capabilities:
- full relay host compromise

Mitigations:
- relay only sees opaque encrypted blobs
- receiver identifiers rotated before relay submission (epoch mailbox handles)
- receiver can split pending fetches across mirrored relays
- fetch-once behavior for normal blobs limits retention

Residual risk:
- timing and traffic correlation remain possible against powerful observers

### D. Blockchain/Directory Adversary
Capabilities:
- inspect or manipulate API-facing metadata

Mitigations:
- blockchain stores hash commitments, not plaintext
- directory resolve responses are signed
- per-IP rate limits and auth controls on both services

Residual risk:
- commitment metadata can still reveal coarse communication patterns

## 4. Key Invariants Enforced in Code/CI

- No persistent Swift APIs (`UserDefaults`, CoreData, direct file writes) in app paths.
- Remote relay use requires security material (HMAC + TLS pin signals) at app config boundary.
- Strict anonymity can block non-onion sends in runtime.
- Chat delivery does not require per-message long-term signatures in default deniable mode.
- Hybrid handshake policy (`prefer/required/disabled`) is explicit and downgrade-sensitive.
- Memory budget regressions must pass before merge.
- Linkability regression baseline gate must pass (or explicit emergency override with incident record).
- Realtime soak/reconnect reliability thresholds are continuously tested.

## 5. Known Accepted Risks

- Global passive traffic analysis is not fully solved.
- If OS/hardware root is compromised, app-level controls are bypassable.
- Hash-only blockchain evidence still leaks bounded metadata.

## 6. Hardening Direction

- State-level resistance requires continuous metadata-hardening upgrades (not a single protocol switch).
- OpenPGP is not selected as the primary realtime message protocol for Redoor; ratchet-based protocols with hybrid PQ evolution are preferred.
- handshake negotiation carries explicit classic/hybrid mode and can enforce required/disabled PQ policy fail-closed.
- deniability signature decision record:
  - `docs/security/DENIABILITY_SIGNATURE_DECISION.md`
- Advanced hardening backlog (PQ, metadata, endpoint and operational controls):
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`

## 7. Traffic-Analysis Simulator Baseline

To keep anonymity claims measurable, the client includes a deterministic traffic-analysis simulator
(`traffic_linkability.v1`) with seeded fixtures:
- `idle`
- `burst`
- `mixed_real_chaff`
- `relay_churn`

Assumptions used by the simulator:
- a global passive observer sees sender egress and receiver ingress timing
- observer correlation uses a latency-window, one-to-one assignment heuristic
- chaff and real packets are transport-indistinguishable

Limits of the simulator:
- no endpoint compromise or active packet injection model
- synthetic topology/traffic only; not internet-scale routing behavior
- baseline heuristic only; advanced ML deanonymization is out of scope

Regression guard:
- the simulator report is deterministic for a fixed seed and includes versioned/comparable IDs
- CI/unit tests assert scenario coverage and expected relative behavior (mixed/churn vs baseline)

## 8. Change Control Questions

Every security-relevant PR should answer:
1. Does this increase metadata exposure at relay/blockchain/directory boundaries?
2. Does this introduce any persistence path on client app/device?
3. Does this weaken wipe/duress/background security behavior?
4. Does this bypass or dilute strict anonymity policy paths?

## 9. PIR/Proxy Retrieval Delta (2026-03-12)

Reference artifacts:
- `docs/security/PIR_PROXY_MAILBOX_RETRIEVAL_SPIKE.md`
- `docs/security/PIR_PROXY_DEPLOYABILITY_GRADUATION_PLAN.md`
- `docs/security/pir-proxy-feasibility-report.v1.json`

Delta summary:
- Baseline split retrieval remains default because it avoids introducing a new trust concentration layer.
- Proxy-fanout retrieval improves relay-side endpoint unlinkability but creates a high-value proxy compromise target.
- Two-server PIR-style retrieval provides stronger receiver-interest privacy under non-collusion assumptions, but current performance/cost envelope is unsuitable for always-on mobile polling.

Current policy:
- No mandatory production migration to PIR/proxy retrieval.
- Continue research profile only, behind explicit operator control and external audit prerequisites.
- Stage advancement is governed by tracked deployability tasks: `#23`, `#24`, `#25`, `#26`.

## 10. PQ Ratchet Evolution + Forced Rekey Delta (2026-03-13)

Reference artifacts:
- `docs/security/PQ_RATCHET_EVOLUTION_AND_FORCED_REKEY.md`
- `docs/security/PQ_RATCHET_EVOLUTION_PROTOTYPE.md`
- `docs/security/pq-ratchet-evolution-report.v1.json`

Delta summary:
- Production baseline now enforces version-aware forced rekey policy in runtime lifecycle.
- Handshake transcript includes explicit protocol-version binding and compatibility gates.
- Forced rekey triggers include protocol transition/minimum rejection, time budget, message budget, lifecycle events, and compromise indicators.
- Prototype analysis still informs PQ mix interval direction (`pq_interval` schedule).
- Compromise persistence window is bounded by next PQ contribution event rather than handshake lifetime alone.
- Simulated tradeoff:
  - lower interval => faster post-compromise divergence;
  - higher interval => lower cost but slower recovery.

Current policy:
- Keep protocol-version and forced-rekey enforcement active by default.
- Maintain staged tuning for PQ mix cadence (`pq_interval`) with telemetry-backed thresholds.
- Tighten minimum accepted protocol version only after interop soak and rollback rehearsal.

## 11. External Cryptography Audit Readiness Delta (2026-03-12)

Reference artifacts:
- `docs/security/audit/README.md`
- `docs/security/audit/CRYPTOGRAPHIC_PROTOCOL_SNAPSHOT.md`
- `docs/security/audit/SECURITY_CLAIMS_TO_TESTS_MATRIX.md`
- `docs/security/audit/EXTERNAL_REVIEWER_CHECKLIST.md`
- `docs/security/audit/REMEDIATION_WORKFLOW.md`
- `.github/ISSUE_TEMPLATE/crypto-remediation.yml`

Delta summary:
- independent reviewers now have a dedicated audit package with protocol snapshot and evidence matrix;
- finding remediation process is standardized with severity, SLA targets, and closure criteria;
- remediation intake is normalized via repository issue template.

Current policy:
- critical/high findings from independent reviews block security milestone completion unless explicitly risk-accepted;
- accepted risks require threat-model/changelog update and expiration date.

## 12. Traffic-Correlation Red-Team Delta (2026-03-12)

Reference:
- `docs/security/TRAFFIC_CORRELATION_RED_TEAM_ASSESSMENT.md`
- `docs/security/traffic-linkability-baseline.v1.json`

Risk statement update:
- traffic correlation remains a high residual risk, especially in low-cover (idle/burst) timing conditions;
- current controls provide regression visibility and partial mitigation but do not provide strong anonymity guarantees
  against global passive observers.

Mitigation backlog:
- `#184` bounded schedule jitter hardening (implemented 2026-03-12; see `docs/security/SCHEDULE_JITTER_HARDENING.md`);
- `#185` multi-relay quorum blend retrieval (implemented 2026-03-12; see `docs/security/MULTI_RELAY_QUORUM_BLEND_RETRIEVAL.md`);
- `#186` route anti-correlation scoring v2 (implemented 2026-03-13; see `docs/security/ROUTE_ANTI_CORRELATION_SCORING_V2.md`).

## 13. Recurring Incident Drill Program Delta (2026-03-12)

Reference:
- `docs/security/drills/QUARTERLY_DRILL_PROGRAM.md`
- `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`
- `docs/security/drills/FIRST_DRILL_RETROSPECTIVE_TEMPLATE.md`

Delta summary:
- quarterly operational drill cadence is now defined for key compromise, relay compromise, and rollback scenarios;
- measurable SLA targets and evidence capture requirements are documented.

Open action tracking:
- `#188` automate quarterly kickoff workflow (implemented 2026-03-13; see `.github/workflows/security-drill-kickoff.yml`);
- `#189` add isolated rollback rehearsal environment (implemented 2026-03-13; see `docs/security/drills/ISOLATED_ROLLBACK_REHEARSAL_ENVIRONMENT.md`).

## 14. Security Hardening Program v2 Delta (2026-03-13)

Reference:
- `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`

Delta summary:
- Security hardening work has been organized into milestone `M26` with explicit production-grade acceptance criteria.
- Workstreams `#196`..`#204` define required controls for zero-click isolation, parser minimization, PQ recovery, metadata resistance, anti-abuse, supply-chain integrity, formal verification, external assurance, and PIR deployment gating.
- Completed implementation workstreams: `#196`, `#197`, `#198`, `#199`, `#200`, `#201`, `#202`, `#203`, `#204`.
- Follow-up execution for open-source readiness is tracked under `M27` (`#212`..`#218`).
- Zero-click workstream architecture artifacts for `#196` are now published:
  - `docs/security/ENDPOINT_ZERO_CLICK_ISOLATION_ARCHITECTURE.md`
  - `docs/security/UNTRUSTED_PARSER_IPC_CONTRACT.md`
  - `docs/security/ZERO_CLICK_INGESTION_THREAT_MODEL.md`

Policy update:
- no silent fallback to weaker security behavior is allowed for new boundaries;
- every new boundary must ship with invariants, observability, tests, and rollback controls.

## 15. Parser Attack-Surface Reduction Delta (2026-03-13)

Reference artifacts:
- `docs/security/PARSER_INVENTORY_MATRIX.md`
- `scripts/check-parser-surface-policy.sh`

Delta summary:
- parser classes are now explicitly allowlisted at runtime via `REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`;
- untrusted parser entry points enforce additional structural guards (UTF-8, nesting depth, token budget, numeric token budget, compressed payload rejection);
- X3DH parser-exposed structs now require strict field schemas (`deny_unknown_fields`);
- CI blocks parser-surface expansion unless inventory + policy controls remain intact.

Policy update:
- media/attachment/preview parser paths stay default-off until a dedicated isolated parser class with fuzz coverage is merged;
- new parser classes require matrix registration, policy gate updates, and regression corpus additions before rollout.
