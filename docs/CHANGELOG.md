# Documentation Changelog

This file tracks major documentation updates for the repository.

## Entry Template

Use this template for each docs update:

```md
## YYYY-MM-DD
- Scope:
  - <what was updated>
- Why:
  - <reason for the docs change>
- Files:
  - <path/to/file.md>
  - <path/to/another-file.md>
- Notes:
  - <follow-up items, if any>
```

## 2026-03-17 (M27 open-source readiness tracking and MIT licensing)
- Scope:
  - Created milestone `M27 - Open Source Readiness & Unfinished Work` and opened tracking issues `#212`..`#218` for remaining implementation/doc governance tasks.
  - Added contributor-facing status and workflow docs (`docs/OPEN_SOURCE_STATUS.md`, `CONTRIBUTING.md`).
  - Added open-source governance/support/security policy docs (`GOVERNANCE.md`, `SUPPORT.md`, `SECURITY.md`).
  - Added issue templates for bug and feature submissions.
  - Added issue template config with security advisory contact link.
  - Updated top-level and architecture/design docs with explicit open-work tracking entrypoints.
  - Switched repository license to MIT and linked license references from core docs.
  - Reconciled M26 status wording in security roadmap/program/threat-model docs to match closed issues.
- Why:
  - Prepare the repository for clearer public open-source collaboration with transparent work tracking and aligned licensing/documentation.
- Files:
  - `LICENSE`
  - `README.md`
  - `CONTRIBUTING.md`
  - `.github/ISSUE_TEMPLATE/bug_report.yml`
  - `.github/ISSUE_TEMPLATE/feature_request.yml`
  - `.github/ISSUE_TEMPLATE/config.yml`
  - `SECURITY.md`
  - `SUPPORT.md`
  - `GOVERNANCE.md`
  - `docs/OPEN_SOURCE_STATUS.md`
  - `docs/README.md`
  - `docs/architecture.md`
  - `SYSTEM_DESIGN.md`
  - `OO_DESIGN.md`
  - `CODE_OF_CONDUCT.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`
  - `docs/threat_model.md`
  - `docs/CHANGELOG.md`

<<<<<<< feat/14-fuzz-matrix-nightly-tracking
## 2026-03-17 (Issue #14 fuzz matrix expansion and nightly coverage tracking)
- Scope:
  - Added parser-worker IPC Rust fuzz target (`parser_worker_ipc`) and declared all fuzz bins for `cargo-fuzz` execution.
  - Added Go fuzz harnesses for relay untrusted boundaries (`validateFixedTransportCell`, auth header parsing, mix packet processing).
  - Added nightly fuzz workflow with extended runtimes, artifact retention, and corpus trend snapshots.
  - Added deterministic crash-promotion utility for fuzz artifacts -> regression corpus fixtures.
  - Expanded parser-fuzz gate/policy/docs to enforce new harness inventory and artifact outputs.
- Why:
  - Close issue #14 by broadening untrusted-boundary fuzz coverage, adding continuous nightly depth, and automating crash-to-regression promotion.
- Files:
  - `.github/workflows/fuzz-nightly.yml`
  - `client/fuzz/Cargo.toml`
  - `client/fuzz/fuzz_targets/parser_worker_ipc.rs`
  - `client/src/engine.rs`
  - `client/tests/parser_fuzz_regression.rs`
  - `relay-node/src/network/fuzz_untrusted_boundaries_test.go`
  - `relay-node/src/onion/fuzz_mix_layer_test.go`
  - `scripts/ci-parser-fuzz.sh`
  - `scripts/check-parser-surface-policy.sh`
  - `scripts/promote-fuzz-crash-fixtures.sh`
  - `scripts/generate-fuzz-corpus-trends.sh`
  - `docs/security/PARSER_INVENTORY_MATRIX.md`
  - `docs/ci.md`
=======
## 2026-03-17 (Issue #16 anomaly detection and response playbooks)
- Scope:
  - Added relay anomaly detector pipeline for replay spikes, malformed payload bursts, and credential spray failures.
  - Added directory anomaly detector pipeline for replay/non-monotonic updates, malformed request bursts, and credential/token spray failures.
  - Exposed read-only anomaly snapshots through relay and directory `GET /metrics/anomaly` endpoints.
  - Added detector-to-runbook action mapping IDs and simulation guidance for detection + response validation.
  - Added relay and directory anomaly simulation tests to validate signal generation and action-map exposure.
- Why:
  - Close issue #16 by providing actionable, low-noise detector signals that are explicitly tied to incident response actions.
- Files:
  - `relay-node/src/network/anomaly.go`
  - `relay-node/src/network/anomaly_test.go`
  - `relay-node/src/network/listener.go`
  - `relay-node/src/main.go`
  - `directory-dht/src/main.rs`
  - `docs/security-runbook.md`
  - `docs/security-logging.md`
  - `docs/protocol.md`
>>>>>>> main
  - `docs/CHANGELOG.md`

## 2026-03-13 (M26 production PQ ratchet evolution and forced rekey)
- Scope:
  - Added protocol-version compatibility enforcement in X3DH handshake (`protocol_version` tagging + responder min/current gates).
  - Added forced-rekey state machine with policy triggers (protocol transition/minimum, time budget, message budget, lifecycle and compromise indicators).
  - Added diagnostics telemetry for rekey health counters and policy visibility.
  - Exposed manual compromise-indicator rekey trigger through FFI and iOS bindings.
  - Added protocol-version interop matrix and rekey/lifecycle/FFI regression tests.
  - Added production design/rollout/rollback document for PQ ratchet evolution + forced rekey.
- Why:
  - Close issue #198 by moving from PQ prototype posture to an enforceable production baseline with explicit versioning, fail-closed rekey behavior, and operational observability.
- Files:
  - `client/src/config.rs`
  - `client/src/crypto/x3dh.rs`
  - `client/src/engine.rs`
  - `client/src/service.rs`
  - `client/src/diagnostics.rs`
  - `client/src/ffi.rs`
  - `RedoorApp/RedoorApp/Core/redoor.h`
  - `RedoorApp/RedoorApp/Core/RedoorFFI.swift`
  - `docs/security/PQ_RATCHET_EVOLUTION_AND_FORCED_REKEY.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `README.md`
  - `docs/CHANGELOG.md`

## 2026-03-13 (M26 parser attack-surface reduction and inventory)
- Scope:
  - Added parser inventory matrix with format ownership, memory-safety posture, isolation boundary, and fuzz coverage mapping.
  - Added runtime parser class allowlist policy (`REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`) with fail-closed denials.
  - Added structural pre-parse validation guards (UTF-8, depth/token budgets, numeric budget, compressed payload rejection) for untrusted JSON surfaces.
  - Tightened X3DH parser schema handling with `deny_unknown_fields` on parser-exposed structs.
  - Added CI parser-surface policy gate to block accidental parser expansion and missing corpus/inventory controls.
- Why:
  - Close issue #197 by making parser minimization and default-off policy enforceable in runtime + CI, not only documented.
- Files:
  - `client/src/engine.rs`
  - `client/src/crypto/x3dh.rs`
  - `client/src/diagnostics.rs`
  - `scripts/check-parser-surface-policy.sh`
  - `scripts/ci-rust-quality.sh`
  - `docs/security/PARSER_INVENTORY_MATRIX.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/README.md`
  - `docs/threat_model.md`
  - `docs/CHANGELOG.md`

## 2026-03-13 (M26 endpoint zero-click isolation runtime enforcement)
- Scope:
  - Implemented untrusted parser worker boundary in client runtime and wired dedicated worker command dispatch.
  - Added bounded worker lifecycle controls: frame limits, timeout kill/restart, memory/CPU limits, fail-closed behavior.
  - Added parser boundary telemetry in diagnostics output (launch/restart/timeout/denial/error counters).
  - Added CI policy script to block direct untrusted parsing inside `poll_messages()`.
  - Added regression tests for fail-closed disabled mode and worker command detection.
  - Aligned IPC contract docs to implemented request/response schema.
- Why:
  - Move issue #196 from architecture-only state to enforceable runtime security boundary with observability and policy gating.
- Files:
  - `client/src/engine.rs`
  - `client/src/main.rs`
  - `client/src/diagnostics.rs`
  - `scripts/check-untrusted-parser-boundary.sh`
  - `scripts/ci-rust-quality.sh`
  - `docs/security/UNTRUSTED_PARSER_IPC_CONTRACT.md`
  - `docs/security/ENDPOINT_ZERO_CLICK_ISOLATION_ARCHITECTURE.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/CHANGELOG.md`

## 2026-03-12 (M24 PQ ratchet evolution prototype)
- Scope:
  - Added PQ ratchet evolution prototype report and deterministic JSON artifact.
  - Documented compromise-recovery simulation model, state/overhead impact, and staged recommendation.
  - Added threat-model delta section for post-compromise recovery schedule behavior.
- Why:
  - Close issue #163 with concrete prototype evidence and a production-path recommendation.
- Files:
  - `client/src/ratchet/pq_evolution.rs`
  - `client/src/bin/pq_ratchet_evolution_prototype.rs`
  - `docs/security/PQ_RATCHET_EVOLUTION_PROTOTYPE.md`
  - `docs/security/pq-ratchet-evolution-report.v1.json`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `scripts/generate-pq-ratchet-evolution-report.sh`
  - `Makefile`
  - `docs/CHANGELOG.md`
- Notes:
  - Current recommendation is staged rollout experiments at `pq_interval=16`; not yet default-on in production.

## 2026-03-13 (M25 quarterly drill kickoff automation)
- Scope:
  - Added scheduled GitHub automation to create one quarterly drill kickoff issue with checklist, owners, and due dates.
  - Added deterministic role-assignment model from repository variable `SECURITY_DRILL_OWNERS` with owner fallback.
  - Added automation operations doc and linked it from drill governance and docs index.
  - Updated roadmap/threat-model references to mark #188 as implemented.
- Why:
  - Close issue #188 and reduce process drift in incident-drill execution readiness.
- Files:
  - `.github/workflows/security-drill-kickoff.yml`
  - `docs/security/drills/QUARTERLY_KICKOFF_AUTOMATION.md`
  - `docs/security/drills/QUARTERLY_DRILL_PROGRAM.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-13 (M25 isolated rollback rehearsal environment)
- Scope:
  - Added isolated rollback drill harness script for baseline/rotate/rollback/post-rollback validation.
  - Added CI gate that executes the rehearsal harness and verifies evidence manifests.
  - Added dedicated environment design doc and integrated evidence checklist into incident drill runbook.
  - Updated security roadmap/threat-model/docs index and quarterly drill program status.
- Why:
  - Close issue #189 with a reproducible and continuously validated rollback + rotation rehearsal path.
- Files:
  - `scripts/drill-rollback-rehearsal.sh`
  - `scripts/ci-drill-rehearsal.sh`
  - `.github/workflows/security-gates.yml`
  - `docs/security/drills/ISOLATED_ROLLBACK_REHEARSAL_ENVIRONMENT.md`
  - `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`
  - `docs/security/drills/QUARTERLY_DRILL_PROGRAM.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-13 (M26 security hardening program v2 initialization)
- Scope:
  - Created milestone `M26 - Security Hardening Program v2`.
  - Opened structured security workstream issues `#196`..`#204` covering endpoint isolation, parser minimization, PQ recovery, metadata resistance v3, anti-abuse, supply-chain integrity, formal verification, external assurance, and PIR deployment viability.
  - Added central execution/governance document with mandatory delivery format and release gates.
  - Updated security roadmap and docs index with v2 program tracking.
- Why:
  - Convert broad hardening goals into a production-grade, enforceable execution program with explicit invariants and acceptance criteria.
- Files:
  - `docs/security/SECURITY_HARDENING_PROGRAM_V2.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-13 (M26 endpoint zero-click isolation architecture pack)
- Scope:
  - Added endpoint isolation architecture, typed IPC contract, and zero-click ingestion threat-model delta documents for workstream `#196`.
  - Updated roadmap/docs index with explicit references to the new boundary artifacts.
- Why:
  - Establish production-grade boundary invariants and implementation contract before coding the zero-click isolation worker path.
- Files:
  - `docs/security/ENDPOINT_ZERO_CLICK_ISOLATION_ARCHITECTURE.md`
  - `docs/security/UNTRUSTED_PARSER_IPC_CONTRACT.md`
  - `docs/security/ZERO_CLICK_INGESTION_THREAT_MODEL.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-12 (M25 external cryptography audit engagement pack)
- Scope:
  - Added dedicated external cryptography audit package under `docs/security/audit`.
  - Added reviewer checklist and claim-to-test evidence matrix for independent assessment.
  - Added remediation workflow and repository issue template for audit findings.
  - Updated docs index, security roadmap, and threat model with audit-readiness delta.
- Why:
  - Close issue #164 with audit-ready documentation and standardized remediation intake.
- Files:
  - `docs/security/audit/README.md`
  - `docs/security/audit/CRYPTOGRAPHIC_PROTOCOL_SNAPSHOT.md`
  - `docs/security/audit/SECURITY_CLAIMS_TO_TESTS_MATRIX.md`
  - `docs/security/audit/EXTERNAL_REVIEWER_CHECKLIST.md`
  - `docs/security/audit/REMEDIATION_WORKFLOW.md`
  - `.github/ISSUE_TEMPLATE/crypto-remediation.yml`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - This pack improves reviewer onboarding and finding lifecycle rigor, but is not a formal proof set.

## 2026-03-12 (M25 traffic-correlation red-team assessment)
- Scope:
  - Added traffic-correlation assessment report with attacker models, success metrics, and live-test plan.
  - Opened concrete mitigation backlog issues for timing/profile hardening.
  - Updated threat model with explicit residual-risk statement and mitigation links.
  - Updated documentation index and advanced security roadmap references.
- Why:
  - Close issue #165 with documented assessment output and actionable follow-up backlog.
- Files:
  - `docs/security/TRAFFIC_CORRELATION_RED_TEAM_ASSESSMENT.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Linked issues:
  - `#184`
  - `#185`
  - `#186`

## 2026-03-12 (M25 recurring security incident drill program)
- Scope:
  - Added quarterly drill calendar and dedicated drill runbook.
  - Added first retrospective template for drill outcomes.
  - Added explicit follow-up issue tracking for unresolved operational actions.
  - Updated security roadmap, docs index, and threat model with drill-program status.
- Why:
  - Close issue #166 with institutionalized operational drill process and actionable follow-up queue.
- Files:
  - `docs/security/drills/QUARTERLY_DRILL_PROGRAM.md`
  - `docs/security/drills/INCIDENT_DRILL_RUNBOOK.md`
  - `docs/security/drills/FIRST_DRILL_RETROSPECTIVE_TEMPLATE.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Linked issues:
  - `#188`
  - `#189`

## 2026-03-12 (M25 bounded schedule jitter hardening)
- Scope:
  - Added per-loop seeded scheduler jitter streams for fixed polling and constant-rate traffic loops.
  - Added deterministic regression tests for schedule sequence stability and stream separation.
  - Documented scheduler hardening model and deterministic fixture usage.
  - Updated traffic-correlation risk references in roadmap/threat model/docs index.
- Why:
  - Close issue #184 and reduce phase-fingerprinting persistence in strict anonymity scheduling.
- Files:
  - `client/src/service.rs`
  - `docs/security/SCHEDULE_JITTER_HARDENING.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-12 (M25 multi-relay quorum blend retrieval)
- Scope:
  - Added explicit quorum fallback policy (`strict` default, optional best-effort) for pending fetches.
  - Added deterministic relay-order shuffle seed override for controlled simulation/testing.
  - Added tests for quorum enforcement, partial-collusion resistance, and fallback behavior.
  - Added operations/security guidance for quorum blend tradeoffs.
- Why:
  - Close issue #185 with explicit quorum policy controls and stronger validation coverage.
- Files:
  - `client/src/network/relay.rs`
  - `docs/security/MULTI_RELAY_QUORUM_BLEND_RETRIEVAL.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-13 (M25 route anti-correlation scoring v2)
- Scope:
  - Expanded onion route scoring with temporal reuse penalty and optional score-threshold rejection.
  - Added explicit reject reasons and counters for diversity, threshold, and empty-topology cases.
  - Exposed new route-reject telemetry fields in diagnostics health report.
  - Added regression tests for repeated-path suppression and reject counter behavior.
  - Added v2 design/operations note and updated roadmap/threat-model/docs index.
- Why:
  - Close issue #186 with stronger anti-correlation enforcement and observable policy telemetry.
- Files:
  - `client/src/network/onion.rs`
  - `client/src/diagnostics.rs`
  - `docs/security/ROUTE_ANTI_CORRELATION_SCORING_V2.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`

## 2026-03-12 (M24 hybrid PQ handshake finalization)
- Scope:
  - Documented transcript-bound hybrid handshake KDF context (mode + OPK usage + PQ usage bits).
  - Added operator migration notes for `prefer` -> `required` rollout and rollback handling.
  - Updated iOS integration docs for FFI/app-level PQ handshake policy controls.
- Why:
  - Close issue #162 with explicit downgrade-resistant policy guidance and migration instructions.
- Files:
  - `docs/protocol.md`
  - `docs/security/PQ_HANDSHAKE_MIGRATION_NOTES.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/ios.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Strict lockdown profile now expects PQ handshake policy `required` for high-risk deployments.

## 2026-03-12 (M24 deniability signature policy audit)
- Scope:
  - Added deniability signature decision record with audited signature paths and final policy.
  - Updated scripted loopback semantics in protocol docs to deniable-by-default signature behavior.
  - Updated security index/threat model and roadmap references.
- Why:
  - Close issue #161 by making transcript deniability policy explicit and testable.
- Files:
  - `docs/security/DENIABILITY_SIGNATURE_DECISION.md`
  - `docs/protocol.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Optional signature enforcement remains available only for controlled interoperability testing.

## 2026-03-12 (M26 PIR/proxy mailbox retrieval feasibility spike)
- Scope:
  - Added deterministic PIR/proxy feasibility benchmark tool and generated JSON artifact.
  - Added security report with benchmark summary, explicit threat-model delta, and go/no-go recommendation.
  - Added regeneration script and Make target for report reproducibility.
- Why:
  - Close issue #156 with a concrete, repeatable decision basis for whether PIR/proxy retrieval should move into production roadmap.
- Files:
  - `client/src/bin/pir_proxy_feasibility.rs`
  - `docs/security/pir-proxy-feasibility-report.v1.json`
  - `docs/security/PIR_PROXY_MAILBOX_RETRIEVAL_SPIKE.md`
  - `docs/threat_model.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/README.md`
  - `scripts/generate-pir-proxy-feasibility-report.sh`
  - `Makefile`
  - `docs/CHANGELOG.md`
- Notes:
  - Current decision is no mandatory rollout; proxy/PIR stays in research/opt-in profile pending stronger cost and audit outcomes.

## 2026-03-12 (M27 lockdown compatibility profile + high-risk guidance)
- Scope:
  - Added strict/standard lockdown compatibility profile model in iOS runtime.
  - Added fail-closed enforcement when strict profile assumptions are violated after network activation.
  - Added compatibility telemetry surfaced in Settings UI and regression tests for strict profile decisions.
  - Published lockdown compatibility matrix and iOS high-risk deployment guidance.
- Why:
  - Close issue #160 with explicit compatibility behavior under high-risk/lockdown assumptions and user-visible safety guidance.
- Files:
  - `RedoorApp/RedoorApp/Core/LockdownCompatibilityProfile.swift`
  - `RedoorApp/RedoorApp/Services/RedoorService.swift`
  - `RedoorApp/RedoorApp/Features/Settings/SettingsView.swift`
  - `RedoorApp/RedoorAppTests/RedoorAppTests.swift`
  - `docs/security/LOCKDOWN_COMPATIBILITY_MATRIX.md`
  - `docs/ios.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - iOS does not provide a stable public Lockdown Mode detection API for third-party apps; Redoor uses profile-based runtime assumption checks.

## 2026-03-12 (M24 zero-click readiness runbook + drill assets)
- Scope:
  - Added a dedicated zero-click readiness runbook with triage, containment, forensic handling, and key/session rotation workflow.
  - Added a versioned tabletop drill scenario (`v1`) and post-drill action tracker template.
  - Linked new zero-click docs from security index/runbook pages.
- Why:
  - Satisfy incident-response readiness requirements for suspected zero-click exploitation attempts and make drill outputs repeatable.
- Files:
  - `docs/security/ZERO_CLICK_READINESS_RUNBOOK.md`
  - `docs/security/drills/zero_click_tabletop_scenario_v1.md`
  - `docs/security/drills/post_drill_action_tracker_template.md`
  - `docs/security-runbook.md`
  - `docs/README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Future drill iterations should increment scenario version (`v2`, `v3`, ...) and link retrospective issue IDs.

## 2026-03-12 (M25 route anti-correlation scoring)
- Scope:
  - Added route anti-correlation scoring in onion route selection using recent path memory across operator/jurisdiction/ASN/node overlap.
  - Added deterministic tests validating overlap-penalty behavior and correlation telemetry output.
  - Extended protocol docs with route-correlation telemetry fields.
- Why:
  - Reduce repeated infrastructure reuse and make path-selection hardening observable in diagnostics/regression checks.
- Files:
  - `client/src/network/onion.rs`
  - `client/src/diagnostics.rs`
  - `docs/BLUEPRINT.md`
  - `docs/protocol.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Correlation telemetry currently reports the latest selected path score and overlap components.

## 2026-03-12 (M22 multi-relay split retrieval + quorum policy)
- Scope:
  - Added parallel `/fetch_pending` fan-out across configured relay mirrors with merged deterministic duplicate handling.
  - Added configurable relay confirmation quorum gate for pending retrieval selection.
  - Added regression tests for deterministic merge, quorum behavior, and partial relay outage handling.
- Why:
  - Reduce single-relay receiver-interest leakage while keeping retrieval behavior predictable under mirror disagreement/outage.
- Files:
  - `client/src/network/relay.rs`
  - `docs/protocol.md`
  - `docs/BLUEPRINT.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Quorum currently defaults to `1` for compatibility and can be tightened per deployment risk tolerance.

## 2026-03-12 (M22 traffic-shape hardening v2)
- Scope:
  - Added strict-mode jitter budget cap and periodic phase-window re-randomization controls for fixed poll and constant-rate loops.
  - Added phase-synchronization simulation metrics to traffic-anonymity diagnostics and checks.
  - Extended Rust CI quality gate with realtime delivery SLO smoke tests.
- Why:
  - Reduce cadence alignment fingerprinting while bounding latency drift for practical delivery UX.
- Files:
  - `client/src/service.rs`
  - `client/src/diagnostics.rs`
  - `scripts/ci-rust-quality.sh`
  - `docs/protocol.md`
  - `docs/CHANGELOG.md`
- Notes:
  - New profile knobs: `REDOOR_SECURE_JITTER_BUDGET_MS`, `REDOOR_SECURE_PHASE_WINDOW_TICKS`, and `REDOOR_SECURE_PHASE_WINDOW_PCT`.

## 2026-03-08
- Scope:
  - Full docs refresh aligned to current architecture, security gates, and iOS/runtime behavior.
  - Added core design/governance docs at repository root.
- Why:
  - Keep project documentation consistent with current implementation and hardening milestones.
- Files:
  - `README.md`
  - `docs/README.md`
  - `docs/architecture.md`
  - `docs/protocol.md`
  - `docs/threat_model.md`
  - `docs/ci.md`
  - `docs/ios.md`
  - `docs/security-logging.md`
  - `docs/security-runbook.md`
  - `docs/BLUEPRINT.md`
  - `docs/DEVELOPER_FLOW.md`
  - `docs/REPO_SETUP.md`
  - `RedoorApp/docs/ENGINEERING_MILESTONES.md`
  - `CODE_OF_CONDUCT.md`
  - `SYSTEM_DESIGN.md`
  - `OO_DESIGN.md`
  - `DOMAIN_MODEL.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Subsequent documentation updates should append a new dated entry.

## 2026-03-10
- Scope:
  - Added a full enterprise documentation pack covering architecture, high/low-level design, requirements, roadmap, testing strategy, database strategy, scalability/performance, API/cybersecurity, SCM/maintenance, and UML views.
  - Updated root and docs indexes to surface the new enterprise documentation.
  - Expanded Code of Conduct with responsible security research disclosure guidance.
- Why:
  - Provide clearer enterprise-level design and operations guidance aligned with the current implementation and security posture.
- Files:
  - `docs/enterprise/README.md`
  - `docs/enterprise/ENTERPRISE_ARCHITECTURE.md`
  - `docs/enterprise/LOW_LEVEL_AND_OO_DESIGN.md`
  - `docs/enterprise/SOFTWARE_DESIGN.md`
  - `docs/enterprise/SECURITY_AND_API_STRATEGY.md`
  - `docs/enterprise/DATA_SCALABILITY_AND_PERFORMANCE.md`
  - `docs/enterprise/TESTING_QUALITY_METRICS_AND_SCM.md`
  - `docs/enterprise/REQUIREMENTS_AND_ROADMAP.md`
  - `docs/enterprise/SCM_AND_MAINTENANCE.md`
  - `docs/enterprise/UML.md`
  - `docs/enterprise/PDF_FOUNDATION.md`
  - `docs/README.md`
  - `README.md`
  - `SYSTEM_DESIGN.md`
  - `OO_DESIGN.md`
  - `CODE_OF_CONDUCT.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Future implementation work should convert roadmap items into tracked milestones/issues with acceptance criteria.

## 2026-03-12
- Scope:
  - Synced core and enterprise docs with recent anonymity work (relay diversity policy, traffic-analysis simulator, linkability regression gate).
  - Added advanced message-security roadmap for high-capability adversaries, including explicit OpenPGP/PGP positioning.
  - Updated CI/security and runbook docs for anonymity artifact publication and emergency override flow.
- Why:
  - Keep architecture/security documentation aligned with implemented controls and clarify next high-impact hardening directions.
- Files:
  - `README.md`
  - `docs/README.md`
  - `docs/architecture.md`
  - `docs/protocol.md`
  - `docs/threat_model.md`
  - `docs/BLUEPRINT.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/ci.md`
  - `docs/security-runbook.md`
  - `docs/enterprise/SECURITY_AND_API_STRATEGY.md`
  - `docs/enterprise/REQUIREMENTS_AND_ROADMAP.md`
  - `SYSTEM_DESIGN.md`
  - `OO_DESIGN.md`
  - `DOMAIN_MODEL.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Use `docs/security/traffic-linkability-baseline.v1.json` as the canonical threshold reference for CI linkability gates.

## 2026-03-12 (M6 hardening implementation update)
- Scope:
  - Documented PQ handshake policy negotiation (`prefer/required/disabled`) and explicit handshake-mode signaling.
  - Added AS-level mix diversity + multi-relay split retrieval controls to protocol docs.
  - Updated advanced security roadmap and incident runbook with concrete audit/drill cadence.
- Why:
  - Keep milestone M6 docs aligned with implemented code-level hardening and remaining high-priority work.
- Files:
  - `docs/protocol.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/security-runbook.md`
  - `docs/enterprise/REQUIREMENTS_AND_ROADMAP.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Remaining M6 priorities: route-scoring anti-correlation, PIR/proxy retrieval prototype, reproducible signed build attestations, and external audit remediation tracking.

## 2026-03-12 (M21 parser fuzz expansion)
- Scope:
  - Added inbound parser fuzz targets and malformed corpus seeds for envelope/handshake paths.
  - Added deterministic parser fuzz regression tests and CI parser-fuzz gate script/workflow job.
  - Updated CI docs and local Make targets for parser fuzz regression execution.
- Why:
  - Increase resilience of untrusted inbound decode paths and keep parser regressions merge-blocking in CI.
- Files:
  - `client/fuzz/fuzz_targets/inbound_decode.rs`
  - `client/fuzz/fuzz_targets/handshake_nested_json.rs`
  - `client/fuzz/corpus/inbound_decode/*`
  - `client/fuzz/corpus/handshake_nested_json/*`
  - `client/tests/parser_fuzz_regression.rs`
  - `client/src/engine.rs`
  - `scripts/ci-parser-fuzz.sh`
  - `.github/workflows/security-gates.yml`
  - `Makefile`
  - `docs/ci.md`
  - `docs/CHANGELOG.md`

## 2026-03-17 (Issue #7 status-board tracker synchronization)
- Scope:
  - Replaced stale status references (`#212..#218` / old milestone wording) with current repository issue tracker references.
  - Added explicit source-of-truth policy in `docs/OPEN_SOURCE_STATUS.md` including update owner, last-synced date, and sync cadence.
  - Aligned contributor-facing status sections in `README.md`, `CONTRIBUTING.md`, and `OO_DESIGN.md` with current issue IDs and tracker links.
- Why:
  - Keep open-source status documentation synchronized with this repository tracker and prevent drift across top-level docs.
- Files:
  - `docs/OPEN_SOURCE_STATUS.md`
  - `README.md`
  - `CONTRIBUTING.md`
  - `OO_DESIGN.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Parser fuzz gate uses deterministic bounded mutation smoke for stable CI runtime.

## 2026-03-17 (Issue #6 PIR/proxy deployability graduation plan)
- Scope:
  - Added a dedicated PIR/proxy deployability graduation plan with measurable stage gates and rollout policy.
  - Linked the new plan from security roadmap/threat model/docs index and open-source status board.
  - Split follow-up implementation into actionable tracker tasks (`#23`, `#24`, `#25`, `#26`).
- Why:
  - Move PIR/proxy retrieval from research-only posture toward an explicit, auditable graduation process.
- Files:
  - `docs/security/PIR_PROXY_DEPLOYABILITY_GRADUATION_PLAN.md`
  - `docs/security/ADVANCED_MESSAGE_SECURITY.md`
  - `docs/threat_model.md`
  - `docs/README.md`
  - `docs/OPEN_SOURCE_STATUS.md`
  - `docs/CHANGELOG.md`

## 2026-03-12 (M23 release integrity and provenance)
- Scope:
  - Added deterministic release build scripts for core Linux artifacts with checksum manifests.
  - Added reproducible rebuild verification and operator attestation/checksum verification script.
  - Added release-integrity CI workflow with signed SLSA provenance and tag asset publishing.
  - Updated CI/index docs and README with release-integrity commands and references.
- Why:
  - Improve release trust and supply-chain integrity with repeatable builds and verifiable provenance.
- Files:
  - `scripts/release-build-core.sh`
  - `scripts/verify-reproducible-build.sh`
  - `scripts/verify-release-integrity.sh`
  - `.github/workflows/release-integrity.yml`
  - `Makefile`
  - `docs/release-integrity.md`
  - `docs/README.md`
  - `docs/ci.md`
  - `README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Provenance verification can be enforced with `gh attestation verify` and signer-workflow policy.

## 2026-03-12 (M23 memory zeroization and forensics audit)
- Scope:
  - Hardened Rust wipe paths to zeroize message, attachment, session, queue, proof, log, and metadata buffers before clearing.
  - Fixed message-history delete path to use secure zeroization instead of direct map clears.
  - Added crash-adjacent hygiene path coverage and regression tests.
  - Added dedicated memory-hygiene CI gate and security matrix documentation with residual forensic risk limits.
- Why:
  - Make memory lifecycle guarantees explicit, regression-tested, and resistant to implementation drift.
- Files:
  - `client/src/engine.rs`
  - `client/src/service.rs`
  - `client/src/ffi.rs`
  - `scripts/ci-memory-hygiene.sh`
  - `.github/workflows/security-gates.yml`
  - `Makefile`
  - `docs/security/MEMORY_ZEROIZATION_MATRIX.md`
  - `docs/ci.md`
  - `docs/README.md`
  - `README.md`
  - `docs/CHANGELOG.md`
- Notes:
  - Zeroization reduces forensic exposure but cannot fully mitigate pre-wipe compromise at kernel/hypervisor level.
