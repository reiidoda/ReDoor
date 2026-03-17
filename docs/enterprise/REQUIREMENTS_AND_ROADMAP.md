# Software Requirements and Roadmap

## 1. Software Requirements

### 1.1 Functional requirements

- **FR-01**: Users can establish secure sessions without centralized account verification.
- **FR-02**: Users can send and receive encrypted messages over relay-backed transport.
- **FR-03**: Relay stores transient message payloads and supports fetch-once for normal blobs.
- **FR-04**: Directory resolves user public key records with signed responses.
- **FR-05**: Blockchain service stores tamper-evidence commitments for sent messages.
- **FR-06**: iOS app enforces lock/wipe flow on lifecycle transitions and duress mode.

### 1.2 Non-functional requirements

- **NFR-01 (Privacy)**: client-side sensitive state is memory-first and wipeable.
- **NFR-02 (Security)**: transport and service APIs enforce TLS and abuse protections.
- **NFR-03 (Reliability)**: realtime delivery and reconnect paths are continuously tested.
- **NFR-04 (Scalability)**: services can scale horizontally by domain.
- **NFR-05 (Maintainability)**: architecture and API contracts remain documented and versioned.
- **NFR-06 (Observability)**: key SLOs and security indicators are measurable.

### 1.3 Constraints

- no centralized identity authority in current product vision;
- plaintext must not be persisted by transport or evidence layers;
- secure defaults should fail closed for critical controls.

## 2. Roadmap (Enterprise Evolution)

### Milestone M1: Security and Identity Hardening

Scope:
- mTLS/service identity for server-to-server communication.
- formal API schema contracts and request validation.
- key management and rotation framework.

Implementation decomposition (tracked):
1. `#28` OpenAPI contracts and strict request validation.
2. `#29` mTLS service-plane identity and cert rotation.
3. `#30` KMS/bootstrap key management and staged rotation framework.
4. `#31` Security event taxonomy and structured audit-log rollout.

Execution map:
- `docs/enterprise/M1_IMPLEMENTATION_DECOMPOSITION.md`

### Milestone M2: Data and Event Platform

Scope:
- domain database separation and event contracts.
- outbox pattern and deduplicated asynchronous workflows.

Candidate issues:
1. Implement `request_db` and `confirmation_db` bounded contexts.
2. Add event bus topic contracts and schema registry.
3. Add outbox/inbox consistency workflow per service.
4. Add replay-safe event consumer idempotency keys.

### Milestone M3: Scalability and Performance

Scope:
- load balancing, partitioning, and region-aware routing.
- WebSocket-assisted realtime notifications (without payload exposure).

Candidate issues:
1. Add relay horizontal partitioning by receiver hash.
2. Add API gateway with rate-limits and policy enforcement.
3. Add optional WebSocket notification channel for pending-message signal.
4. Add regional failover and latency-aware routing tests.

### Milestone M4: Reliability and Quality Excellence

Scope:
- comprehensive chaos and resilience testing.
- SLO-driven operations and automated rollback criteria.

Candidate issues:
1. Add chaos tests for relay restarts and network partitions.
2. Add SLO dashboards and automated error-budget alerts.
3. Add fuzzing campaigns for parser/security-critical modules.
4. Add release readiness checklist with rollback simulation.

### Milestone M5: Formal Verification and Compliance Readiness

Scope:
- stronger cryptographic review and protocol verification.
- incident response and governance maturity.

Candidate issues:
1. Add protocol state-machine checks and invariant tests.
2. Perform external security review and track remediation.
3. Add data retention and privacy governance controls.
4. Align runbooks to SOC2/ISO27001-style control mapping.

### Milestone M6: State-Level Adversary Resistance

Scope:
- strengthen resistance to global surveillance correlation and endpoint compromise.
- evolve protocol toward hybrid post-quantum forward secrecy and stronger deniability posture.

Candidate issues:
1. Completed: hybrid classical + PQ session bootstrap with explicit handshake-mode negotiation and runtime policy (`prefer/required/disabled`).
2. Completed: route diversity minima now enforce operator/jurisdiction/ASN anti-correlation constraints in strict profile.
3. Completed (baseline): multi-relay split mailbox retrieval support (`REDOOR_FETCH_PENDING_MIRRORS`) with randomized relay selection.
4. Completed (baseline): deniability-safe defaults in loopback API where per-message signatures are optional and not required for decrypt path.
5. Remaining: add route scoring heuristics (not only minimum-set constraints) and circuit history anti-correlation memory.
6. Remaining: evaluate PIR/proxy mailbox retrieval prototype and quantify cost/latency/security trade-offs.
7. Remaining: introduce reproducible builds + signed provenance attestations for client/service binaries.
8. Remaining: complete independent crypto + traffic-correlation external audits and close remediation actions.

OpenPGP note:
- OpenPGP/PGP is not the primary realtime message protocol target for this roadmap; it can still be used for release-signing and limited out-of-band operational use.

## 3. Prioritization Rules

- prioritize vulnerabilities and privacy regressions over feature work;
- prioritize high-impact reliability blockers before scaling features;
- treat insecure defaults as release blockers;
- tie every roadmap item to measurable acceptance criteria.
