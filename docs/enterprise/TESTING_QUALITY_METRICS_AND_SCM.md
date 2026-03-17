# Testing Strategy, Software Quality, Metrics, SCM, and Maintenance

## 1. Testing Strategy

### 1.1 Test pyramid for Redoor
- **Unit tests**: crypto primitives, parsers, validators, replay guards.
- **Component tests**: relay handlers, directory resolve logic, blockchain validation.
- **Integration tests**: user-to-user realtime flow, reconnect chaos, lifecycle wipe.
- **Security tests**: replay attempts, malformed payloads, auth bypass checks.
- **Performance tests**: memory budgets, throughput and latency soak tests.

### 1.2 Existing automated gates
- Rust quality + clippy + audit + deny.
- Go format/vet/lint/test/vuln checks.
- Swift format/lint/static analysis.
- RAM-only policy checks.
- secret scanning via gitleaks.
- realtime soak and reconnect chaos tests.

### 1.3 Additional enterprise tests
- contract tests for all external APIs (OpenAPI + schema snapshots);
- property-based tests for envelope encode/decode invariants;
- fuzzing of relay/directory request parsers;
- chaos tests for service restarts and regional failover;
- threat regression suite mapped to threat model IDs.

## 2. Software Metrics

### 2.1 Delivery metrics
- lead time for change;
- deployment frequency;
- change failure rate;
- mean time to restore (MTTR).

### 2.2 Runtime reliability metrics
- availability by service (relay, directory, blockchain API);
- p50/p95 latency by endpoint;
- delivery success ratio;
- reconnect success ratio and p95 reconnect time;
- memory growth and reclaim ratio after wipe/duress.

### 2.3 Security metrics
- vulnerabilities by severity and SLA aging;
- replay rejection success rate;
- auth failure anomaly rate;
- secret leak detection/resolution time;
- dependency freshness and unsupported version count.

## 3. Software Configuration Management (SCM)

- trunk-based flow with short-lived feature/fix branches;
- protected `main` with mandatory CI checks;
- conventional commits and changelog discipline;
- release tagging with immutable build artifacts;
- environment-specific config via explicit variables and secrets managers;
- rollback playbooks for every production release.

## 4. Software Quality Model

Adopt quality gates aligned with ISO-like dimensions:
- **Functional suitability**: behavior matches protocol and policy contracts.
- **Reliability**: predictable performance under load and failure.
- **Security**: confidentiality, integrity, accountability controls.
- **Maintainability**: modular code, clear docs, measurable complexity.
- **Portability**: deterministic builds and environment parity.

## 5. Maintenance: C/A/R/M

### 5.1 Consistency
- schema/version governance;
- deterministic policy defaults;
- cross-service contract tests.

### 5.2 Availability
- multi-instance service deployment;
- health checks, retries, circuit breakers;
- automated failover drills.

### 5.3 Reliability
- SLO-based alerting;
- queue backlog controls;
- error budget policy for release pacing.

### 5.4 Maintainability
- bounded contexts and stable interfaces;
- regular dependency upgrades;
- architecture decision records (ADRs);
- deprecation policies and migration guides.

## 6. Tooling Matrix (Equivalent to SpotBugs-style governance)

| Language | Static/Quality Tooling |
|---|---|
| Rust | `clippy`, `rustfmt`, `cargo deny`, `cargo audit`, fuzzing (`cargo-fuzz`) |
| Go | `golangci-lint` (includes `staticcheck`, `errcheck`, `revive`), `go vet`, `govulncheck` |
| Swift | `swiftlint`, `swiftformat`, `xcodebuild analyze` |
| Repo-wide | gitleaks, dependency pinning checks, policy scripts |

## 7. Recommended SLO Baseline

| SLO | Target |
|---|---|
| Relay availability | >= 99.95% monthly |
| Directory resolve success | >= 99.95% monthly |
| End-to-end delivery success | >= 99.5% (excluding recipient offline windows) |
| Wipe path completion | >= 99.99% |
| Security gate pass rate on main | 100% |

