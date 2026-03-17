# Security Claims to Tests Matrix

Date: 2026-03-12  
Scope version: `audit-snapshot.v1`

## 1. How to Use

This matrix links each major claim to executable evidence.
External reviewers should re-run commands and inspect referenced files/artifacts before concluding.

## 2. Matrix

| Security Claim | Evidence Type | Command / File | Current Signal | Notes |
| --- | --- | --- | --- | --- |
| No client persistence for sensitive Swift app paths | Policy gate | `./scripts/check-ram-only-policy.sh` | Pass in local gating | Enforces RAM-only policy for iOS app paths. |
| Auto-processing attack surface reduced | Policy gate | `./scripts/check-auto-processing-lockdown.sh` | Pass in local gating | Checks lockdown policy for untrusted content auto-processing. |
| Parser surface expansion is blocked by policy | Policy gate | `./scripts/check-parser-surface-policy.sh` | Pass in local gating | Enforces parser inventory, allowlist guards, strict schema controls, and corpus baseline presence. |
| Rust security/static quality gates are enforced | CI quality | `./scripts/ci-rust-quality.sh` | Pass locally | Runs format/clippy/audit policy and additional security checks. |
| Go relay/network quality + vuln scan enforced | CI quality | `./scripts/ci-go-quality.sh` | Project gate | Includes linting/vuln posture for Go components. |
| Swift static analysis gate is enforced | CI quality | `./scripts/ci-swift-quality.sh` | Project gate | Includes static analysis and RAM-only policy checks. |
| Parser hardening regressions are detected | Regression test | `./scripts/ci-parser-fuzz.sh` | Project gate | Guards against parser regressions and malformed input acceptance. |
| Memory hygiene regressions are detected | Regression test | `./scripts/ci-memory-hygiene.sh` | Project gate | Tracks wipe/zeroization policy regressions. |
| Memory budget regressions are detected | Regression test | `./scripts/ci-memory-regression.sh` | Project gate | Enforces bounded memory behavior over time. |
| Realtime delivery and reconnect reliability are tested | Integration tests | `./scripts/ci-reliability-soak.sh` | Project gate | Covers runtime connection resilience and delivery latencies. |
| User-to-user realtime path has integration coverage | Integration tests | `itest/tests/realtime_user_to_user.rs` | In repo | Simulates delivery, reconnect, and burst behavior. |
| HMAC roundtrip/auth path has integration coverage | Integration tests | `itest/tests/hmac_roundtrip.rs` | In repo | Validates authenticated relay request path. |
| Parser fuzz classifications are validated | Test source | `client/tests/parser_fuzz_regression.rs` | In repo | Ensures malformed payload classes remain blocked. |
| Deniability defaults are explicitly documented | Design decision | `docs/security/DENIABILITY_SIGNATURE_DECISION.md` | Accepted decision | Default avoids mandatory globally verifiable message signatures. |
| PQ handshake policy and downgrade hardening documented | Design + migration | `docs/security/PQ_HANDSHAKE_MIGRATION_NOTES.md` | Published | Includes mode negotiation and transcript binding expectations. |
| PQ post-compromise recovery profile is benchmarked (prototype) | Prototype artifact | `docs/security/pq-ratchet-evolution-report.v1.json` | Published | Research profile; not default production behavior yet. |
| Traffic-linkability baseline is measurable | Artifact + gate | `docs/security/traffic-linkability-baseline.v1.json` and `./scripts/ci-traffic-anonymity-simulator.sh` | Baseline available | Deterministic simulator for regression tracking. |

## 3. Gaps to Keep Explicit

1. No formal cryptographic proof artifact is included yet.
2. Independent third-party cryptanalysis report is pending.
3. Internet-scale real-world traffic-correlation red-team data is pending.

These gaps are tracked by issues:
- `#164` (this engagement pack, initial setup)
- `#165` (traffic-correlation red-team assessment)
- `#166` (recurring incident drill program)
