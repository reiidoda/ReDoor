# RedoorApp Engineering Milestones

This document tracks iOS-facing milestones and cross-runtime hardening relevant to the app integration.

## 1. Current Architecture Snapshot
- UI layer: SwiftUI feature modules (`Features/Setup`, `Features/Chat`, `Features/Settings`)
- App orchestration: `ChatViewModel` + `ChatService`
- Service facade: `RedoorService` and focused services (network, identity, session, security)
- Runtime bridge: `Core/RedoorFFI.swift` -> Rust `client` static library
- Volatile storage: `SecureStorage` / `HMACKeyStore` (RAM-only)

## 2. Security Baseline (Implemented)
- remote relay validation requires HTTPS + HMAC + TLS pin material
- onion routing config required (`>= 3` nodes)
- lock/wipe on background, resign-active, terminate, and duress
- strict anonymity and fixed polling toggles wired through FFI
- volatile-only local storage policy checks in CI

## 3. Completed Milestones

### Milestone A: Build and Runtime Integration Stabilization
Status: `DONE`
- fixed iOS simulator static-link flow to Rust client library
- removed flaky startup coupling in app bootstrap paths

### Milestone B: Transport Security Enforcement
Status: `DONE`
- added relay CA/SPKI pin plumbing and runtime setters
- enforced remote relay security validation in `NetworkConfigValidator`
- required onion route configuration for secure sessions

### Milestone C: Reliability and Recovery
Status: `DONE`
- implemented bounded reconnect strategy
- stabilized heartbeat behavior and user preference handling
- improved status polling and reconnect cancellation paths

### Milestone D: CI Security Gates
Status: `DONE`
- Swift quality gate with static analysis and RAM-only policy checks
- Rust and Go quality/security gates aligned with repo CI workflows

### Milestone E: Regression Hardening
Status: `DONE`
- issue `79`: Rust enforcement improvements
- issue `80`: Go enforcement improvements
- issue `81`: lifecycle wipe + duress regression tests
- issue `82`: memory budget benchmarks and regression checks

## 4. Active Risks / Known Gaps
- deployment target and Xcode SDK drift can break CI analyze jobs if not synced
- linking failures can occur if Rust staticlib is not built before iOS analysis
- strict security config can block setup UX if fields are incomplete; validation messaging must remain clear

## 5. Next Milestones

### Milestone F: iOS UX Hardening (Security Clarity)
- improve setup flow guidance for pinning/onion requirements
- replace deprecated navigation APIs and remove warnings
- add more deterministic UI tests for lock/unlock/duress transitions

### Milestone G: End-to-End Observability
- expose structured diagnostics summary in-app for troubleshooting
- map diagnostics to actionable states for non-technical users

### Milestone H: Release Readiness
- define reproducible release checklist for iOS + Rust library artifacts
- enforce final threat-model and runbook sign-off before production rollouts

## 6. Definition of Done for New iOS Security Issues
- change is covered by unit/integration tests
- no RAM-only policy regression
- no new secret or persistence risk introduced
- CI security gates pass without exceptions
