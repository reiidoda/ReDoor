# Developer Flow

This document defines the day-to-day implementation cycle used in this repository.

## 1. Issue-First Workflow
1. Open/assign an issue with clear scope and acceptance criteria.
2. Create a branch from `main`.
3. Implement minimal, scoped changes.
4. Run required quality gates locally.
5. Open PR with security/testing evidence.
6. Merge after checks and review pass.

## 2. Branch Naming
Preferred pattern:
- `fix/issue-<id>-<short-slug>`

Examples:
- `fix/issue-80-add-go-enforcement`
- `fix/issue-81-add-lifecycle-wipe-and-duress-regression-tests`

## 3. Commit Expectations
- Small, focused commits.
- Message format: imperative summary with issue context.
- Never commit secrets, generated local certs, or private key material.

## 4. Local Verification Matrix
Run at least the gates affected by your change.

### 4.1 Full baseline
```bash
cd <repo-root>
make ci
```

### 4.2 Focused gates
- Rust/security: `./scripts/ci-rust-quality.sh`
- Go/security: `./scripts/ci-go-quality.sh`
- Swift/static analysis: `./scripts/ci-swift-quality.sh`
- Memory regressions: `./scripts/ci-memory-regression.sh`
- Realtime soak: `./scripts/ci-reliability-soak.sh`
- Traffic anonymity simulation: `./scripts/ci-traffic-anonymity-simulator.sh`
- Traffic anonymity regression gate: `./scripts/ci-anonymity-regression.sh`

## 5. Security Change Checklist
For any transport/crypto/state change confirm:
- relay HMAC/pinning behavior is preserved
- strict anonymity/onion path policy is not bypassed
- no new persistent storage introduced on iOS paths
- wipe/duress behavior still clears sensitive runtime state
- logs do not expose secrets/tokens/keys

## 6. PR Template Guidance
Include:
- issue link and scope
- what changed and why
- risk assessment (security, reliability, compatibility)
- exact commands executed locally
- CI results and any expected warnings
- follow-up tasks (if intentionally deferred)

## 7. Merge Criteria
A PR is merge-ready only when:
- all mandatory CI checks are green
- review comments are resolved
- no unresolved secret-scan findings
- no known security regression is introduced

## 8. Hotfix Path
For urgent security fixes:
1. branch from latest `main`
2. isolate the patch
3. run minimum critical gates (`ci-rust-quality`, `ci-go-quality`, `ci-swift-quality`, secret scan)
4. merge with expedited review
5. follow with retrospective hardening issue

## 9. Documentation Rule
Every behavior/security change must update relevant docs in the same PR:
- protocol changes -> `docs/protocol.md`
- architecture changes -> `docs/architecture.md` and/or `SYSTEM_DESIGN.md`
- model changes -> `OO_DESIGN.md` / `DOMAIN_MODEL.md`
- operational changes -> `docs/ci.md`, `docs/security-runbook.md`, `docs/REPO_SETUP.md`
