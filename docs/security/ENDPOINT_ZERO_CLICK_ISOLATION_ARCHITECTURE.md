# Endpoint Zero-Click Isolation Architecture

Date: 2026-03-13  
Issue: #196

## Objective

Ensure all attacker-controlled content parsing is isolated behind a strict process boundary so compromise of parser logic does not directly compromise the main application runtime.

## Boundary Definition

Protected boundary: **Untrusted Ingestion Boundary (UIB)**.

- **Outside boundary (hostile):** bytes fetched from relay/network/storage restoration payloads, metadata probes, attachment/media payloads.
- **Inside boundary (trusted core):** session state, key material, routing/policy engine, identity material, outbound controls.

Only typed, validated parse outputs can cross from UIB to trusted core.

## Component Model

1. Main runtime (trusted core)
- Owns session/key state.
- Owns policy decisions.
- Owns storage/transport orchestration.
- Must not directly invoke parser entry points on hostile bytes.

2. Untrusted parser worker (sandboxed process)
- Single-purpose process for hostile-byte parsing/validation.
- No secret-bearing environment variables.
- Strict IPC schema only.
- Time-bounded request handling.

3. Boundary manager
- Starts/stops worker.
- Enforces request size, timeout, restart policy.
- Emits structured security telemetry.

## Current Implementation Status (2026-03-13)

- Implemented in client runtime:
  - [engine.rs](<repo-root>/client/src/engine.rs)
  - [main.rs](<repo-root>/client/src/main.rs)
- `poll_messages()` now parses untrusted envelope/inner/initial payloads only through boundary helper calls.
- Worker lifecycle is fail-closed:
  - timeout => kill worker + single restart attempt;
  - repeated failure => drop payload path, no inline fallback in production mode.
- Boundary telemetry is surfaced in health diagnostics:
  - launches, launch failures, restarts, timeouts, denials, IO failures, protocol mismatches, last error.
- Parser classes are policy-gated by allowlist (`REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`).
- Untrusted JSON inputs are pre-validated for depth/token/number budgets before typed decode.
- CI policy gate blocks direct untrusted parsing regressions in `poll_messages()`:
  - [check-untrusted-parser-boundary.sh](<repo-root>/scripts/check-untrusted-parser-boundary.sh)
  - wired from [ci-rust-quality.sh](<repo-root>/scripts/ci-rust-quality.sh)

## Invariants

- I1: direct parser calls for hostile bytes are forbidden in trusted core modules.
- I2: worker timeout/crash results in fail-closed behavior (drop/defer), never implicit inline bypass.
- I3: only schema-validated outputs are accepted from worker.
- I4: worker process environment excludes privileged credentials and admin controls.
- I5: boundary health is observable (launches, denials, crashes, restarts, kill-on-timeout).

## Failure Modes

- Worker unavailable at startup -> protected ingest path disabled fail-closed.
- Worker timeout -> kill worker, restart once, then fail-closed.
- Repeated malformed payloads -> deny and increment anomaly counters.
- IPC schema mismatch -> deny and quarantine request class.

## Rollout Strategy

1. Shadow mode telemetry (no policy switch) for stability baselining.
2. Strict mode in CI and canary deployments.
3. Strict mode default with documented emergency kill-switch.
4. Remove legacy direct parse paths once parity and telemetry SLOs hold.

Note:
- Integration test runs use debug-only inline mode when `INTEGRATION_RUN=1` to keep non-production harnesses deterministic.
- Release builds do not rely on this path.

## Operational Controls

- `REDOOR_UNTRUSTED_PARSER_WORKER_ENABLED`
- `REDOOR_UNTRUSTED_PARSER_WORKER_TIMEOUT_MS`
- `REDOOR_UNTRUSTED_PARSER_WORKER_MEM_LIMIT_BYTES`
- `REDOOR_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES`
- `REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`

All controls must have secure defaults and be surfaced in diagnostics.
