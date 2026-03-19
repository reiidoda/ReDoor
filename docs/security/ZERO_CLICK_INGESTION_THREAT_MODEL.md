# Zero-Click Ingestion Threat Model Delta

Date: 2026-03-13  
Issue: #196

## Scope

This delta focuses on hostile payload ingestion and parser-exposed paths.

## Adversaries

1. Remote payload attacker
- sends crafted payloads to trigger parser memory corruption or logic bugs.

2. Persistent exploit operator
- attempts repeated malformed inputs to force fallback or crash loops.

3. Correlation-aware attacker
- uses ingest degradation to force behavior that weakens anonymity.

## Key Risks

- R1: parser compromise leading to trusted-core compromise.
- R2: timeout/crash loops causing unsafe fallback.
- R3: parser bypass introduced by convenience code paths.
- R4: weak observability hides exploitation attempts.

## Mitigations

- M1: strict process isolation boundary for hostile parsing.
- M2: bounded typed IPC with deny-unknown schema.
- M3: fail-closed policy on parser unavailability.
- M4: structured security telemetry and anomaly counters.
- M5: CI policy checks to prevent direct hostile-byte parsing in trusted core.

## Residual Risk

- Endpoint compromise at OS/hardware layer remains out of app-level scope.
- Parser process compromise may still enable denial of service; containment reduces blast radius but does not eliminate all risk.

## Required Security Tests

- Boundary enforcement tests.
- Kill-on-timeout and restart policy tests.
- Direct-parse forbidden pattern checks in protected modules.
- Repeated malformed input pressure tests.
