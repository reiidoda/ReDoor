# Schedule Jitter Hardening

Date: 2026-03-12  
Issue: #184

## Summary

The scheduler now uses per-loop seeded jitter streams (separate stream tags for fixed polling
and constant-rate sender loops) with bounded jitter and bounded phase-window shifts.

Goal:
- reduce long-term phase fingerprinting risk while preserving constant-rate envelope behavior.

## Implementation Notes

- Fixed polling loop and constant-rate loop each initialize a dedicated scheduler RNG stream.
- Stream seeds derive from:
  - optional deterministic override: `REDOOR_SECURE_SCHEDULER_SEED`,
  - stream tag (poll vs send),
  - base interval and strict-mode tag.
- Timing controls remain bounded by secure-profile caps:
  - `REDOOR_SECURE_JITTER_PCT`
  - `REDOOR_SECURE_JITTER_BUDGET_MS`
  - `REDOOR_SECURE_PHASE_WINDOW_TICKS`
  - `REDOOR_SECURE_PHASE_WINDOW_PCT`

## Strict Mode Behavior

- Strict anonymity still fail-closes on unsafe route conditions.
- Scheduler randomization cannot disable strict route requirements.
- Defaults remain secure-profile driven when intervals are not explicitly provided.

## Deterministic Regression Fixtures

Added service-level tests:
- `service::tests::test_scheduler_rng_sequence_is_deterministic_with_seed_override`
- `service::tests::test_scheduler_rng_stream_tags_avoid_identical_sequences`

Existing metrics gate (already in place):
- diagnostics phase-synchronization improvement checks via
  `diagnostics::tests::test_traffic_analysis_simulator_regression_expectations_hold`.
