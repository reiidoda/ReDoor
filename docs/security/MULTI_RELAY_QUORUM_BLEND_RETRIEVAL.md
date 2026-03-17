# Multi-Relay Quorum Blend Retrieval

Date: 2026-03-12  
Issue: #185

## Summary

Pending mailbox retrieval supports multi-relay fanout with configurable quorum and optional
best-effort fallback behavior.

Key properties:
- random relay query ordering (with deterministic seed override for test reproducibility);
- quorum threshold for accepting a hit across relay responses;
- optional best-effort fallback when quorum is not met.

## Configuration

- `REDOOR_FETCH_PENDING_MIRRORS`:
  - comma-separated or JSON array of mirror relay URLs.
- `REDOOR_FETCH_PENDING_MIRROR_MAX`:
  - cap on number of mirrors included in fanout.
- `REDOOR_FETCH_PENDING_RELAY_QUORUM`:
  - minimum matching confirmations required for strict acceptance.
- `REDOOR_FETCH_PENDING_QUORUM_BEST_EFFORT`:
  - if `true`, returns top-ranked candidate when quorum is not met.
  - default `false` (strict behavior).
- `REDOOR_FETCH_PENDING_SHUFFLE_SEED`:
  - optional deterministic ordering for tests/controlled simulations.

## Security and Availability Tradeoffs

- Higher quorum:
  - improves resistance to partial-relay collusion and inconsistent responses;
  - increases risk of no-result under relay outages.
- Lower quorum:
  - improves availability/latency;
  - weakens confidence against malicious or inconsistent relay subsets.
- Best-effort fallback:
  - improves liveness in degraded environments;
  - should be disabled for high-risk strict profiles where integrity confidence is prioritized.

## Coverage

Unit tests cover:
- deterministic shuffled ordering with seed override;
- quorum enforcement and collusion-resistance behavior;
- fallback-policy behavior when quorum is unmet.
