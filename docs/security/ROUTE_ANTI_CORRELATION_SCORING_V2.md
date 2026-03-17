# Route Anti-Correlation Scoring v2

Date: 2026-03-13  
Issue: #186

## Summary

Onion route selection now uses an expanded v2 anti-correlation scorer with:
- operator/jurisdiction/ASN/node overlap weighting;
- exact-route reuse penalty;
- temporal reuse penalty biased toward recent routes;
- optional max-score rejection threshold.

## v2 Controls

- Route candidate pool respects `route_attempts` cap.
- `REDOOR_MIXNET_MAX_CORRELATION_SCORE` (optional):
  - rejects candidate routes whose score exceeds configured maximum.
- Diversity policy constraints remain enforced:
  - minimum unique operators;
  - minimum unique jurisdictions;
  - minimum unique ASNs.

## Reject Reasons and Telemetry Counters

Router telemetry now tracks:
- diversity-policy reject count;
- correlation-threshold reject count;
- empty-topology reject count;
- last reject reason.

Diagnostics report now exposes:
- temporal reuse penalty for last selected route;
- reject counters and last reject reason for monitoring/alerting.

## Regression Coverage

Added/updated tests cover:
- repeated-path suppression preference over infrastructure reuse;
- diversity failure counter updates;
- correlation-threshold reject behavior;
- telemetry content for v2 scoring.
