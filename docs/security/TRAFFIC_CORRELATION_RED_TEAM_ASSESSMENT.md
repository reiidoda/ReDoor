# Traffic-Correlation Red-Team Assessment

Date: 2026-03-12  
Issue: #165  
Milestone: M25 - Independent Security Assurance

## Objective

Assess current anonymity posture against traffic-correlation attacks and define concrete,
prioritized mitigations with measurable outcomes.

## Inputs and Evidence

- Simulator baseline artifact:
  - `docs/security/traffic-linkability-baseline.v1.json`
- Regression gate:
  - `./scripts/ci-traffic-anonymity-simulator.sh`
- Threat model:
  - `docs/threat_model.md`

## Attacker Models

### T1. Global Passive Correlator (timing observer)
- Sees sender egress timing and receiver ingress timing.
- Uses latency-window matching to infer sender->receiver links.
- Cannot decrypt payload.

### T2. Partial Relay Collusion
- Compromises one or more relays (not all infrastructure).
- Observes mailbox polling cadence and relay-local metadata.
- Attempts to improve correlation confidence over time.

### T3. Active Timing Perturbation Adversary
- Injects bounded delay/jitter on segments to improve matching confidence.
- Attempts to force deterministic timing signatures across sessions.

## Success Metrics

Primary metrics (from `traffic_linkability.v1` baseline):
- weighted top-1 linkability (lower is better);
- unresolved rate (higher can indicate ambiguity but may hide delivery quality issues);
- estimated anonymity set size (higher is better).

Current threshold posture:
- max weighted top-1 linkability: `0.79`
- max weighted top-1 regression delta: `0.025`
- max total unresolved rate: `0.02`
- minimum total delivered real messages: `180`

## Assessment Summary (Current State)

1. Baseline indicates strong relative improvement under mixed/churn scenarios compared to idle/burst.
2. Idle and burst timing still present high correlation potential (expected under low-cover conditions).
3. Current controls are effective for regression detection, but not sufficient to claim robust resistance
   against high-capability global passive observers.

## Live-Test Plan (Independent Exercise)

Phase 1: Lab replay
- Reproduce simulator traffic shape using controlled network taps.
- Validate metric parity with deterministic baseline.

Phase 2: Relay-collusion simulation
- Emulate single-relay and multi-relay observer views.
- Measure linkability lift over baseline.

Phase 3: Active perturbation
- Inject bounded delays and compare matching-confidence changes.
- Evaluate which schedule components are most fingerprintable.

Phase 4: Mitigation A/B
- Re-run phases with mitigation flags enabled.
- Quantify delta per mitigation with same seed/scenario controls.

Deliverables:
- measurement report archived under `docs/security`;
- recommended mitigations ranked by risk-reduction-per-cost;
- follow-up remediation issues and owners.

## Mitigation Backlog (Concrete Issues)

- #184: Bounded schedule jitter hardening.
- #185: Multi-relay quorum blend retrieval.
- #186: Route anti-correlation scoring v2.

## Risk Statement

Current risk posture:
- metadata correlation remains a high residual risk category;
- current anonymity controls are meaningful but not sufficient for strong adversary guarantees;
- mitigation work in #184-#186 is required before claiming materially improved correlation resistance.
