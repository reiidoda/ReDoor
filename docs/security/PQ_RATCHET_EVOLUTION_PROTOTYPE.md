# PQ Ratchet Evolution Prototype

Date: 2026-03-12  
Issue: #163  
Artifact: `docs/security/pq-ratchet-evolution-report.v1.json`

## Objective

Prototype a post-handshake PQ contribution schedule that reduces post-compromise persistence
window without replacing the existing double-ratchet flow in production yet.

## Prototype Model

Implemented in:
- `client/src/ratchet/pq_evolution.rs`
- `client/src/bin/pq_ratchet_evolution_prototype.rs`

Model behavior:
1. Classical per-message ratchet step always runs.
2. Additional PQ contribution is mixed every `pq_interval` steps.
3. KDF context is separated for classical and PQ mixes.
4. Compromise simulation snapshots state at selected steps and measures how quickly attacker
   key predictions diverge after compromise (without future PQ secret access).

## Benchmark Snapshot (v1)

Seed: `0xA11CE11D16300001`  
Total simulated steps per sample: `4096`

| PQ Interval | Avg Recovery Steps | P95 Recovery Steps | Max Recovery Steps | State Bytes | Overhead vs Baseline |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 | 3.375 | 4 | 4 | 72 | +8 |
| 8 | 6.875 | 8 | 8 | 72 | +8 |
| 16 | 12.875 | 16 | 16 | 72 | +8 |
| 24 | 11.875 | 24 | 24 | 72 | +8 |
| 32 | 26.875 | 32 | 32 | 72 | +8 |
| 48 | 26.875 | 48 | 48 | 72 | +8 |
| 64 | 50.875 | 64 | 64 | 72 | +8 |

## Recommendation

Prototype recommendation:
- start staged rollout experiments with `pq_interval=16`;
- keep it behind an explicit profile flag (not forced for all clients yet);
- require telemetry + interop soak + external cryptography review before production default.

Rationale:
- `pq_interval=16` keeps P95 recovery at 16 steps while reducing PQ mix frequency compared to
  tighter intervals (`4`/`8`).
- state overhead is low (+8 bytes over baseline prototype state model).

## Threat-Model Delta

Compared to handshake-only PQ:
- attacker value from one-time state compromise decays after the next scheduled PQ mix;
- tighter schedule lowers compromise persistence window;
- looser schedule improves cost profile but prolongs recovery.

Residual risks:
- endpoint compromise still exposes plaintext after decryption;
- metadata correlation remains out of scope for this control;
- this prototype is not yet a formal triple-ratchet proof.

## Regeneration

```bash
./scripts/generate-pq-ratchet-evolution-report.sh
```

or:

```bash
make pq-ratchet-evolution
```
