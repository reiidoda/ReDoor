# PIR/Proxy Mailbox Retrieval Feasibility Spike

Date: 2026-03-12  
Issue: #156

## Objective

Evaluate PIR/proxy retrieval trade-offs for stronger receiver privacy, compared to the current multi-relay split retrieval path.

## Method

- Deterministic benchmark tool: `client/src/bin/pir_proxy_feasibility.rs`
- Seed: `0x50A75EED2026`
- Samples: `10,000`
- Output artifact: `docs/security/pir-proxy-feasibility-report.v1.json`

The benchmark models three strategies:
- `baseline_split_retrieval` (current production path)
- `proxy_fanout_retrieval` (single privacy proxy with relay fanout)
- `two_server_pir_proxy` (research-only two-server PIR-style candidate)

## Benchmark Summary

| Strategy | Availability | p95 Latency (ms) | Client Downlink (KiB/fetch) | Infra CPU (ms/fetch) | Endpoint Exposure | Receiver-Interest Exposure |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline_split_retrieval | 1.000 | 1300.0 | 2.168 | 8.7 | 1.00 | 1.00 |
| proxy_fanout_retrieval | 0.986 | 1345.0 | 0.771 | 16.0 | 0.52 | 0.64 |
| two_server_pir_proxy | 0.930 | 1520.0 | 10.801 | 58.0 | 0.44 | 0.27 |

Interpretation:
- Proxy fanout materially reduces direct endpoint leakage to relays.
- PIR-style retrieval further reduces receiver-interest leakage but is currently too costly for always-on mobile polling.

## Threat-Model Delta

### Baseline (current)
- No additional trust domain beyond independent relays.
- Endpoint metadata remains directly visible at each queried relay.

### Proxy fanout candidate
- New trust concentration point (privacy proxy) can re-link endpoint identity with receiver interest if compromised.
- Relay-side metadata exposure decreases because relays primarily see proxy-origin traffic.

### Two-server PIR candidate
- Strongest receiver-interest privacy only under non-colluding-server assumption.
- Operational blast radius increases due to higher compute load and lower effective availability tolerance.

## Decision Proposal

Decision: **NO-GO** for mandatory PIR/proxy rollout in production now.  
Conditional **GO** for optional research profile behind explicit operator flag.

Reasons:
- PIR candidate currently adds substantial latency/cost overhead and lowers availability under outage assumptions.
- Proxy candidate improves metadata resistance but introduces a high-value trust concentration component that must be independently audited first.

Production gate to revisit PIR/proxy default:
- p95 latency increase <= 35% versus baseline
- infra CPU <= 3x baseline
- no single proxy trust concentration without verifiable no-log and jurisdiction-split controls
- external audit sign-off on privacy and abuse-resistance controls

## How to Regenerate

```bash
./scripts/generate-pir-proxy-feasibility-report.sh
```

