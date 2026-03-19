# Hybrid PQ Handshake Migration Notes

Date: 2026-03-12  
Issue: #162

## Summary

Redoor now exposes explicit handshake policy control across runtime, FFI, and iOS settings:

- `prefer` (default): use hybrid when available, otherwise classic.
- `required`: fail closed unless handshake mode is `hybrid_kyber1024`.
- `disabled`: force classic and reject hybrid handshakes.

Handshake KDF context is now transcript-bound with:
- negotiated mode (`classic` / `hybrid_kyber1024`);
- one-time prekey usage bit;
- PQ contribution usage bit.

This tightens downgrade resistance and makes mixed-policy behavior explicit.

## Operator Rollout Plan

1. Baseline (`prefer`)
- keep all nodes/clients on `prefer`;
- monitor for peers that still negotiate `classic`.

2. Compatibility Validation
- verify all active peers publish PQ-capable prekey material;
- run interoperability tests in CI and staging before policy changes.

3. Enforce (`required`)
- switch high-risk deployments to `required`;
- keep strict lockdown profile aligned (`Lockdown strict now expects `required` policy).

4. Emergency Rollback
- if interoperability breakage is detected, temporarily set `prefer`;
- file a remediation issue and track unsupported peers until resolved.

## iOS / FFI Controls

- FFI:
  - `redoor_set_pq_handshake_policy(const char *policy)`
- iOS:
  - Settings -> `PQ HANDSHAKE` section (`Prefer Hybrid`, `Require Hybrid`, `Classic Only`)
  - strict lockdown profile reports incompatibility when PQ policy is not `required`.

## CI Coverage

`scripts/ci-rust-quality.sh` now executes:
- `handshake_policy_matrix_interop`
- `required_policy_rejects_downgraded_hybrid_message`

These tests validate policy combinations and downgrade handling.
