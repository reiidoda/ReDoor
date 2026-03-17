# Deniability Signature Decision Record

Date: 2026-03-12  
Issue: #161  
Status: Accepted

## Objective

Reduce transcript non-repudiation risk by constraining globally verifiable per-message
signatures in chat payload paths, while preserving authenticated delivery.

## Audit Scope

Audited locations:
- `client/src/engine.rs` (`InnerPayload.signature` handling)
- `client/src/api.rs` scripted loopback envelope verification path
- `client/src/orchestrator.rs` delegated blockchain commitment signatures
- `client/src/network/directory.rs` directory response signature verification
- `docs/protocol.md` signature semantics

## Findings

1. Message authenticity for chat delivery is provided by session-bound ratchet AEAD.
2. Per-message signature field exists in `InnerPayload`/loopback envelope but is not required
   for normal delivery.
3. Control-plane signatures (directory/auth/delegated commitment) are not transcript signatures
   and must remain mandatory.

## Decision

1. Deniable mode remains the default.
2. Chat delivery does not require a per-message long-term signature.
3. Scripted loopback now ignores per-message signatures by default and only enforces them when
   `REDOOR_MESSAGE_SIGNATURE_POLICY=enforce` (or `required`/`strict`) is explicitly set.
4. Control-plane signatures remain required:
   - directory resolve response signatures;
   - relay scoped-token/request signatures;
   - delegated blockchain commitment signatures.

## Security Tradeoff

- Benefit: reduced transcript non-repudiation and lower risk that exported transcript artifacts
  become globally verifiable identity statements.
- Cost: explicit signature-based non-repudiation is unavailable in default mode.
- Mitigation: optional enforcement mode is available for controlled test/interop scenarios.

## Test Evidence

Unit tests in `client/src/api.rs` cover:
- deniable default accepts missing signature;
- deniable default ignores invalid signature;
- enforce mode rejects missing signature;
- enforce mode accepts valid signature.

## Follow-up

Future work (not in this issue):
- remove legacy signature field from message payload schema in a major protocol version if
  migration impact is acceptable;
- add transcript export labeling that explicitly marks deniable vs enforce-mode sessions.
