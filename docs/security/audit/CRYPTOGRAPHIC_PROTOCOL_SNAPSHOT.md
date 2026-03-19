# Cryptographic Protocol Snapshot

Date: 2026-03-12  
Scope version: `audit-snapshot.v1`

## 1. Scope

In scope:
- X3DH-style prekey bootstrap and session establishment.
- Double-ratchet message-key evolution.
- Hybrid PQ handshake policy controls (`prefer`, `required`, `disabled`).
- Optional PQ ratchet evolution prototype (research profile).
- Relay transport protections (TLS, auth, anti-replay).

Out of scope:
- compromised OS kernel/baseband/hardware root;
- coercion against unlocked endpoint;
- internet-scale global passive observer guarantees of perfect unlinkability.

## 2. Security Objectives

1. Confidentiality:
   - message content remains opaque to relay/directory/blockchain operators.
2. Integrity/authenticity:
   - tampering and forged ciphertexts are rejected by authenticated encryption and ratchet state.
3. Forward secrecy:
   - old message keys are not recoverable from current state.
4. Post-compromise recovery:
   - after attacker state capture, future secret evolution should diverge after fresh secret input.
5. Metadata minimization:
   - limit direct sender/receiver linkage via onion/mix pathing, rotating handles, and cover traffic.

## 3. Current Protocol Components

## 3.1 Bootstrap/Session Setup

- Identity and prekey material support asynchronous key agreement.
- Negotiated handshake mode includes explicit PQ posture controls.
- Hybrid transcript binding includes mode and prekey usage bits to reduce downgrade risk.

References:
- `docs/protocol.md`
- `docs/security/PQ_HANDSHAKE_MIGRATION_NOTES.md`

## 3.2 Message Protection

- Double ratchet drives per-message key evolution.
- AEAD envelope protects confidentiality and ciphertext integrity.
- Deniability-default policy avoids mandatory globally verifiable per-message signatures.

References:
- `docs/security/DENIABILITY_SIGNATURE_DECISION.md`

## 3.3 Transport and Relay Controls

- TLS for relay transport in production profile.
- HMAC request authentication and replay windows.
- Strict anonymity mode blocks direct/non-onion sends.
- Rotating receiver mailbox handles and optional multi-relay split retrieval.

## 3.4 Evidence Anchoring

- Blockchain path stores hash commitments, not plaintext.
- Directory path uses signed responses for key/discovery integrity.

## 4. Explicit Assumptions

1. Endpoint device remains uncompromised during message composition/decryption.
2. At least part of the network path remains non-colluding for anonymity controls to add value.
3. Operators monitor and rotate credentials/certs according to runbooks.
4. CI security gates are enforced in release process.

## 5. Known Residual Risks

1. Traffic correlation by high-capability observers remains a top residual risk.
2. Endpoint compromise bypasses transit cryptography.
3. Hash commitment metadata can still leak coarse communication timing patterns.
4. PQ ratchet evolution is currently prototype-level and not default-enabled.

## 6. Audit Questions for External Review

1. Are key derivation boundaries and transcript bindings sufficient against downgrade/cross-protocol confusion?
2. Does current deniability mode avoid accidental non-repudiation leaks?
3. Are replay and sequencing controls complete across relay endpoints?
4. Is post-compromise recovery posture adequate for declared threat model?
5. Do implementation choices match documented assumptions and fail-closed intent?
