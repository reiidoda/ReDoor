# PQ Ratchet Evolution and Forced Rekey (Production Baseline)

Date: 2026-03-13  
Issue: #198  
Milestone: M26 - Security Hardening Program v2

## Objective

Upgrade the post-quantum posture from handshake-only compatibility to a production baseline with:
- explicit protocol-version compatibility gates;
- forced rekey policy for stale/at-risk sessions;
- lifecycle and compromise-signal rekey triggers;
- diagnostics and rollout controls.

## Security Invariants

1. No silent downgrade below the configured minimum protocol version.
2. Sessions cannot remain active indefinitely after policy thresholds are hit.
3. Rekey state transitions are explicit and observable.
4. Send/poll paths fail closed when forced rekey is pending.
5. No key material is exposed in diagnostics.

## Design Overview

Implemented modules:
- `client/src/config.rs`
- `client/src/crypto/x3dh.rs`
- `client/src/engine.rs`
- `client/src/service.rs`
- `client/src/diagnostics.rs`
- `client/src/ffi.rs`
- `RedoorApp/RedoorApp/Core/redoor.h`
- `RedoorApp/RedoorApp/Core/RedoorFFI.swift`

### Protocol Versioning

- Handshake payload (`InitialMessage`) includes `protocol_version`.
- Transcript context binds `protocol_version` to KDF input.
- Responder enforces:
  - reject `incoming_version < protocol_min_accepted_version`;
  - reject `incoming_version > protocol_version_current`;
  - legacy fallback (`None`) treated as version `1`.

### Session Rekey State Machine

Per peer, runtime tracks:
- established/rekey timestamps;
- messages since rekey;
- negotiated protocol version;
- pending rekey flag + reason.

Rekey-trigger reasons:
- `protocol_version_rejected`
- `protocol_version_transition`
- `rekey_time_window_elapsed`
- `rekey_message_budget_exhausted`
- lifecycle and manual compromise indicators (`lifecycle_*`, `compromise_indicator_manual`)

Enforcement behavior:
- if pending rekey exists, `send_payload` blocks fail-closed;
- poll path drops/deprioritizes traffic on sessions requiring rekey;
- lifecycle transitions and compromise signals mark session(s) rekey-pending.

### Policy Configuration

Configurable defaults and overrides:
- `protocol_version_current`
- `protocol_min_accepted_version`
- `forced_rekey_after_messages`
- `forced_rekey_after_secs`
- `pq_ratchet_interval_messages`

## Observability

Diagnostics now expose only non-secret health signals:
- active/pending session counts for rekey;
- forced rekey event counters;
- last forced rekey reason;
- protocol/rekey policy values.

## Rollout Plan

1. Ship with `protocol_min_accepted_version=1` (legacy interop still allowed).
2. Observe rekey diagnostics and compatibility failures in staging.
3. Increase `protocol_min_accepted_version` only after interop confidence.
4. Tighten time/message rekey thresholds progressively by environment.

## Rollback Plan

If compatibility regression is detected:
1. Lower `protocol_min_accepted_version` to restore interoperability.
2. Keep rekey enforcement active (do not disable forced rekey boundary).
3. Capture diagnostics snapshot and open regression issue.
4. Re-run version/policy matrix tests before re-raising minimum.

## Tests Added and Required

Protocol/version interop and downgrade checks:
- `crypto::x3dh::tests::protocol_version_is_tagged_on_new_handshake`
- `crypto::x3dh::tests::responder_rejects_protocol_version_below_minimum`
- `crypto::x3dh::tests::legacy_protocol_is_allowed_when_minimum_is_legacy`
- `crypto::x3dh::tests::protocol_version_interop_matrix_enforces_compatibility`
- `crypto::x3dh::tests::handshake_policy_matrix_interop`
- `crypto::x3dh::tests::required_policy_rejects_downgraded_hybrid_message`

Forced rekey policy and transition checks:
- `engine::tests::session_rekey_policy_marks_message_budget_exhaustion`
- `engine::tests::session_rekey_policy_marks_protocol_transition`
- `engine::tests::session_rekey_property_pending_state_is_sticky_after_trigger`
- `engine::tests::send_payload_blocks_when_forced_rekey_is_pending`
- `service::tests::test_background_immediate_marks_sessions_for_rekey`
- `service::tests::test_foreground_signal_marks_sessions_for_rekey`
- `ffi::tests::test_compromise_indicator_marks_target_and_all_sessions_for_rekey`

## Residual Risks

- This baseline adds enforceable rekey policy, but does not yet provide full production triple-ratchet formal proof.
- Metadata correlation defenses remain tracked in `#199`.
- External cryptographic assurance cadence remains tracked in `#203`.
