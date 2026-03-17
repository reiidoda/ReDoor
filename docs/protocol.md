# Redoor Protocol Notes

This document describes the currently implemented wire-level behavior and cryptographic flow.

## 1. Identity and Session Bootstrap

- Client identity: Ed25519 keypair generated in runtime (`initialize_keys`).
- Session bootstrap: X3DH-style prekey flow, then Double Ratchet state.
- Handshake negotiation mode is explicitly encoded in `InitialMessage.handshake_mode`:
  - `classic`
  - `hybrid_kyber1024` (when PQ is active and negotiated)
- PQ handshake policy is runtime-configurable:
  - `REDOOR_PQ_HANDSHAKE_POLICY=prefer` (default)
  - `REDOOR_PQ_HANDSHAKE_POLICY=required` (fail closed if hybrid handshake is unavailable)
  - `REDOOR_PQ_HANDSHAKE_POLICY=disabled` (reject hybrid handshakes)
- handshake KDF transcript is bound to:
  - negotiated mode (`classic` / `hybrid_kyber1024`)
  - one-time prekey usage bit
  - PQ contribution usage bit
- Session state is keyed by peer identity hex.

High-level session path:
1. Generate identity + prekeys.
2. Resolve peer identity via directory and fetch prekey bundle via directory TTL storage.
3. Create session (`RatchetSession`) and persist in runtime memory.
4. Use ratchet per message.

## 2. Message Payload Model

### Inner Payload (`InnerPayload`)
Serialized before ratchet encryption:

- `sender_id: String`
- `content: String`
- `msg_type: String`
- `signature: Vec<u8>`
- `group_id: Option<String>`
- `counter: u32`
- `commitment_nonce: u64`

Message signature policy (chat payload path):
- `signature` is optional metadata and is unset in deniable default operation.
- Message acceptance/authenticity relies on ratchet-layer AEAD session state.
- Optional non-deniable interop mode exists only for controlled testing:
  - `REDOOR_MESSAGE_SIGNATURE_POLICY=enforce` (also accepts `required`/`strict`)
  - if enabled, scripted loopback requires valid per-message signature verification.
- Control-plane signatures (directory/relay scoped auth/delegated commitment) remain mandatory.
- Decision record: `docs/security/DENIABILITY_SIGNATURE_DECISION.md`

### Envelope (`Envelope`)
Serialized and sent over transport:

- `mailbox_id: String`
- `sender_id: String`
- `timestamp: u64`
- `ciphertext: Vec<u8>`
- `pow_nonce: u64`

`msg_id` used at transport level is `hex(blake3(envelope_bytes))`.

## 3. Transport Behavior

### Relay Mode
- `POST /relay`
  - Headers include `X-Message-ID`, `X-Receiver-ID`.
  - Optional HMAC headers: `X-HMAC`, `X-HMAC-Timestamp`, `X-HMAC-Nonce`.
- `POST /auth/register`
  - Optional JSON body: `{ "blind_nonce_b64": "<base64-random>" }`.
  - Issues short-lived anonymous scoped credentials.
- `POST /auth/refresh`
  - Requires valid scoped-token auth headers.
  - Rotates scoped credential and returns fresh credential tuple.
- `GET /fetch_pending?receiver=<blinded_receiver>`
  - Returns normalized envelope `{ envelope, receiver, hit, id, blob_base64, pad_base64? }`.
- `POST /fetch_pending_batch`
  - Authenticated body `{ "receivers": ["<handle>", ...] }`.
  - Returns normalized envelope `{ envelope, results: [{ receiver, hit, id?, blob_base64? }], pad_base64? }`.
- `GET /fetch?id=<message_id>` for direct ID retrieval.
- `GET /metrics/abuse`
  - Returns relay abuse counters (`requests_allowed`, `denied`, throttle/challenge metrics).

#### Anonymous Scoped-Token Auth (v1)

Scoped authentication uses a signed token plus per-request MAC instead of linkable long-lived client identifiers.

Register response fields:
- `scoped_token`: base64-encoded claims payload (`v`, `tid`, `exp`, `gen`, optional `bh`).
- `scoped_token_sig_b64`: relay signature over `scoped_token` with generation-scoped signing key.
- `token_secret_b64`: shared request-signing secret.
- `token_fingerprint`: `sha256(scoped_token + "." + scoped_token_sig_b64)` (used as request MAC identity).
- `expires_at`, `credential_version`, optional `blind_hash`.

Scoped request headers:
- `X-Scoped-Token`
- `X-Scoped-Token-Signature`
- `X-Scoped-Request-Signature`
- `X-Scoped-Timestamp`
- `X-Scoped-Nonce`

Canonical request-signature input:
- newline-joined fields:
  - `timestamp`
  - `nonce`
  - `token_fingerprint`
  - `METHOD` (uppercase)
  - request path
  - message ID (if present)
  - receiver ID (if present)
  - `hex(sha256(body))`

Replay protection:
- relay enforces timestamp window + nonce uniqueness per token scope (`scoped:<token_fingerprint>`).
- replayed nonce/timestamp tuples are rejected.

Compatibility:
- legacy scoped headers (`X-Client-ID`, `X-Client-Signature`, `X-Client-Timestamp`, `X-Client-Nonce`) are still accepted during migration.

Receiver IDs are blinded client-side before relay calls.

Rotating mailbox handles (address privacy):
- clients derive epoch-scoped mailbox handles (`mb1_<epoch>_<sha256(...)>`) instead of stable blinded receiver IDs;
- sender and receiver rotate automatically with wall-clock epochs (no manual user action);
- receiver fetch attempts current + recent epochs and includes a legacy static-blind fallback during migration.
- in batch mode, receivers can fetch multiple handles in one request and include decoy handles to reduce mailbox-interest linkability.

Relay mailbox-handle policy:
- validates rotating mailbox epoch bounds on both `/relay` and `/fetch_pending`;
- rejects stale/future-out-of-window handles;
- supports temporary legacy static-handle migration window with configurable sunset.

Mailbox rotation knobs:
- `RELAY_MAILBOX_EPOCH_SEC`
- `RELAY_MAILBOX_ACCEPT_PAST_EPOCHS`
- `RELAY_MAILBOX_ACCEPT_FUTURE_EPOCHS`
- `RELAY_MAILBOX_ALLOW_LEGACY`
- `RELAY_MAILBOX_LEGACY_UNTIL_UNIX`
- client-side fetch migration: `RELAY_MAILBOX_FETCH_PAST_EPOCHS`, `RELAY_MAILBOX_FETCH_LEGACY_FALLBACK`
- relay batch window size: `RELAY_FETCH_PENDING_BATCH_MAX_RECEIVERS`
- client batch/decoy controls:
  - `REDOOR_MAILBOX_BATCH_FETCH`
  - `REDOOR_MAILBOX_BATCH_MAX_HANDLES`
  - `REDOOR_MAILBOX_DECOY_FETCH_COUNT`
  - multi-relay split retrieval:
    - `REDOOR_FETCH_PENDING_MIRRORS` (CSV or JSON list of mirror relay URLs)
    - `REDOOR_FETCH_PENDING_MIRROR_MAX` (default: `2`, max: `8`)
    - `REDOOR_FETCH_PENDING_RELAY_QUORUM` (default: `1`, max: `8`)

Multi-relay split retrieval policy:
- client fans out `/fetch_pending` in parallel to primary + configured mirrors.
- duplicate pending hits are merged by message id with deterministic tie-break:
  - highest relay confirmation count first;
  - then lexicographically smallest relay URL;
  - then lexicographically smallest message id.
- selected hit must satisfy `REDOOR_FETCH_PENDING_RELAY_QUORUM`.
- partial outage behavior:
  - if at least one relay returns a clean miss and no hit reaches quorum, client reports miss (not hard-fail);
  - if all relays fail, client returns the last relay error;
  - if hits exist but quorum is not met, client returns quorum-not-met error.

Relay abuse hardening:
- anonymous spend-unit and per-receiver pressure budgets are enforced in addition to per-IP fallback;
- spend-unit buckets rotate in short windows to reduce long-lived linkage while preserving abuse control;
- optional issuer-generation budgets can throttle distributed token churn from a single active credential generation;
- overload can trigger adaptive challenge mode (PoW-like) with response headers:
  - `X-Abuse-Challenge-Difficulty`
  - `X-Abuse-Challenge-Window-Sec`
  - `X-Abuse-Challenge-Reasons`

Relay abuse governance knobs:
- `RELAY_ABUSE_BUCKET_MODE`:
  - `anonymous_spend_unit` (default)
  - `dual_enforce` (staged migration; enforces anonymous + legacy buckets)
  - `legacy_client` (rollback mode)
- `RELAY_ABUSE_SPEND_UNIT_WINDOW_SEC`
- `RELAY_CLIENT_RPS` / `RELAY_CLIENT_BURST`
- `RELAY_RECEIVER_RPS` / `RELAY_RECEIVER_BURST`
- `RELAY_ISSUER_RPS` / `RELAY_ISSUER_BURST` (optional, disabled if unset)

Transport normalization profile (relay client):
- default behavior normalizes HTTP transport shape:
  - deterministic header set/order (`User-Agent`, `Accept`, `Accept-Encoding`, `Cache-Control`, `Pragma`, `Connection`)
  - `Accept-Encoding: identity`
  - connection pooling disabled (`pool_max_idle_per_host=0`)
  - HTTP/1.1-only mode for ALPN normalization (where feasible in reqwest/rustls)
- policy knobs:
  - `REDOOR_TRANSPORT_NORMALIZATION` (`1` default)
  - `REDOOR_TRANSPORT_USER_AGENT` (default: `redoor-relay-client/1.0`)
  - `REDOOR_TRANSPORT_CONNECTION_MODE` (`close` default, or `keep-alive`)
  - `REDOOR_TRANSPORT_FORCE_HTTP1` (`1` default)

#### Fixed-Size Transport Cells (secure profile compatible)
When client traffic shaping `pad_to > 0`, relay payloads are encoded as:
- `[4-byte big-endian payload length][payload][zero padding]`
- total wire size is always exactly `pad_to` bytes.

Client behavior:
- outbound relay payloads are normalized to this cell format;
- inbound relay payloads are decoded from this cell format;
- malformed/oversized cells are rejected locally.

Relay behavior (when `RELAY_FIXED_CELL_BYTES > 0`):
- accepts only exact-size cells (`len == RELAY_FIXED_CELL_BYTES`);
- rejects malformed length prefixes and non-zero trailing padding;
- stores/returns validated cells unchanged so on-wire size shape stays normalized.

### Onion / Mix Path
When enabled and strict anonymity is active:
- sender must route via onion path
- non-onion and p2p sends are rejected by policy
- user-originated payloads are queued and released only by the constant-rate sender tick (no direct burst sends)
- fixed relay polling is enforced even when callers request `interval_ms=0`
- constant-rate sender loop is enforced even when callers request `interval_ms=0`
- if no real outbound message is queued at a tick, a cover payload is emitted
- bounded jitter applies to both loops with policy cap (`REDOOR_SECURE_JITTER_PCT`, capped to 10%)
- strict-mode jitter also honors an absolute budget cap (`REDOOR_SECURE_JITTER_BUDGET_MS`) to bound UX impact
- strict-mode loops apply periodic phase-window re-randomization to reduce long-lived cadence alignment
- secure profile enforces fixed-size transport cells (`pad_to=4096`) if no explicit shaping is configured.

Relay diversity policy (secure mode):
- mix nodes support optional metadata tags: `operator`, `jurisdiction`, and `asn`.
- strict mode enforces route diversity minima (at least 2 unique operators, 2 unique jurisdictions, and 2 unique ASNs by default).
- route builder applies anti-correlation scoring against recent route memory and penalizes overlap across operator/jurisdiction/ASN/node reuse.
- among policy-compliant candidates with equal feasibility, lower correlation-score paths are preferred deterministically.
- if no route satisfies policy, client logs a mix route policy violation and exposes counters through diagnostics/traffic stats.
- diagnostics now include last selected route-correlation telemetry:
  - `route_last_correlation_score`
  - `route_last_correlation_operator_overlap`
  - `route_last_correlation_jurisdiction_overlap`
  - `route_last_correlation_asn_overlap`
  - `route_last_correlation_node_overlap`
  - `route_last_correlation_exact_route_reuse`

FFI controls:
- `redoor_configure_mixnet_diversity_policy(min_unique_operators, min_unique_jurisdictions, route_attempts)`
- `redoor_configure_mixnet_as_diversity_policy(min_unique_asns)`

Sphinx-like packet format (mixnet core):
- transport receiver header is fixed to `__mix__`; final receiver identity is encrypted end-to-end in hop payload.
- packet wire format: `\"MXP1\" || tag(16) || ephemeral_pub(32) || nonce(12) || ciphertext`.
- each hop decrypts one route layer, learns only the immediate next hop, and rewraps the nested packet with a fresh packet tag and fresh ephemeral transform.
- each relay hop enforces replay rejection on packet tags (per-hop replay cache).
- each relay can apply bounded random per-hop forwarding delay and optional batch-window forwarding (queue + timed flush) for timing-correlation resistance.
- mix forwarding metrics are exposed at `GET /metrics/mix` with queue depth, batch flush counters, and queue-delay averages.

Relay mix-forward policy knobs:
- `RELAY_MIX_HOP_DELAY_MIN_MS` / `RELAY_MIX_HOP_DELAY_MAX_MS`
- `RELAY_MIX_BATCH_WINDOW_MS`
- `RELAY_MIX_BATCH_MAX`
- `RELAY_MIX_BATCH_QUEUE_CAPACITY`
- `RELAY_MIX_FORWARD_TIMEOUT_MS`

Relay-generated chaff (relay-to-relay):
- relays can emit independent chaff traffic into the mix pipeline, ending at final receiver `__cover__`.
- chaff emission is budget-capped to avoid self-induced DoS and shares the same mix forwarding safeguards.
- chaff metrics are exposed at `GET /metrics/chaff` (`generated`, `forwarded`, `budget_throttled`, failures, and config snapshot).

Relay chaff policy knobs:
- `RELAY_CHAFF_ENABLED` (`1` to enable)
- `RELAY_CHAFF_PEERS` (JSON list or CSV `url|pubkey_hex`)
- `RELAY_CHAFF_INTERVAL_MIN_MS` / `RELAY_CHAFF_INTERVAL_MAX_MS`
- `RELAY_CHAFF_PAYLOAD_MIN_BYTES` / `RELAY_CHAFF_PAYLOAD_MAX_BYTES`
- `RELAY_CHAFF_PATH_MIN_HOPS` / `RELAY_CHAFF_PATH_MAX_HOPS`
- `RELAY_CHAFF_BUDGET_PER_MIN`
- `RELAY_CHAFF_FORWARD_TIMEOUT_MS`

Secure profile defaults:
- `REDOOR_SECURE_FIXED_POLL_MS` (default: `1000`)
- `REDOOR_SECURE_CONSTANT_RATE_MS` (default: `1000`)
- `REDOOR_SECURE_JITTER_PCT` (default: `5`, max `10`)
- `REDOOR_SECURE_JITTER_BUDGET_MS` (default: `120`, max `400`)
- `REDOOR_SECURE_PHASE_OFFSET_PCT` (default: `35`, max `90`) one-time startup phase randomization to reduce synchronized polling/send cadence across clients.
- `REDOOR_SECURE_PHASE_WINDOW_TICKS` (default: `16`, max `256`) cadence for periodic phase-window shifts.
- `REDOOR_SECURE_PHASE_WINDOW_PCT` (default: `20`, max `50`) max per-window shift as interval percentage.

### P2P Mode
Supported in runtime API but policy-dependent and not the default secure path.

## 4. Blockchain Evidence Path

Client submits hash-only evidence to blockchain (`/tx`):

- `signer_id` (alias `sender_id`)
- `message_hash`
- `signature`
- `timestamp`
- `receiver_commitment` (alias `receiver_id`)
- optional `pq_pub_b64`, `pq_sig_b64`

Verification signs over:
`timestamp || signer_id || receiver_commitment || message_hash`

The ledger stores message-hash payloads and block linkage metadata.

### Delegated Commitment Submission (Optional)
- Client can route commitment submission through a delegated submitter endpoint:
  - `POST /delegate/commitment`
- Request fields:
  - `origin_signer_id`
  - `message_hash`
  - `origin_signature`
  - `timestamp`
  - `receiver_commitment`
  - `auth_threshold` (optional, default `1`)
  - `co_signatures[]` (`signer_id`, `signature`) optional
- Delegated signature payload:
  - `timestamp || origin_signer_id || receiver_commitment || message_hash || auth_threshold`
- Effective authorization threshold:
  - `max(BLOCKCHAIN_DELEGATE_AUTH_THRESHOLD, auth_threshold)`
- Optional blockchain-node policy controls:
  - `BLOCKCHAIN_DELEGATE_AUTH_THRESHOLD`
  - `BLOCKCHAIN_DELEGATE_ALLOWED_SIGNERS` (comma-separated pubkey hex)
  - `BLOCKCHAIN_DELEGATE_MAX_COSIGNERS`
  - `BLOCKCHAIN_DELEGATE_MAX_BODY_BYTES`

Client-side delegation controls:
- `REDOOR_COMMITMENT_DELEGATE_URL`
- `REDOOR_COMMITMENT_DELEGATE_REQUIRED` (fail-closed if delegate unavailable)
- `REDOOR_COMMITMENT_AUTH_THRESHOLD`
- `REDOOR_COMMITMENT_COSIGNER_SECRETS_HEX` (comma-separated 32-byte Ed25519 secret key hex)

### Secure Default Batching
- In strict anonymity profile, blockchain submission defaults to Merkle-batched commitments.
- Client queues per-message hashes in RAM, computes a Merkle root per window, and submits only the root on-chain.
- Batch flush scheduling uses randomized delay around the base interval to reduce timing-correlation leakage.
- Optional protocol-valid decoy commitments are submitted alongside each real Merkle root.
- Per-message inclusion proofs are retained in volatile memory and can be queried through FFI (`redoor_get_commitment_inclusion_proof`).
- Compatibility fallback: set `REDOOR_BLOCKCHAIN_PER_MESSAGE_FALLBACK=1` to force legacy per-message submissions.

Batching controls:
- `REDOOR_SECURE_BLOCKCHAIN_BATCH_MS` (default: `5000`)
- `REDOOR_SECURE_BLOCKCHAIN_BATCH_JITTER_PCT` (default: `35`, clamped to `<=200`)
- `REDOOR_SECURE_BLOCKCHAIN_BATCH_DECOY_COUNT` (default: `0`, max `32`)
- `REDOOR_SECURE_BLOCKCHAIN_BATCH_SEED` (optional deterministic scheduler seed for test/replay)
- `REDOOR_BLOCKCHAIN_PER_MESSAGE_FALLBACK` (default: disabled)

## 5. Directory Protocol

Directory endpoints:
- `POST /publish`
- `GET /query/:id`
- `GET /resolve?username=...`
- `POST /prekey/publish` (TTL-bounded prekey bundle write)
- `GET /prekey/query/:id` (prekey bundle read if not expired)

Username ownership semantics:
- records carry signed `seq` and `expires_at` metadata;
- first claim must start at `seq=1`;
- updates require same owner key + strictly monotonic `seq`;
- expired leases are removed from read paths, and stale/replay updates are rejected.

Prekey retention semantics:
- prekey bundles are no longer distributed through relay persistent blob paths;
- directory prekey records carry explicit TTL and are evicted on expiry;
- relay keeps fetch-once transient message transport only.
- runtime policy can be set through FFI:
  - `redoor_set_pq_handshake_policy("prefer"|"required"|"disabled")`
- migration playbook:
  - `docs/security/PQ_HANDSHAKE_MIGRATION_NOTES.md`

Resolve responses are signed with directory signing key and include:
- `public_key`
- `signature`
- `key_id`
- `issued_at`

## 6. Lifecycle / Wipe Semantics

- iOS app locks/wipes on background, resign active, and terminate notifications.
- Duress mode wipes runtime state and transitions app to locked mode.
- Fetch-once semantics for normal relay blobs reduce residual message footprint.
- In secure mode (`REDOOR_SECURE_MODE=1`), runtime init fails closed if memory locking
  hardening (`mlockall`) cannot be enabled.
- In non-secure/dev mode, init can continue but diagnostics expose degraded
  `memory_hardening_*` flags.

## 7. Diagnostics and Regression APIs

Selected FFI diagnostics:
- `redoor_run_diagnostics`
- `redoor_benchmark_crypto`
- `redoor_get_storage_usage`
- `redoor_benchmark_memory_budget`
- `redoor_benchmark_traffic_linkability(seed)` (deterministic seeded traffic-analysis simulation report)
- `redoor_get_traffic_stats` (real/cover counts, queued real messages, send/poll tick counters, and tick failure counters)
- `redoor_get_blockchain_batch_telemetry` (scheduler delay, drift, decoy submissions, and recent batch observations)

These APIs are used by CI regression gates and iOS instrumentation.

Anonymity regression gate:
- CI runner generates:
  - `client/artifacts/anonymity/traffic-linkability-report.json`
  - `client/artifacts/anonymity/traffic-linkability-evaluation.json`
- report is compared against versioned baseline thresholds:
  - `docs/security/traffic-linkability-baseline.v1.json`
- gate fails when linkability worsens beyond tolerance, unless explicit emergency override is enabled in CI policy.
- simulator report also includes phase-synchronization metrics (`baseline_pair_sync_ratio`, `hardened_pair_sync_ratio`, `improvement_ratio`) to track cadence de-alignment impact.
