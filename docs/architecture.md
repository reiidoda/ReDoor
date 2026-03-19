# Redoor Architecture

## 1. Topology

Redoor is a modular distributed system with five operational planes:

1. Client cryptographic runtime (`client/`, Rust)
2. iOS application layer (`RedoorApp/`, Swift)
3. Relay transport plane (`relay-node/`, Go)
4. Tamper-evidence plane (`blockchain-node/`, Rust)
5. Discovery plane (`directory-dht/`, Rust)

The repository is a monorepo, but runtime deployment is service-oriented.

## 2. Component Responsibilities

### Client Runtime (`client/`)
- Maintains identity, prekeys, and ratchet sessions in memory.
- Negotiates classical/PQ hybrid handshake modes with explicit downgrade-resistant signaling.
- Builds encrypted envelopes (`InnerPayload` -> `Envelope`).
- Sends via relay/onion/p2p policy paths.
- Emits FFI APIs consumed by iOS.
- Provides diagnostics including memory-budget and traffic-linkability reports.

Key modules:
- `engine.rs`: state model and send/poll behavior
- `service.rs`: wipe/duress/cover-traffic/background policies
- `network/relay.rs`: TLS, HMAC, rotating mailbox handles, decoy/batch fetch, optional mirror fetch splitting
- `ffi.rs`: C ABI surface for mobile embedding

### iOS App (`RedoorApp/`)
- SwiftUI features for setup/chat/settings.
- Enforces secure network config validation before FFI calls.
- Requires onion node configuration (>=3) for secure operation.
- Wipes session state on background/resign/terminate and duress.
- Uses volatile in-memory secure storage (`SecureStorage`) only.

### Relay Node (`relay-node/`)
- Accepts TLS connections only (`RELAY_CERT_FILE`, `RELAY_KEY_FILE`).
- Validates optional HMAC signatures with anti-replay controls.
- Stores normal blobs in memory and removes on fetch.
- Supports anonymous scoped-token auth and spend-unit abuse governance.
- Applies per-IP + spend-unit rate limits and payload/receiver quotas.
- Supports rotating mailbox-handle validation and batch retrieval APIs.

### Blockchain Node (`blockchain-node/`)
- Accepts transaction payloads (`/tx`) and signed blocks (`/signed_block`).
- Verifies Ed25519 signatures and receiver commitments.
- Stores chain state on disk (`blockchain.json`) for integrity history.
- Exposes metrics and admin endpoints with token/rate limits.
- Supports delegated commitment submission with threshold policy controls.

### Directory Service (`directory-dht/`)
- HTTP facade for publish/query/resolve key records.
- Signed resolve responses using `DIR_SIGNING_KEY_HEX`.
- Optional publish token (`DIR_TOKEN`) and TLS requirement.
- Sequence/lease ownership semantics and TTL prekey publication.
- Abuse controls (`DIR_RPS`, `DIR_BURST`, `DIR_MAX_BODY_BYTES`).

## 3. End-to-End Data Path

1. Sender app prepares plaintext in memory.
2. Client runtime ratchets state, encrypts, and wraps payload.
3. Relay receives opaque blob and queues by rotating mailbox handle.
4. Receiver polls relay, decrypts in-memory, and consumes message.
   Receiver may split pending-fetch attempts across mirrored relays to reduce single-relay visibility.
5. Client best-effort submits message hash commitment to blockchain.
6. Directory assists key discovery/bootstrap, not message transport.

## 4. Security Boundaries

- **Device boundary**: plaintext and keys should remain in RAM only.
- **Relay boundary**: relay is untrusted for content; sees opaque blobs and timing.
- **Mix metadata boundary**: route policy enforces operator/jurisdiction/ASN diversity but cannot eliminate all global-correlation risk.
- **Blockchain boundary**: stores hashes/commitments, not plaintext messages.
- **Directory boundary**: serves signed key material; must not be trusted blindly.

## 5. Reliability and Quality Gates

- Security gates workflow: `.github/workflows/security-gates.yml`
- Nightly soak workflow: `.github/workflows/reliability-nightly.yml`
- Memory regressions: `scripts/ci-memory-regression.sh`
- Anonymity regression gate + artifacts: `scripts/ci-anonymity-regression.sh`
- Realtime soak/reconnect chaos: `scripts/ci-reliability-soak.sh`

## 6. Architectural Constraints

- No global account/identity authority.
- Onion path policy expected for high-security sessions.
- RAM-only policy enforced on Swift sources via CI checks.
- Relay and directory must run with explicit TLS/auth settings for non-local use.

## 7. Open Implementation Work

Project status and remaining implementation work are tracked in the contributor status board:
- `docs/OPEN_SOURCE_STATUS.md`

Contributor entrypoints:
- `docs/OPEN_SOURCE_STATUS.md`
- `CONTRIBUTING.md`
