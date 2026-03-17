# Domain Model

## 1. Domain Boundaries
Redoor is split into five bounded contexts:

1. Identity and Session
2. Messaging and Transport
3. Relay Delivery
4. Integrity Evidence (Blockchain)
5. Directory and Resolution

## 2. Core Aggregates and Entities

### 2.1 Identity and Session
- `Identity` (entity)
  - Ed25519 identity keypair.
  - Stable per runtime/user session.
- `PrekeySecrets` / Prekey bundle (entity/value object set)
  - Supports X3DH bootstrap.
- `SessionEntry` (entity)
  - Contains ratchet state, handshake status, peer seal key.
  - Keyed by `peer_id`.

Invariants:
- A secure message send requires an existing ratchet session.
- Session material is wiped on lock/duress/background policies.

### 2.2 Messaging and Transport
- `InnerPayload` (value object)
  - Sender ID, content, type, signature, counter, commitment nonce.
- `Envelope` (value object)
  - Mailbox ID, sender ID, timestamp, ciphertext, PoW nonce.
- `StoredMessage` (entity)
  - In-memory user-visible message.

Invariants:
- Plaintext exists only after successful decrypt and before wipe.
- `msg_id` is derived from envelope bytes.
- Receiver identity is blinded before relay transport.

### 2.3 Relay Delivery
- `Blob` (entity in relay)
  - Opaque byte payload + timestamps + persistence flag.
- `EphemeralStore` (aggregate)
  - Message map, receiver index, fetch-once retrieval semantics.
- `RateLimiter` (policy object)
  - Per-IP admission control.

Invariants:
- Non-persistent blobs are deleted after fetch.
- Per-receiver pending queue limits are enforced.
- Optional HMAC replay protection gates accepted requests.

### 2.4 Integrity Evidence (Blockchain)
- `Transaction` (value object)
  - `signer_id`, `message_hash`, `signature`, `timestamp`, `receiver_commitment`.
- `Block` (entity)
  - Index, previous hash, payload hash, signer, signature.
- `Blockchain` (aggregate)
  - Ordered block chain + hash index + validator checks.

Invariants:
- Transaction signature must validate over canonical signed bytes.
- Block link (`previous_hash`) and block signature must verify.
- Stored payload is hash/commitment data, not plaintext messages.

### 2.5 Directory and Resolution
- `PublishReq` (command object)
  - Username, public key, ownership signature, optional token.
- `ResolveResp` (value object)
  - Public key + directory signature + key id + issuance time.
- Directory store entry (entity)
  - `username -> public_key` mapping.

Invariants:
- Username can only be re-published with same public key.
- Resolve responses are signed and verifiable.
- Abuse controls (rate/body/token/TLS policy) are enforced at endpoint boundaries.

### 2.6 Anonymity Validation and Governance
- `TrafficAnalysisSimulationReport` (value object)
  - deterministic seeded scenario metrics (`idle`, `burst`, `mixed_real_chaff`, `relay_churn`).
- `TrafficAnonymityBaseline` (policy object)
  - versioned threshold set for scenario/global linkability metrics.
- `TrafficAnonymityRegressionResult` (decision object)
  - pass/fail + violation reasons for CI security gate decisions.

Invariants:
- baseline/report metric versions must match;
- regression gate fails when thresholds are exceeded unless explicit incident override policy is active;
- gate artifacts are publishable for auditability.

## 3. Domain Events (Implicit)
- IdentityCreated
- SessionEstablished
- MessageSent
- MessageDelivered
- MessageConsumed
- MemoryWiped
- DuressModeEntered
- EvidenceAppended
- DirectoryRecordPublished

## 4. State Transitions

### 4.1 Client Runtime
`Disconnected -> Connected -> SessionReady -> Messaging -> Locked/Wiped`

### 4.2 Relay Blob
`Stored -> Pending -> Fetched -> Deleted` (non-persistent)

### 4.3 Directory Record
`Unpublished -> Published -> Resolved`

## 5. Policy Constraints
- No central account authority in core protocol flow.
- Onion/mix routing expected for high-security sessions.
- Local app/runtime state should remain volatile and wipeable.
- Evidence and directory systems must not become plaintext message stores.

## 6. Traceability to Code
- Client runtime model: `client/src/engine.rs`
- Relay model: `relay-node/src/storage/ephemeral_storage.go`
- Blockchain model: `blockchain-node/src/dto.rs`, `blockchain-node/src/ledger/chain.rs`
- Directory model: `directory-dht/src/main.rs`
- iOS app state model: `RedoorApp/RedoorApp/Services/RedoorService.swift`
