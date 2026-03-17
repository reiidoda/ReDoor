# Security Logging Policy

Redoor treats logs as sensitive metadata. Logging is allowed only when it preserves operational visibility without exposing user, key, or message secrets.

## 1. Never Log

- raw private keys, prekeys, wrapped key blobs
- HMAC secrets, admin tokens, TLS private material
- full peer identifiers, full message IDs, safety numbers
- plaintext message content
- relay auth headers (`X-HMAC`, nonce/timestamp pairs)

## 2. Allowed Logging

- status codes and coarse error classes
- counts/counters (queue depth, retry count)
- boolean state flags
- bounded latency/duration metrics
- redacted identifiers (`<redacted:...>` style)

## 3. Component-Specific Expectations

### Client Runtime
- Internal logs pass through redaction logic before entering in-memory buffer.
- `log_buffer` is bounded to avoid unbounded memory growth.

### Relay
- Structured JSON logs should avoid identity-linked values.
- Do not emit HMAC-derived request material.
- Anomaly detector output should use detector IDs + aggregate counters only
  (for example: `relay_replay_spike`, `relay_malformed_burst`, `relay_credential_spray`).

### Directory
- Anomaly detector output should use detector IDs + aggregate counters only
  (for example: `directory_replay_spike`, `directory_malformed_burst`, `directory_credential_spray`).

### Blockchain
- Admin/auth failure logs must not include token values.
- Transaction logs should avoid full signer/commitment raw values where possible.

### iOS
- Do not print secrets or user data in release builds.
- Lifecycle wipe/lock events may be logged at high level only.

## 4. Test Requirement

New logging code touching security-sensitive paths must include tests or assertions that verify redaction behavior.

## 5. Incident Handling

If a sensitive logging leak is detected:
1. remove or redact source logging immediately
2. rotate impacted secrets/tokens
3. backfill incident notes in `docs/security-runbook.md` workflow
