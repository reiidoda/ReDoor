# Untrusted Parser IPC Contract (v1)

Date: 2026-03-13  
Issue: #196  
Version: `uib-ipc.v1`

## Transport

- Channel: line-delimited JSON over stdin/stdout.
- One request -> one response.
- Requests must be independent and side-effect free.

## Request Schema

Envelope parse request:

```json
{
  "op": "envelope",
  "blob_base64": "<base64>"
}
```

Inner payload parse request:

```json
{
  "op": "inner_payload",
  "expected_sender_id": "sender-token",
  "plaintext_base64": "<base64>"
}
```

Initial handshake parse request:

```json
{
  "op": "initial_message",
  "ciphertext_base64": "<base64>"
}
```

Constraints:
- Unknown fields are rejected (`deny_unknown_fields`).
- Decoded payload length must be <= `REDOOR_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES`.
- Per-frame budget is bounded (`max_input * 2`, minimum 4096 bytes).

## Response Schema

Successful envelope response:

```json
{
  "kind": "envelope",
  "envelope": { "...typed Envelope..." }
}
```

Successful inner response:

```json
{
  "kind": "inner_payload",
  "inner": { "...typed InnerPayload..." }
}
```

Successful initial response:

```json
{
  "kind": "initial_message",
  "initial": { "...typed InitialMessage..." }
}
```

Error response:

```json
{
  "kind": "error",
  "err_kind": "invalid_request | invalid_payload | policy_denied",
  "err_msg": "bounded error text"
}
```

Constraints:
- Unknown fields are rejected (`deny_unknown_fields`).
- Error responses are bounded and line-delimited.

## Security Requirements

- No generic object passing or dynamic code execution paths.
- No secret-bearing fields cross IPC.
- Binary payloads use base64 only.
- Schema-deny-unknown enforced on both sides.
- Worker process is launched with `env_clear()` and only allowlisted parser limit env vars.
- Parser class execution is allowlisted via `REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`.

## Compatibility

- Version key is explicit (`uib-ipc.v1`).
- Any schema change requires version bump + compatibility tests.
