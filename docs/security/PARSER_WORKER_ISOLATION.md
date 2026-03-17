# Relay Parser Worker Isolation

## Purpose
Redoor relay ingress parsing for `X-Receiver-ID=__mix__` now runs in a dedicated parser worker process (`parser-worker`) instead of inside the main relay request handler.

This reduces blast radius for malformed/untrusted mix payload parsing and gives a fail-closed control plane.

## Security Boundary
- Main relay process:
  - handles TLS, auth/rate-limit, mailbox policy, storage, forwarding decisions.
  - does **not** call `onion.ProcessSphinxPacket` directly for untrusted mix payloads.
- Parser worker process:
  - receives raw payload bytes over stdin/stdout JSON IPC.
  - performs Sphinx packet parse/decrypt/validation and replay checks.
  - returns only validated result fields (`forwarded/final`, `next_hop`, `receiver_id`, payload bytes).

## Privilege Firewall
- Worker startup now uses an explicit env allowlist:
  - `RELAY_MIX_PRIVATE_KEY_HEX`
  - `RELAY_MIX_TAG_TTL_SEC`
  - `RELAY_MIX_TAG_MAX_ENTRIES`
  - `RELAY_PARSER_WORKER_MEM_LIMIT_BYTES`
- Privileged relay env keys are blocked from parser worker context:
  - `RELAY_HMAC_KEY`
  - `ADMIN_TOKEN`
  - `RELAY_KEY_FILE`
- Worker self-check fails startup if forbidden privileged env keys are present in its process environment.

This enforces one-way data flow:
1. main relay authorizes request;
2. untrusted payload bytes cross boundary to parser worker;
3. only validated envelope fields come back;
4. session/authentication state remains in main relay process.

## Operational Controls
- `RELAY_PARSER_WORKER_ENABLED`:
  - default: enabled (any value except `0`).
  - `0` disables worker startup and forces mix path fail-closed (`503`).
- `RELAY_PARSER_WORKER_TIMEOUT_MS`:
  - per-request IPC timeout.
  - default: `1500`.
- `RELAY_PARSER_WORKER_MEM_LIMIT_BYTES`:
  - Go runtime memory limit for worker (`debug.SetMemoryLimit`).
  - default: `67108864` (64 MiB).

## Crash/Restart Policy
- If worker I/O or timeout fails, relay restarts worker once and retries parsing once.
- If restart/retry fails, request is rejected (no payload stored/forwarded).
- Worker crash therefore degrades mix ingress availability, not relay integrity.

## Malformed Payload Kill-Switch
- Invalid payloads return parser rejection (`400`/`401`) with no side effects.
- For emergency isolation, set `RELAY_PARSER_WORKER_ENABLED=0` to disable mix parsing path entirely (fail-closed).
