# Lockdown Compatibility Matrix

Date: 2026-03-12

This document defines Redoor behavior under a high-risk iOS posture inspired by Lockdown Mode assumptions.

Important: iOS does not expose a stable public API that directly reports Lockdown Mode state for third-party apps. Redoor therefore enforces a **runtime compatibility profile** (`standard` or `strict`) and validates hardening assumptions directly.

## Profiles

- `standard` (`REDOOR_LOCKDOWN_PROFILE=standard`): advisories only; no automatic disconnect.
- `strict` (`REDOOR_LOCKDOWN_PROFILE=strict`): fail-closed when required assumptions are violated after network profile activation.

## Compatibility Matrix

| Check | Standard Profile | Strict Profile |
| --- | --- | --- |
| Identity profile is `strict_ephemeral` | Advisory | Blocking |
| PQ handshake policy is `required` | Advisory | Blocking |
| Strict anonymity enforced | Advisory | Blocking |
| Fixed polling enforced | Advisory | Blocking |
| Constant-rate traffic enforced | Advisory | Blocking |
| Onion routing configured | Advisory | Blocking |
| Cover heartbeat enabled | Advisory | Blocking |
| Remote relay HTTPS | Advisory | Blocking |
| Remote relay HMAC present | Advisory | Blocking |
| Remote relay SPKI/CA pin present | Advisory | Blocking |

## Reduced Functionality in Strict Profile

- Identity persistence profiles are rejected during active network sessions.
- PQ handshake policy should stay on `required` for high-risk sessions.
- Polling cadence hardening remains mandatory (fixed polling + constant-rate traffic).
- Disabling cover heartbeat is treated as unsafe for high-risk posture.

## Telemetry and UX

`RedoorService` publishes lockdown compatibility telemetry:
- profile (`standard` / `strict`)
- `checkedAt` timestamp
- `violations` (blocking)
- `advisories` (non-blocking)
- `reducedFunctionality`

The Settings screen displays this status and uses **Blocked** state when strict checks fail.

## Fail-Closed Behavior

When strict profile is active and a network profile is configured:
1. Redoor evaluates compatibility assumptions.
2. If any blocking check fails, the app disconnects and wipes volatile connection context.
3. A user-visible security error explains the blocking reason.

## High-Risk Deployment Guidance

- Use `strict` lockdown profile.
- Keep identity profile on `strict_ephemeral`.
- Set PQ handshake policy to `required`.
- Keep onion routing + relay pinning + HMAC enabled for all remote relays.
- Keep fixed polling, constant-rate traffic, and cover heartbeat enabled.
- Prefer independent relay operators and jurisdiction diversity in mix routes.
