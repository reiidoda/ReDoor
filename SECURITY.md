# Security Policy

## Reporting a Vulnerability

Please do not open public issues for potential vulnerabilities.

Use one of these private channels:
- GitHub Security Advisories for this repository.
- Private maintainer contact path documented in `CODE_OF_CONDUCT.md`.

Include:
- affected component/path,
- reproduction steps,
- impact assessment,
- any proof-of-concept artifacts (minimal and sanitized).

## Response Expectations

Current target response windows:
- initial triage acknowledgment: within 3 business days,
- status update after triage: within 7 business days.

These are targets, not guaranteed SLAs.

## Disclosure Guidance

- Prefer coordinated disclosure.
- Do not publish exploit details before maintainers confirm mitigation is available or a safe timeline is agreed.

## Security Scope

Security-sensitive areas include:
- `client/` cryptographic and FFI boundaries,
- `relay-node/` transport/auth/replay controls,
- `directory-dht/` key publication/verification logic,
- `blockchain-node/` commitment verification and admin surfaces,
- lifecycle wipe/duress and memory hygiene controls.

For operational process detail, see `docs/security-runbook.md`.

