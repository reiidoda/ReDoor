# Security Incident Runbook

Use this runbook for key leaks, auth bypass suspicion, abnormal relay/directory behavior, or CI secret/vulnerability findings.

For zero-click specific incident response and tabletop drill assets, use:
- `docs/security/ZERO_CLICK_READINESS_RUNBOOK.md`
- `docs/security/drills/zero_click_tabletop_scenario_v1.md`
- `docs/security/drills/post_drill_action_tracker_template.md`

## 1. Severity Model

- `SEV-1`: confirmed active compromise (keys/tokens/certs abused)
- `SEV-2`: high-confidence suspicious behavior, impact not yet confirmed
- `SEV-3`: low-confidence alert or weakness without active exploitation

## 2. Immediate Triage (0-15 min)

1. Freeze deployments to `main`.
2. Open incident channel and assign incident commander.
3. Capture UTC start time and impacted components.
4. Preserve evidence (logs, CI artifacts, commits, env snapshots).
5. Classify incident type:
   - relay HMAC/admin token exposure
   - directory signing key exposure
   - TLS cert/key compromise
   - blockchain admin/token misuse
   - source secret exposure (`gitleaks`)

## 3. Containment Playbooks

### A. Relay HMAC Rotation

```bash
cd <repo-root>
ADMIN_TOKEN="<admin-token>" \
RELAY_URL="https://relay.example.com:8443" \
NEW_KEY_FILE="/secure/redoor/relay_hmac.b64" \
./scripts/rotate-relay-hmac.sh
```

Also rotate `ADMIN_TOKEN` if suspected compromised.

### A2. Scoped Credential Rotation + Revocation

Rotate credential generation with overlap so connected clients can refresh without downtime:

```bash
curl -sS -X POST "https://relay.example.com:8443/admin/scoped/rotate" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"overlap_sec":300}'
```

Revoke a compromised scoped credential immediately:

```bash
curl -sS -X POST "https://relay.example.com:8443/admin/scoped/revoke" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"token_fingerprint":"<compromised-token-fingerprint>"}'
```

Operational notes:
- keep overlap short (`60-300s`) and rotate again after incident containment
- clients auto-refresh scoped credentials before expiry via `/auth/refresh`
- revoked token fingerprints fail immediately even if overlap is active
- compatibility fallback: `client_id` is still accepted during migration
- if abuse pressure spikes during migration, switch `RELAY_ABUSE_BUCKET_MODE=dual_enforce`;
  use `legacy_client` only as rollback, then return to `anonymous_spend_unit` after stabilization

### B. Directory Signing Key Rotation

```bash
cd <repo-root>
./scripts/rotate-directory-signing-key.sh --output /secure/redoor/dir_signing_key.env --env-format
```

Restart directory with rotated `DIR_SIGNING_KEY_HEX`.

### C. Service TLS Rotation

```bash
cd <repo-root>
./scripts/rotate-service-cert.sh relay --cn relay.example.com --days 90
./scripts/rotate-service-cert.sh directory --cn directory.example.com --days 90
```

## 4. Verification Checklist

- relay `/health` and directory endpoints reachable
- blockchain `/health` and transaction path healthy
- no unauthorized publish/admin actions observed post-rotation
- blockchain batch telemetry reviewed for drift/leak anomalies (`redoor_get_blockchain_batch_telemetry`)
- required CI gates passing:
  - `./scripts/ci-rust-quality.sh`
  - `./scripts/ci-go-quality.sh`
  - `./scripts/ci-swift-quality.sh`
  - `./scripts/ci-memory-regression.sh`
  - `./scripts/ci-anonymity-regression.sh`
  - `./scripts/ci-reliability-soak.sh` (where applicable)

## 5. Post-Incident Actions

1. Document root cause and timeline.
2. File hardening issues with owner + due date.
3. Audit secrets in history and secret managers.
4. Confirm no policy regressions in documentation and CI baselines.

## 6. Emergency Override Workflow (Anonymity Regression Gate)

Use this only for time-bounded emergency releases with incident commander approval.

1. Open incident ticket with risk assessment and expiration time.
2. Set repository variables:
   - `REDOOR_ALLOW_ANONYMITY_REGRESSION=true`
   - `REDOOR_ANONYMITY_OVERRIDE_REASON=<incident-ticket-id>`
3. Re-run `Security Gates`; artifact output must be reviewed:
   - `client/artifacts/anonymity/traffic-linkability-report.json`
   - `client/artifacts/anonymity/traffic-linkability-evaluation.json`
4. Merge only with explicit approval from security owner + incident commander.
5. Immediately remove override vars after release.
6. File follow-up hardening issue to restore thresholds before next release.

## 7. Hardening Backlog Suggestions

- reduce long-lived admin surfaces where not required
- enforce secret expiration/rotation cadence
- increase negative-path integration tests for auth and replay controls
- add continuous compliance checks for runtime environment variables

## 8. Audit and Drill Cadence

Minimum operating cadence for high-capability adversary readiness:

1. Quarterly crypto review drill
- simulate compromised relay credential + forced key/session rotation
- verify incident override expiration workflow end-to-end
- record MTTR and unresolved corrective actions

2. Quarterly traffic-correlation red-team drill
- run anonymity simulator baselines plus adversarial fixtures
- compare CI artifacts against approved baseline
- file mandatory remediation issues for degradations

3. Semi-annual external review
- independent cryptography/protocol review (ratchet + handshake + deniability)
- independent network-metadata review (mix diversity, retrieval leakage, timing shape)

4. Release gate requirement
- every production release references the latest completed drill report ID
- if latest drill is older than 90 days, release is blocked except incident hotfixes
