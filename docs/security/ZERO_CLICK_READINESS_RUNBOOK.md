# Zero-Click Readiness Runbook

## Purpose
Use this runbook when there is suspicion of a zero-click exploitation attempt against Redoor clients, relay ingress, or automatic network processing paths.

## Incident Profile
- threat: exploit without user interaction through untrusted inbound processing surfaces
- likely targets: parser/decode paths, transport handling, background poll loops, key/session handling paths after compromise
- severity defaults:
  - `SEV-1`: confirmed exploitation or code execution
  - `SEV-2`: high-confidence suspicious signal with potential exploit chain
  - `SEV-3`: weak signal requiring investigation

## Immediate Triage (0-15 minutes)
1. Freeze production deployments.
2. Open incident channel and assign Incident Commander, Security Lead, and Communications Lead.
3. Capture UTC timeline start and impacted components.
4. Preserve volatile evidence immediately:
   - relay logs and action run outputs
   - CI artifacts for latest security gates
   - exact build SHA and release metadata
5. Classify signal source:
   - anomalous parser failures / crash loops
   - abnormal polling/fetch behavior
   - suspicious session/key behavior
   - unexplained transport anomalies

## Containment Checklist
1. Enforce strict server-side posture:
   - `RELAY_REQUIRE_SCOPED_AUTH=1`
   - `RELAY_MAILBOX_ALLOW_LEGACY=0`
2. If parser path is suspect, disable mix parser worker ingress (fail-closed):
   - `RELAY_PARSER_WORKER_ENABLED=0`
3. Rotate relay and admin secrets:
   - `RELAY_HMAC_KEY`
   - `ADMIN_TOKEN`
4. Force strict client runtime profile:
   - `REDOOR_SECURE_MODE=1`
5. Verify auto-processing lockdown controls are still active:
   - attachment decrypt/send FFI disabled
   - text-only inbound filter path active

## Forensic Data Handling (RAM-First Constraints)
- do not add new persistent logging paths for convenience during incident response
- capture process/runtime metadata and bounded logs only
- treat captured artifacts as sensitive and time-bound
- redact secrets/tokens before sharing any cross-team summary
- preserve chain of custody in incident notes:
  - collector
  - timestamp (UTC)
  - source host/component
  - hash of exported artifact

## Key and Session Rotation
1. Rotate relay HMAC and scoped credential chain.
2. Rotate directory signing key if resolve integrity is in scope.
3. Rotate TLS cert/key on affected services.
4. Force client session resets for impacted peers.
5. Re-run critical quality/security gates before resuming normal deploys.

## Emergency Kill-Switch Checklist
- `RELAY_PARSER_WORKER_ENABLED=0` (disable mix parser ingress)
- `RELAY_MAILBOX_ALLOW_LEGACY=0` (remove legacy mailbox path)
- `RELAY_REQUIRE_SCOPED_AUTH=1` (mandatory scoped auth)
- `REDOOR_SECURE_MODE=1` (strict secure runtime posture)

## Drill Assets
- scripted tabletop scenario:
  - `docs/security/drills/zero_click_tabletop_scenario_v1.md`
- post-drill action tracker template:
  - `docs/security/drills/post_drill_action_tracker_template.md`

## Exit Criteria
- exploitation path contained or disproven
- all emergency overrides removed or explicitly approved with expiry
- required rotations completed and validated
- remediation issues opened with owners and due dates
- post-incident summary approved by security owner
