# Zero-Click Tabletop Scenario v1

- version: `v1`
- owner: Security Lead
- cadence target: quarterly
- duration: 60-90 minutes

## Scenario Goal
Rehearse coordinated response for a suspected zero-click chain affecting inbound parser/background poll surfaces while preserving RAM-first security constraints.

## Participants
- Incident Commander
- Security Lead
- Relay Operator
- Client Runtime Owner
- iOS App Owner
- Scribe

## Initial Conditions
- production release running from `main`
- parser worker isolation enabled
- scoped relay auth enabled
- strict client security profile enabled for high-risk users

## Inject Timeline
1. `T+00`: telemetry reports elevated malformed inbound parser failures and intermittent crash signatures in a subset of clients.
2. `T+10`: one relay node shows unexplained parser worker restarts with no deploy event.
3. `T+20`: security gate artifacts indicate unusual traffic-shape deviation in the same window.
4. `T+35`: external report claims possible zero-click exploit attempt with no user interaction.
5. `T+50`: pressure to ship a hotfix with temporary feature relaxations.

## Required Decisions
1. classify initial severity and incident owner handoff
2. decide whether to activate parser ingress kill switch (`RELAY_PARSER_WORKER_ENABLED=0`)
3. decide relay/admin key rotation sequence and blast radius
4. decide client-side guidance and temporary strict-mode enforcement
5. approve or deny any temporary override with explicit expiry

## Success Criteria
- containment actions executed in the correct order
- kill-switch decisions are documented with rationale
- no persistent logging anti-pattern introduced during incident
- rotation and verification checklist completed
- follow-up remediation issues created with owners and due dates

## Artifacts To Produce
- incident timeline (UTC)
- containment command log
- verification checklist
- remediation backlog links
- completed action tracker:
  - `docs/security/drills/post_drill_action_tracker_template.md`
