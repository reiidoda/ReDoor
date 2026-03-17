# PIR/Proxy Deployability Graduation Plan

Date: 2026-03-17
Tracker issue: #6

## 1. Purpose

This plan defines measurable graduation gates for moving PIR/proxy retrieval from research to deployable production posture.

Scope:
- baseline split retrieval remains default while this plan is in progress;
- proxy/PIR candidates are evaluated only through explicit staged gates;
- no default-on rollout is allowed without passing all required gates.

## 2. Inputs and Baseline

Primary references:
- `docs/security/PIR_PROXY_MAILBOX_RETRIEVAL_SPIKE.md`
- `docs/security/pir-proxy-feasibility-report.v1.json`

Current baseline from feasibility spike:
- baseline split retrieval p95 latency: `1300.0ms`
- baseline split retrieval infra CPU: `8.7ms/fetch`
- proxy fanout candidate availability: `0.986`
- two-server PIR candidate availability: `0.930`

## 3. Graduation Stages

### Stage A: Research-complete (current)

Entry criteria:
- deterministic benchmark artifact exists and is reproducible;
- threat-model delta is documented;
- default production policy remains no-go.

Exit criteria for Stage B:
- follow-up implementation tasks are tracked and owned;
- measurable success thresholds are documented (Section 4).

### Stage B: Controlled pilot-ready

Entry criteria:
- Stage A complete;
- all required P0/P1 follow-up tasks complete (Section 5);
- external audit preconditions met (Section 6).

Pilot constraints:
- opt-in only (`research` or `pilot` profile), never default-on;
- canary deployments only, with rollback playbook tested;
- explicit operator acknowledgment of proxy trust assumptions.

Exit criteria for Stage C:
- pilot SLOs consistently pass over minimum 30 days;
- no unresolved high-severity findings in audit/remediation set;
- rollback drill evidence demonstrates fail-closed behavior.

### Stage C: Production-candidate

Entry criteria:
- Stage B exit criteria complete;
- governance sign-off from security owner + maintainer owner.

Exit criteria for Stage D:
- release-readiness checklist passes in CI/docs/runbook;
- migration plan includes default-off fallback and emergency disable controls.

### Stage D: Production default (future, optional)

Entry criteria:
- Stage C complete;
- explicit maintainers decision recorded in changelog and roadmap docs.

## 4. Measurable Gates

All gates are required unless explicitly marked optional.

Performance and availability:
- p95 latency increase <= 35% vs baseline split retrieval.
- infra CPU <= 3x baseline split retrieval.
- candidate availability >= 0.985 in pilot windows.

Privacy and trust controls:
- no single opaque trust concentration without documented no-log controls.
- jurisdiction/operator split controls are enforced for proxy-critical roles.
- receiver-interest exposure reduction is demonstrated in deterministic report artifacts.

Abuse and operational safety:
- abuse controls for proxy path achieve low-noise alerting and bounded false positive rate.
- rollback path tested and documented with bounded recovery time objective.
- fail-closed behavior verified for policy-denied/unsafe runtime conditions.

Assurance:
- external review sign-off on privacy assumptions and abuse resistance controls.
- no unresolved high/critical findings without explicit time-bounded risk acceptance.

## 5. Follow-up Implementation Tasks

Actionable task groups tracked in repository issues:
- #23 PIR/proxy benchmark hardening and CI graduation metrics
- #24 PIR/proxy trust controls and jurisdiction-split operating model
- #25 PIR/proxy abuse controls and detector/runbook integration
- #26 PIR/proxy pilot rollout, rollback drills, and release gating

Completion policy:
- Stages cannot advance with open blocking tasks in their required task group.

## 6. Audit and Governance Requirements

Required before pilot:
- threat-model update for selected candidate architecture;
- runbook mapping for incident response and rollback;
- external reviewer checklist coverage for new trust assumptions.

Required before production-candidate:
- independent review evidence linked in docs/changelog;
- remediation SLAs defined for findings.

## 7. Decision Record Rules

Every stage transition must record:
- decision date;
- approvers;
- gate evidence links;
- rollback posture.

Record location:
- `docs/CHANGELOG.md`
- `docs/security/ADVANCED_MESSAGE_SECURITY.md`
- `docs/threat_model.md`

## 8. Current Status

Current stage: `Stage A (research-complete)`
Current default policy: `NO-GO for mandatory rollout`
Allowed mode: `opt-in research profile only`

