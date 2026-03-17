# Audit Remediation Workflow

Date: 2026-03-12  
Scope version: `audit-remediation.v1`

## 1. Purpose

Define a consistent process for triaging, fixing, validating, and closing findings from
external cryptography/security assessments.

## 2. Finding Severity and Target SLA

| Severity | Definition | Target Response | Target Fix |
| --- | --- | --- | --- |
| Critical | Active exploit path or complete security-goal break | 24h | 7 days or emergency mitigation |
| High | Practical attack with strong impact | 3 days | 14 days |
| Medium | Exploitable weakness with constraints | 7 days | 30 days |
| Low | Hard-to-exploit weakness or hardening gap | 14 days | next planned security milestone |
| Informational | Observation/no direct exploit | 30 days | optional / backlog |

## 3. Required Tracking Fields

Each finding must have:
- issue id and title;
- source (audit name/report section);
- severity and CWE/crypto-category if available;
- affected components/paths;
- exploit preconditions and impact summary;
- remediation strategy;
- owner and due date;
- verification method and evidence links.

## 4. Workflow Steps

1. Intake:
   - log finding using `Crypto/Protocol Remediation` issue template.
2. Triage:
   - security owner confirms severity and release impact.
3. Remediation design:
   - define fix and test updates before coding.
4. Implementation:
   - use dedicated branch and PR linking the finding issue.
5. Validation:
   - rerun affected CI/test paths and provide command output summary in PR.
6. Closure:
   - close issue only after merged fix and updated docs/threat model where relevant.

## 5. Acceptance and Risk Exception

If a finding is not fixed immediately:
- add explicit risk-exception note to threat model/change log;
- define compensating controls and expiration/review date;
- assign accountable approver.

No silent deferment is allowed for critical/high findings.

## 6. Audit Cycle Hygiene

- Keep a milestone for active audit findings.
- Review open findings at least weekly while milestone is active.
- Run a post-cycle review:
  - fixed vs deferred ratios,
  - mean time to remediate by severity,
  - recurring root-cause themes.
