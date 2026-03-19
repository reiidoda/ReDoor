## Summary

- Describe the change.
- Link the primary issue(s).

## Validation

- [ ] I ran the relevant local checks and listed them below.
- [ ] I updated docs for any behavior, policy, or contributor-workflow change.

Validation commands and notes:

```text
- make ci
- ./scripts/ci-bugscan.sh --include-swift
```

## Security Review

- [ ] This PR is security-relevant.
- [ ] If security-relevant: I updated `docs/security/control-matrix.csv`, or explained why no mapped control changed.
- [ ] If security-relevant: I updated threat model, runbook, release, or contributor docs where needed.
- [ ] If security-relevant: I documented rollback/containment considerations.
- [ ] If security-relevant: I documented telemetry, alerting, or observability impact.

## Notes for Reviewers

- Risks or follow-ups:
- Open questions:
