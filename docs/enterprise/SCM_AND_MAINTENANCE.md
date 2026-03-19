# Software Configuration Management and Maintenance

## 1. Configuration Management Strategy

- branch protection on `main` with required CI checks;
- immutable release tags and reproducible builds;
- environment-specific configuration via explicit variables;
- secret material sourced from dedicated secret managers;
- documented rollback procedures for every release.

## 2. Baseline Configuration Inventory

| Layer | Configuration Source |
|---|---|
| Rust toolchain | `rust-toolchain.toml` |
| Go quality policy | `.golangci.yml` |
| Dependency policy | `deny.toml` |
| Secret scanning policy | `.gitleaks.toml` |
| CI entrypoints | `scripts/ci-*.sh`, GitHub workflows |

## 3. Release and Change Governance

1. Every PR requires security and quality gates.
2. High-risk changes require explicit threat/risk note.
3. Production change windows include rollback-ready artifacts.
4. Post-incident actions are tracked to closure.

## 4. Maintenance Model (CARM)

- **Consistency**: API/schema versioning and deterministic policies.
- **Availability**: multi-instance services and health-driven routing.
- **Reliability**: SLOs, error budgets, and resilience testing.
- **Maintainability**: bounded contexts, architecture docs, and technical debt tracking.

