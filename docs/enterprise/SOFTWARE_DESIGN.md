# Software Design

## 1. Design Scope

Redoor software design is split into:
- high-level architecture and deployment concerns;
- low-level component and object interaction concerns;
- security-by-default policy behavior;
- reliability and maintainability controls.

Primary references:
- [ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md)
- [LOW_LEVEL_AND_OO_DESIGN.md](LOW_LEVEL_AND_OO_DESIGN.md)
- [SECURITY_AND_API_STRATEGY.md](SECURITY_AND_API_STRATEGY.md)
- [TESTING_QUALITY_METRICS_AND_SCM.md](TESTING_QUALITY_METRICS_AND_SCM.md)

## 2. Core Software Design Rules

1. Keep sensitive client state memory-resident and wipeable.
2. Isolate domain services by bounded context.
3. Prefer explicit contracts over implicit coupling.
4. Enforce secure defaults and fail closed on critical policies.
5. Design for observability and measurable reliability.

## 3. Design Decisions to Preserve

- Monorepo governance with service-oriented runtime.
- Fetch-once relay behavior for transient payloads.
- Signed and sequence-bound directory records.
- Commitment-based evidence model instead of plaintext persistence.

