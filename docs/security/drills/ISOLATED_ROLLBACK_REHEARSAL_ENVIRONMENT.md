# Isolated Rollback Rehearsal Environment

Date: 2026-03-13  
Issue: #189  
Script: `scripts/drill-rollback-rehearsal.sh`

## Objective

Provide a reproducible, isolated rehearsal harness for emergency rollback and credential rotation without touching production files or live services.

The rehearsal executes three controlled states:
1. baseline snapshot,
2. rotated state,
3. rollback + post-rollback re-rotation.

## Isolation Model

- Runs entirely in a temporary workspace (`mktemp`) unless `--workspace` is provided.
- Uses only copied/generated artifacts under that workspace.
- Never mutates repository runtime cert/key files.
- Produces evidence manifests and summaries under `<workspace>/evidence`.

## Commands

Default ephemeral rehearsal:

```bash
./scripts/drill-rollback-rehearsal.sh
```

Deterministic retained workspace:

```bash
./scripts/drill-rollback-rehearsal.sh \
  --workspace dist/drills/rollback-rehearsal \
  --keep-workspace \
  --relay-cn relay-drill.local \
  --directory-cn directory-drill.local \
  --days 14
```

CI validation harness:

```bash
./scripts/ci-drill-rehearsal.sh
```

## Generated Evidence

Expected artifacts:
- `baseline.sha256`
- `rotated.sha256`
- `rollback.sha256`
- `post-rollback.sha256`
- `rollback-rehearsal-summary.md`
- `rollback-rehearsal-summary.json`

Acceptance checks enforced by script:
- rotated state must differ from baseline;
- rollback state must exactly match baseline;
- post-rollback rotation must differ from baseline.

## Rotation Coverage

The rehearsal rotates:
- relay TLS cert/key;
- directory TLS cert/key;
- relay HMAC key material (isolated file in workspace).

This provides operational readiness coverage for emergency rollback + rotation sequencing under time pressure.
