# Multi-Language Bug Scanner

`./scripts/ci-bugscan.sh` is a SpotBugs-style umbrella scanner for this repository.

It runs language-specific static/security gates and prints a single pass/fail summary:

- Rust: `scripts/ci-rust-quality.sh`
- Go: `scripts/ci-go-quality.sh`
- Shell: `shfmt` + `shellcheck` over `scripts/*.sh`
- Swift (optional): `scripts/ci-swift-quality.sh`

## Quick Start

```bash
cd <repo-root>
./scripts/ci-bugscan.sh
```

## Useful Modes

```bash
cd <repo-root>
./scripts/ci-bugscan.sh --strict
./scripts/ci-bugscan.sh --include-swift
./scripts/ci-bugscan.sh --summary-json artifacts/bugscan-summary.json
./scripts/ci-bugscan.sh --sarif artifacts/bugscan.sarif
```

- `--strict`: fail if optional scanner tools are missing.
- `--include-swift`: include Swift static-analysis gate.
- `--summary-json`: write a machine-readable run summary for CI artifacts.
- `--sarif`: write a SARIF file suitable for code-scanning annotations.

In CI, `.github/workflows/security-gates.yml` runs bugscan in strict mode and uploads `artifacts/bugscan.sarif` to GitHub code scanning.

## Make Target

```bash
cd <repo-root>
make ci-bugscan
```

