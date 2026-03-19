# CI and Reproducibility

Primary local command:

```bash
cd <repo-root>
make ci
```

`make ci` runs deterministic component checks and fails fast on the first error.

## 1. Local Command Matrix

- Relay format: `make ci-relay-format`
- Relay tests: `make ci-relay-test`
- Directory tests: `make ci-directory`
- Blockchain tests: `make ci-blockchain`
- Client compile: `make ci-client`
- Client memory regressions: `make ci-client-memory`
- Client memory hygiene regressions: `make ci-client-memory-hygiene`
- Client parser fuzz regression: `make ci-client-parser-fuzz`
- Client traffic-anonymity simulator: `./scripts/ci-traffic-anonymity-simulator.sh`
- Client traffic-anonymity regression gate: `./scripts/ci-anonymity-regression.sh`
- Realtime reliability soak: `make ci-reliability-soak`
- Release reproducibility check: `make ci-release-integrity`
- Multi-language bug scanner: `make ci-bugscan` or `./scripts/ci-bugscan.sh`

## 2. Security Gate Workflows

### `.github/workflows/security-gates.yml`
Runs on `pull_request` and pushes to `main`:
- RAM-only policy checks (`scripts/check-ram-only-policy.sh`)
- Swift quality/static analysis (`scripts/ci-swift-quality.sh`)
- Rust quality/security (`scripts/ci-rust-quality.sh`)
- Rust memory regressions (`scripts/ci-memory-regression.sh`)
- Memory hygiene regressions (`scripts/ci-memory-hygiene.sh`)
- Parser fuzz regression gate (`scripts/ci-parser-fuzz.sh`)
- Anonymity regression gate (`scripts/ci-anonymity-regression.sh`)
- Go quality/security (`scripts/ci-go-quality.sh`)
- Bugscan SARIF annotations (`scripts/ci-bugscan.sh --strict --sarif ...`)
- Secret scan (`gitleaks`)
- Artifact upload (`client/artifacts/anonymity/*.json`)

### `.github/workflows/pr-policy.yml`
Runs on `pull_request`:
- enforces completion of the security checklist when a PR is marked security-relevant
- blocks merges that skip required control-matrix/docs/rollback/telemetry declarations

### `.github/workflows/reliability-nightly.yml`
Runs on schedule and manual trigger:
- realtime soak + reconnect chaos integration test
- artifact upload (`itest/artifacts/reliability-soak.json`)

### `.github/workflows/fuzz-nightly.yml`
Runs on schedule and manual trigger:
- parser fuzz regression gate (`scripts/ci-parser-fuzz.sh`)
- nightly fuzz corpus metrics artifact (`itest/artifacts/fuzz-corpus-metrics.json`)

### `.github/workflows/codeql-analysis.yml`
Runs on `pull_request`, pushes to `main`, schedule:
- CodeQL SAST for Go (`security-and-quality` query suite)
- CodeQL SAST for C/C++ surfaces (for C interop/stub paths)

### `.github/workflows/release-integrity.yml`
Runs on tag pushes (`v*`) and manual trigger:
- deterministic release build for core Linux artifacts (`scripts/release-build-core.sh`)
- reproducibility verification across rebuilds (`scripts/verify-reproducible-build.sh`)
- artifact upload (`dist/release/*`)
- signed SLSA provenance attestation (`actions/attest-build-provenance@v1`)
- tag release asset publication

## 3. Gate Details

### Swift Quality Gate
- `swiftformat --lint`
- `swiftlint lint --strict`
- RAM-only forbidden API scan
- iOS deployment target guard (`scripts/check-ios-deployment-target.sh`)
- Xcode static analysis (`xcodebuild analyze`)

### Rust Quality Gate
- `rustfmt --check` on changed Rust files
- `cargo clippy -- -D warnings` (`client`, `blockchain-node`, `directory-dht`, `itest`)
- `cargo deny check bans licenses sources`
- `cargo audit` (high/critical advisories block)

### Go Quality Gate
- `gofmt` check on changed Go files
- `go vet`
- `golangci-lint` (`staticcheck`, `errcheck`, `revive`)
- `go test ./...`
- `govulncheck ./...`

### Memory Regression Gate
- exercises `client/src/diagnostics.rs` memory benchmark
- verifies populated/post-wipe/post-duress budgets
- enforces minimum reclaim ratio

### Memory Hygiene Regression Gate
- executes targeted zeroization tests in Rust wipe/delete/crash-adjacent paths:
  - `engine::tests::secure_wipe_zeroizes_sensitive_collections_and_tracks_report`
  - `service::tests::test_wipe_sensitive_state_clears_memory_structures`
  - `ffi::tests::test_delete_all_messages_zeroizes_buffers`
  - `ffi::tests::test_crash_hygiene_wipe_clears_sensitive_state`
- enforces Swift memory-hygiene policy/test presence checks for:
  - `SecureStorage` wipe hooks
  - lifecycle wipe tests (background/duress)
  - lifecycle observer wiring (resign-active/terminate)

### Parser Fuzz Regression Gate
- executes deterministic corpus + mutation smoke (`client/tests/parser_fuzz_regression.rs`)
- validates parser classification behavior for regression fixtures in:
  - `client/fuzz/corpus/inbound_decode/`
  - `client/fuzz/corpus/handshake_nested_json/`
- enforces presence of parser fuzz targets:
  - `client/fuzz/fuzz_targets/inbound_decode.rs`
  - `client/fuzz/fuzz_targets/handshake_nested_json.rs`
- emits nightly corpus metrics via `scripts/generate-fuzz-corpus-metrics.sh`

### Traffic-Anonymity Simulator Gate
- exercises deterministic seeded fixtures:
  - `idle`
  - `burst`
  - `mixed_real_chaff`
  - `relay_churn`
- validates versioned linkability report shape and scenario coverage
- enforces relative regression expectations (mixed/churn vs baseline scenarios)

### Anonymity Regression Gate
- generates deterministic report artifact from baseline seed
- baseline source: `docs/security/traffic-linkability-baseline.v1.json`
- compares linkability metrics against versioned baseline thresholds:
  - per-scenario: `top1_linkability`, `unresolved_rate`, `estimated_anonymity_set_size`
  - global: weighted top1 score, weighted regression delta, sample floor
- fails pipeline when regression exceeds configured tolerances
- supports emergency override only via controlled CI vars:
  - `REDOOR_ALLOW_ANONYMITY_REGRESSION=true`
  - `REDOOR_ANONYMITY_OVERRIDE_REASON=<ticket-or-incident-id>`

### Reliability Soak Gate
- executes ignored integration `realtime_user_to_user_soak_with_reconnect_chaos`
- enforces thresholds on:
  - delivery ratio
  - reconnect timeout count
  - reconnect latency p95
  - runtime-memory growth after cleanup

## 4. Legacy Broad Script

`./scripts/ci.sh` remains available for broad best-effort checks, but `make ci` and security workflows are canonical.

## 5. SpotBugs-Style Multi-Language Scanner

- Script: `scripts/ci-bugscan.sh`
- Goal: aggregate bug/warning/error checks across Rust, Go, shell, and optional Swift into one summary.
- Default behavior:
  - runs Rust and Go quality/security scripts
  - runs shell static checks (`shfmt`, `shellcheck`) on `scripts/*.sh`
  - skips Swift unless explicitly enabled
- Strict behavior (`--strict`): missing optional scanner tools fail the run instead of being skipped.
- Optional machine-readable output: `--summary-json <path>`.
- Optional code-scanning output: `--sarif <path>`.
- In GitHub Actions, SARIF is uploaded by the `Bugscan SARIF` job in `.github/workflows/security-gates.yml` for PR annotations.
- See `docs/BUGSCAN.md` for command examples.

## 6. Reproducibility Notes

- Rust toolchain is pinned by `rust-toolchain.toml` (`stable`, `clippy`, `rustfmt`).
- Go version is controlled by `relay-node/go.mod` and CI `check-latest: true`.
- iOS project deployment target is pinned to `17.0` and guarded in CI.
- Security policy files: `.golangci.yml`, `deny.toml`, `.gitleaks.toml`.
- Contributor process files:
  - `.github/PULL_REQUEST_TEMPLATE.md`
  - `.github/workflows/pr-policy.yml`
- Release integrity scripts:
  - `scripts/release-build-core.sh`
  - `scripts/verify-reproducible-build.sh`
  - `scripts/verify-release-integrity.sh`
