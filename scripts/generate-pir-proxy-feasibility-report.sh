#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR/client"
cargo run --quiet --bin pir_proxy_feasibility -- --output ../docs/security/pir-proxy-feasibility-report.v1.json "$@"
