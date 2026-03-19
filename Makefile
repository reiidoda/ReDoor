SHELL := /bin/bash

.PHONY: ci ci-relay-format ci-relay-test ci-relay ci-directory ci-blockchain ci-client ci-client-memory ci-client-memory-hygiene ci-client-parser-fuzz ci-client-anonymity ci-client-anonymity-regression ci-reliability-soak ci-release-integrity ci-bugscan pir-proxy-feasibility pq-ratchet-evolution

ci: ci-relay ci-directory ci-blockchain ci-client ci-client-memory ci-client-memory-hygiene ci-client-parser-fuzz ci-client-anonymity ci-client-anonymity-regression
	@echo "All CI component checks passed."

ci-relay: ci-relay-format ci-relay-test

ci-relay-format:
	@set -euo pipefail; \
	diff="$$(gofmt -l relay-node/src || true)"; \
	if [[ -n "$$diff" ]]; then \
		echo "gofmt required for relay-node/src files:"; \
		echo "$$diff"; \
		exit 1; \
	fi

ci-relay-test:
	@set -euo pipefail; \
	cd relay-node && go test ./...

ci-directory:
	@set -euo pipefail; \
	cd directory-dht && cargo test

ci-blockchain:
	@set -euo pipefail; \
	cd blockchain-node && RUST_TEST_THREADS=1 cargo test --tests

ci-client:
	@set -euo pipefail; \
	cd client && cargo check

ci-client-memory:
	@set -euo pipefail; \
	./scripts/ci-memory-regression.sh

ci-client-memory-hygiene:
	@set -euo pipefail; \
	./scripts/ci-memory-hygiene.sh

ci-client-parser-fuzz:
	@set -euo pipefail; \
	./scripts/ci-parser-fuzz.sh

ci-client-anonymity:
	@set -euo pipefail; \
	./scripts/ci-traffic-anonymity-simulator.sh

ci-client-anonymity-regression:
	@set -euo pipefail; \
	./scripts/ci-anonymity-regression.sh

ci-reliability-soak:
	@set -euo pipefail; \
	./scripts/ci-reliability-soak.sh

ci-release-integrity:
	@set -euo pipefail; \
	./scripts/verify-reproducible-build.sh

ci-bugscan:
	@set -euo pipefail; \
	./scripts/ci-bugscan.sh

pir-proxy-feasibility:
	@set -euo pipefail; \
	./scripts/generate-pir-proxy-feasibility-report.sh

pq-ratchet-evolution:
	@set -euo pipefail; \
	./scripts/generate-pq-ratchet-evolution-report.sh
