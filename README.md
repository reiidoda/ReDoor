![ReDoor banner](docs/assets/readme-banner-monochrome.svg)

# Redoor

Redoor is a privacy-first messaging platform in a single monorepo.

## What Redoor Includes
- Rust client runtime (`client/`)
- Swift iOS app (`RedoorApp/`)
- Go relay service (`relay-node/`)
- Rust blockchain evidence service (`blockchain-node/`)
- Rust directory service (`directory-dht/`)

## Project Principles
- no centralized user verification authority
- secure transport paths with onion routing support
- volatile client-side state with wipe/duress flows
- fail-closed security defaults for critical runtime boundaries
- relay blind forwarding and fetch-once semantics for normal blobs
- tamper evidence via blockchain commitments

## Architecture at a Glance
| Path | Responsibility |
|---|---|
| `client/` | Cryptography, session engine, transport clients, diagnostics, FFI |
| `RedoorApp/` | SwiftUI app, lifecycle hardening, secure network validation |
| `relay-node/` | TLS relay, HMAC/replay checks, in-memory queues, abuse controls |
| `blockchain-node/` | Commitment ledger and signed block ingestion |
| `directory-dht/` | Key publication, signed resolution, TTL prekey distribution |
| `itest/` | User-to-user integration and soak tests |
| `scripts/` | Build, bootstrap, quality and security automation |

## End-to-End Message Flow
1. Device creates identity and prekeys.
2. Sender resolves peer key material from directory.
3. Plaintext is encrypted into an opaque envelope.
4. Relay stores/fetches opaque blobs in memory.
5. Sender submits commitment evidence to blockchain.
6. Receiver decrypts in memory and lifecycle policies wipe sensitive state.

## Quick Start (Local Development)
1) Bootstrap local certs and secrets:

```bash
cd /Users/aidei/Documents/github/redoor
./scripts/bootstrap-dev-secrets.sh
```

2) Start services:

```bash
cd /Users/aidei/Documents/github/redoor/relay-node
RELAY_CERT_FILE=cert.pem
RELAY_KEY_FILE=key.pem
RELAY_ADDR=127.0.0.1:8443
go run ./src/main.go
```

```bash
cd /Users/aidei/Documents/github/redoor/blockchain-node
BLOCKCHAIN_HTTP_ADDR=127.0.0.1:9444
cargo run
```

```bash
cd /Users/aidei/Documents/github/redoor/directory-dht
DIR_SIGNING_KEY_HEX=<32-byte-hex-secret>
cargo run
```

3) Run quality gates:

```bash
cd /Users/aidei/Documents/github/redoor
make ci
```

## CI and Security Gates
- `.github/workflows/security-gates.yml`
- `.github/workflows/reliability-nightly.yml`
- `.github/workflows/release-integrity.yml`

Local integrity checks:

```bash
cd /Users/aidei/Documents/github/redoor
./scripts/verify-reproducible-build.sh
./scripts/verify-release-integrity.sh --artifact dist/release/redoor-core-linux-amd64.tar.gz --repo reiidoda/redoor --signer-workflow reiidoda/redoor/.github/workflows/release-integrity.yml
```

## Project Status and Roadmap
- Active open-source readiness milestone: `M27 - Open Source Readiness & Unfinished Work`
- Current open tracking issues: `#212` to `#218`
- Canonical status board: `docs/OPEN_SOURCE_STATUS.md`

## Contributing and Governance
- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`
- Support policy: `SUPPORT.md`
- Governance model: `GOVERNANCE.md`

## Documentation
- Documentation index: `docs/README.md`
- System design: `SYSTEM_DESIGN.md`
- Architecture: `docs/architecture.md`
- Object-oriented design: `OO_DESIGN.md`
- Domain model: `DOMAIN_MODEL.md`
- Security roadmap: `docs/security/ADVANCED_MESSAGE_SECURITY.md`

## License
This project is licensed under the MIT License. See `LICENSE`.

