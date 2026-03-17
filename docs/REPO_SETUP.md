# Repository Setup

## 1. Clone
```bash
git clone https://github.com/reiidoda/redoor.git
cd redoor
```

## 2. Toolchain Prerequisites

### 2.1 Common
- `git`
- `openssl`
- `jq` (recommended)
- `rg` (ripgrep, recommended for policy scripts)

### 2.2 Rust stack
- Rust stable (see `rust-toolchain.toml`)
- components: `clippy`, `rustfmt`

### 2.3 Go stack
- Go `1.26.1+` (from `relay-node/go.mod`)

### 2.4 iOS stack (macOS)
- Xcode and command line tools
- `swiftlint`
- `swiftformat`

## 3. Bootstrap Local Secrets and Certificates
Run once per fresh checkout:
```bash
./scripts/bootstrap-dev-secrets.sh
```

Creates local-only files (git-ignored):
- `relay-node/cert.pem`
- `relay-node/key.pem`
- `blockchain-node/node_key.hex`

## 4. Start Services (Development)

### 4.1 Relay
```bash
cd /Users/aidei/Documents/github/redoor/relay-node
RELAY_CERT_FILE=cert.pem \
RELAY_KEY_FILE=key.pem \
RELAY_ADDR=127.0.0.1:8443 \
go run ./src/main.go
```

### 4.2 Blockchain
```bash
cd /Users/aidei/Documents/github/redoor/blockchain-node
BLOCKCHAIN_HTTP_ADDR=127.0.0.1:9444 cargo run
```

### 4.3 Directory
```bash
cd /Users/aidei/Documents/github/redoor/directory-dht
DIR_SIGNING_KEY_HEX=<32-byte-hex-secret> cargo run
```

## 5. Build Client Targets

### 5.1 Rust client
```bash
cd /Users/aidei/Documents/github/redoor/client
cargo check
```

### 5.2 iOS static libraries
```bash
cd /Users/aidei/Documents/github/redoor/client
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
```

## 6. Run Quality Gates

### 6.1 Full baseline
```bash
cd /Users/aidei/Documents/github/redoor
make ci
```

### 6.2 Security-focused
```bash
./scripts/ci-rust-quality.sh
./scripts/ci-go-quality.sh
./scripts/ci-swift-quality.sh
```

## 7. Troubleshooting

### 7.1 Missing merge base in CI
If `origin/main...HEAD` fails, fetch history before running diff-based scripts:
```bash
git fetch --prune --unshallow || true
git fetch origin main --depth=200
```

### 7.2 Missing iOS static library
If Xcode fails to link `libredoor_client.a`, build simulator target:
```bash
cd /Users/aidei/Documents/github/redoor/client
rustup target add aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-ios-sim
```

### 7.3 `rg` not found in policy script
Install ripgrep or ensure grep fallback is available:
```bash
brew install ripgrep   # macOS
```

### 7.4 Gitleaks PR permission errors
If GitHub Action token lacks PR commit read permissions (fork restrictions), run push-based scan in trusted branch context or adjust workflow permissions.

## 8. Security Notes
- Never commit real production keys or credentials.
- Keep local cert/key artifacts outside PR changes.
- Use `.gitleaks.toml` and CI secret scan results before merge.
