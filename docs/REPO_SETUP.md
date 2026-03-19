# Repository Setup

## 1. Clone
```bash
git clone https://github.com/reiidoda/ReDoor.git
cd ReDoor
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
cd <repo-root>/relay-node
RELAY_CERT_FILE=cert.pem \
RELAY_KEY_FILE=key.pem \
RELAY_ADDR=127.0.0.1:8443 \
go run ./src/main.go
```

### 4.2 Blockchain
```bash
cd <repo-root>/blockchain-node
BLOCKCHAIN_HTTP_ADDR=127.0.0.1:9444 cargo run
```

### 4.3 Directory
```bash
cd <repo-root>/directory-dht
DIR_SIGNING_KEY_HEX=<32-byte-hex-secret> cargo run
```

## 5. Build Client Targets

### 5.1 Rust client
```bash
cd <repo-root>/client
cargo check
```

### 5.2 iOS static libraries
```bash
cd <repo-root>/client
export IPHONEOS_DEPLOYMENT_TARGET=17.0
export CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS="-C link-arg=-miphoneos-version-min=17.0"
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS="-C link-arg=-mios-simulator-version-min=17.0"
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
```

## 6. Run Quality Gates

### 6.1 Full baseline
```bash
cd <repo-root>
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
cd <repo-root>/client
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
