# iOS Integration Guide (`RedoorApp`)

This guide reflects the current Swift app that embeds the Rust client runtime through FFI.

## 1. Architecture Snapshot

- UI: SwiftUI (`Features/Setup`, `Features/Chat`, `Features/Settings`)
- Service composition: `RedoorService` + `ChatService`
- FFI bridge: `Core/RedoorFFI.swift`
- Volatile secure storage: `Core/SecureStorage.swift` (RAM-only zeroizable buffers)

## 2. Security-Sensitive App Rules

1. No persistent user/session secrets on device storage.
2. Lock and wipe behavior on app lifecycle transitions.
3. Remote relay config must satisfy strict validator checks:
   - secure relay URL policy
   - HMAC presence for remote relay
   - relay pin material (SPKI or CA)
   - onion node JSON present and valid (`>= 3` nodes)
4. Strict anonymity path should remain enabled at runtime.
5. Sensitive HMAC material must live in zeroizable volatile buffers and be wiped on lock/duress/background flows.
6. Lockdown compatibility profile controls high-risk fail-closed behavior:
   - `REDOOR_LOCKDOWN_PROFILE=standard` (advisories)
   - `REDOOR_LOCKDOWN_PROFILE=strict` (blocking checks + disconnect on violation)
7. PQ handshake policy is configurable and enforced through FFI/app settings:
   - `prefer` (default), `required`, `disabled`
   - strict lockdown profile expects `required` policy.

## 3. Rust Library Build for iOS

```bash
cd <repo-root>/client
export IPHONEOS_DEPLOYMENT_TARGET=17.0
export CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS="-C link-arg=-miphoneos-version-min=17.0"
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS="-C link-arg=-mios-simulator-version-min=17.0"
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
```

Static library outputs:
- `client/target/aarch64-apple-ios/release/libredoor_client.a`
- `client/target/aarch64-apple-ios-sim/release/libredoor_client.a`

Optional header generation:

```bash
cd <repo-root>/client
cbindgen --config cbindgen.toml --crate redoor-client --output target/redoor.h
```

## 4. Core FFI Calls Used by App

Representative calls used in Swift bridge/service:
- runtime/env: `redoor_init_runtime`, `redoor_init_env`
- identity/session: `redoor_create_identity`, `redoor_generate_prekeys`, `redoor_has_session`, `redoor_connect_via_qr`
- messaging: `redoor_send_message`, `redoor_poll_messages`, `redoor_delete_message`
- security: `redoor_wipe_memory`, `redoor_enter_duress_mode`, `redoor_enable_strict_anonymity`, `redoor_enable_fixed_polling`
- handshake policy: `redoor_set_pq_handshake_policy`
- pinning/onion: `redoor_set_relay_ca_b64`, `redoor_set_relay_spki_pin_b64`, `redoor_configure_onion_routing`

## 5. Local Run (Simulator)

1. Start relay with TLS cert/key.
2. Start blockchain HTTP endpoint.
3. Optionally start directory service.
4. Run `RedoorApp` scheme in Xcode.
5. Configure relay/blockchain/onion values in Setup screen.

## 6. Lifecycle Hardening Behavior

Current app behavior:
- on `didEnterBackground` -> lock + disconnect + wipe
- on `willResignActive` -> lock + disconnect + wipe
- on `willTerminate` -> lock + disconnect + wipe
- on duress -> wipe runtime, clear volatile store, lock UI state
- secure storage test hooks (`debugLastZeroization`) verify wipe paths zeroize bytes before dropping references.

## 7. CI Gates for iOS

Use:

```bash
./scripts/ci-swift-quality.sh
```

This enforces:
- style/lint
- RAM-only forbidden API scanning
- deployment-target compatibility guard (`scripts/check-ios-deployment-target.sh`)
- Xcode static analysis

## 8. Known Engineering Caveats

- The iOS app links against Rust static libs built for iOS 17.0; helper scripts set the deployment target automatically.
- Deployment target is pinned at `IPHONEOS_DEPLOYMENT_TARGET = 17.0`; CI fails if it exceeds installed simulator SDK support.

## 9. High-Risk Lockdown Guidance

- Use `strict` lockdown compatibility profile.
- Keep identity profile on `strict_ephemeral`.
- Set PQ handshake policy to `required`.
- Keep cover heartbeat enabled.
- Keep remote relay transport fully hardened (HTTPS + HMAC + SPKI/CA pinning).
- Review the matrix in `docs/security/LOCKDOWN_COMPATIBILITY_MATRIX.md`.
