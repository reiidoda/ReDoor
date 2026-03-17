# Parser Inventory Matrix

## Scope

This matrix enumerates all parser-exposed ingress paths that can process attacker-controlled bytes, the owning module, memory-safety posture, isolation boundary, and fuzz/test coverage.

## Policy Baseline

- default-off preview policy: no attachment, media, rich-preview, thumbnail, archive, or document parser is enabled in user messaging path.
- allowed parser classes are explicitly allowlisted via `REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`.
- untrusted parsing must stay behind the worker boundary and fail closed when policy denies a class.

## Inventory

| Parser Class | Format / Surface | Owner | Memory-Safe | Isolation Boundary | Fuzz/Regression Coverage | Default State |
| --- | --- | --- | --- | --- | --- | --- |
| `envelope_json` | Relay envelope JSON blob | Rust client `engine` | Yes (Rust) | Untrusted parser worker process | `client/fuzz/fuzz_targets/inbound_decode.rs`, `client/tests/parser_fuzz_regression.rs` | Enabled (allowlist) |
| `inner_payload_json` | Decrypted inner JSON payload | Rust client `engine` | Yes (Rust) | Untrusted parser worker process | `client/fuzz/fuzz_targets/inbound_decode.rs`, `client/tests/parser_fuzz_regression.rs` | Enabled (allowlist) |
| `initial_message_json` | X3DH initial handshake JSON | Rust client `engine` / `crypto::x3dh` | Yes (Rust) | Untrusted parser worker process | `client/fuzz/fuzz_targets/handshake_nested_json.rs`, `client/tests/parser_fuzz_regression.rs` | Enabled (allowlist) |
| `transport_fixed_cell` | Fixed-cell transport decode | Rust client `network::relay` | Yes (Rust) | In-process transport codec (bounded format) | unit tests in `client/src/network/relay.rs` | Enabled |
| `relay_certificate_x509` | TLS cert/SPKI pin parse | Rust client `network::relay` (`x509-parser`) | Mostly Rust crate + native TLS stack interaction | In-process cert validation path | unit tests in `client/src/network/relay.rs` | Enabled |
| `swift_message_render_text_only` | iOS rendering filter (`text/system/cover`) | Swift app `RedoorService` | Yes (Swift) | UI filter after Rust boundary | `scripts/check-auto-processing-lockdown.sh`, Swift CI gates | Enabled |
| `attachment_file_parser` | File send/decrypt path | Rust FFI / Swift | N/A (disabled) | Disabled by policy | CI lockdown gate | Disabled (default-off) |
| `media_preview_parser` | Auto-preview / thumbnail / metadata parsing | Swift UI + platform codecs | N/A (disabled) | Disabled by policy | CI import-block + lockdown gate | Disabled (default-off) |

## Structural Validation Guards

All untrusted JSON parser classes enforce:

- input size bounds before parse;
- UTF-8 and JSON shape precheck;
- nesting-depth limits;
- structural token budget limits;
- numeric token digit limits;
- compressed payload magic rejection;
- strict schema (`deny_unknown_fields`) for parser structs.

## Corpus Management

- Corpus packs are versioned under `client/fuzz/corpus/`.
- Mandatory directories:
  - `inbound_decode/`
  - `handshake_nested_json/`
- Regression fixtures must remain stable for deterministic CI classification.

## Expansion Process (Fail-Closed)

Adding a new parser class requires:

1. Add class to this matrix with owner + boundary + coverage.
2. Add explicit allowlist token handling in `engine` parser policy.
3. Add structural validation limits for the class.
4. Add fuzz target + corpus fixture + deterministic regression test.
5. Add CI policy gate updates (`check-parser-surface-policy.sh`).
6. Document rollback/kill-switch behavior.

No parser class is implicitly enabled by introducing new code paths.

## Removal / Isolation Plan for Unsafe Paths

- Keep all high-risk preview/media/document paths disabled until a dedicated sandboxed worker class exists.
- If a parser cannot be isolated behind the boundary with strict resource controls, remove the feature instead of bypassing policy.
- Legacy parser code paths (if reintroduced) must be fronted by deny-by-default feature flags and explicit operator rollout.
