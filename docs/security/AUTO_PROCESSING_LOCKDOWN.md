# Auto-Processing Lockdown

## Goal
Reduce zero-click attack surface by keeping inbound handling text-only unless an explicit future feature gate is introduced.

## Enforced Policy
- incoming `msg_type` is restricted to a safe allowlist in Rust runtime validation:
  - `text`
  - `system`
  - `cover`
- parser class rollout is explicit and allowlisted:
  - `REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST`
  - default classes: `envelope_json,inner_payload_json,initial_message_json`
- Swift poll path filters inbound messages to text-only for rendering.
- attachment/media FFI paths remain disabled:
  - `redoor_send_file`
  - `redoor_decrypt_file`

## Regression Gates
- `scripts/check-auto-processing-lockdown.sh` blocks:
  - removal of disabled attachment guards in Rust FFI;
  - removal of Swift text-only poll filter;
  - introduction of high-risk media/document frameworks in app code (`AVFoundation`, `PhotosUI`, `QuickLook`, `PDFKit`, `WebKit`).
- gate is executed by:
  - `scripts/ci-rust-quality.sh`
  - `scripts/ci-swift-quality.sh`

## Operational Notes
- this policy is fail-closed: unsupported/unknown inbound message types are dropped.
- any future media support must be explicit user-action only and introduced with a separate audited milestone.
