#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE_FILE="$ROOT/client/src/engine.rs"

if [[ ! -f "$ENGINE_FILE" ]]; then
  echo "::error::missing engine file at $ENGINE_FILE"
  exit 1
fi

start_line="$(awk '/pub fn poll_messages\(&self\) -> String \{/{print NR; exit}' "$ENGINE_FILE")"
if [[ -z "$start_line" ]]; then
  echo "::error::unable to locate poll_messages in $ENGINE_FILE"
  exit 1
fi

end_line="$(
  awk -v s="$start_line" '
    BEGIN {
      found = 0
    }
    NR > s && $0 ~ /^    pub fn / {
      print NR - 1;
      found = 1;
      exit
    }
    END {
      if (!found && NR >= s) {
        print NR;
      }
    }
  ' "$ENGINE_FILE"
)"

section="$(sed -n "${start_line},${end_line}p" "$ENGINE_FILE")"

if ! grep -q "parse_untrusted_envelope_via_boundary" <<<"$section"; then
  echo "::error::poll_messages must parse envelopes only through the parser boundary"
  exit 1
fi

if ! grep -q "parse_untrusted_inner_via_boundary" <<<"$section"; then
  echo "::error::poll_messages must parse inner payloads only through the parser boundary"
  exit 1
fi

if grep -Eq 'serde_json::from_slice::<(Envelope|InnerPayload|InitialMessage)>' <<<"$section"; then
  echo "::error::direct serde parsing of untrusted envelope/inner/initial payloads is forbidden in poll_messages"
  exit 1
fi

if grep -Eq 'parse_validated_untrusted_(envelope|inner_payload|initial_message)' <<<"$section"; then
  echo "::error::poll_messages must not call inline untrusted parse helpers directly"
  exit 1
fi

echo "PASS: untrusted parser boundary policy"
