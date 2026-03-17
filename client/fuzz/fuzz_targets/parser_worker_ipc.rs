#![no_main]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use libfuzzer_sys::fuzz_target;
use redoor_client::engine::fuzz_parse_untrusted_parser_worker_request_frame;
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);

    // Exercise worker request JSON framing across all parser ops.
    let request = json!({
        "op": if data.first().copied().unwrap_or_default() % 3 == 0 {
            "envelope"
        } else if data.first().copied().unwrap_or_default() % 3 == 1 {
            "inner_payload"
        } else {
            "initial_message"
        },
        "blob_base64": B64.encode(data),
        "expected_sender_id": raw.chars().take(32).collect::<String>(),
        "plaintext_base64": B64.encode(data),
        "ciphertext_base64": B64.encode(data)
    });

    if let Ok(request_bytes) = serde_json::to_vec(&request) {
        let _ = fuzz_parse_untrusted_parser_worker_request_frame(&request_bytes);
    }

    let _ = fuzz_parse_untrusted_parser_worker_request_frame(data);
});


