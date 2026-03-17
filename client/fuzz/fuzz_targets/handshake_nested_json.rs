#![no_main]

use libfuzzer_sys::fuzz_target;
use redoor_client::engine::fuzz_classify_untrusted_blob;
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    let nested = json!({
        "identity_key": data,
        "ephemeral_key": data,
        "one_time_prekey_id": null,
        "ciphertext": data,
        "deep": {
            "nested": {
                "blob": data
            }
        }
    });

    let nested_bytes = serde_json::to_vec(&nested).unwrap_or_default();
    let envelope = json!({
        "mailbox_id": "mailbox-1",
        "sender_id": "sender-1",
        "timestamp": 0,
        "ciphertext": nested_bytes,
        "pow_nonce": 0
    });
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap_or_default();
    let _ = fuzz_classify_untrusted_blob(&envelope_bytes);
});
