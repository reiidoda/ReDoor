#![no_main]

use libfuzzer_sys::fuzz_target;
use redoor_client::engine::{fuzz_classify_untrusted_blob, fuzz_validate_untrusted_inner_payload};

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_classify_untrusted_blob(data);

    if data.is_empty() {
        return;
    }

    let split = data[0] as usize % data.len();
    let sender = if split % 2 == 0 {
        "sender-1"
    } else {
        "bad sender with spaces"
    };
    let plaintext = &data[split..];
    let _ = fuzz_validate_untrusted_inner_payload(sender, plaintext);
});
