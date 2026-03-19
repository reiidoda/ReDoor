#![no_main]
use libfuzzer_sys::fuzz_target;
use redoor_client::network::relay::compute_hmac;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    // Split fuzz data into id/receiver/body slices (simple split points)
    let third = data.len() / 3;
    let (id_bytes, rest) = data.split_at(third);
    let (recv_bytes, body) = rest.split_at(rest.len() / 2);

    // Fixed key for determinism
    let key = [0u8; 32];

    // Compute HMAC; ensure it never panics
    let _ = compute_hmac(&key, std::str::from_utf8(id_bytes).unwrap_or(""), std::str::from_utf8(recv_bytes).unwrap_or(""), body);
});
