#![no_main]
use libfuzzer_sys::fuzz_target;
use redoor_client::crypto::chacha20poly1305;
use redoor_client::crypto::ed25519;
use redoor_client::ratchet::double_ratchet::RatchetSession;

fuzz_target!(|data: &[u8]| {
    // Guard against tiny inputs
    if data.len() < 32 {
        return;
    }

    // Create a dummy shared secret from first 32 bytes
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data[..32]);

    // Start a session with a dummy remote public key (reuse secret slice)
    let mut sess = RatchetSession::new(secret, None);

    // Encrypt then decrypt the remaining payload
    let payload = &data[32..];
    if let Ok(ct) = sess.ratchet_encrypt(payload) {
        let _ = sess.ratchet_decrypt(&ct);
    }
});
