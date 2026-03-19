use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// Verify block/transaction signatures
pub fn verify_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let pk_bytes: [u8; 32] = match public_key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let public_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sig_bytes: [u8; 64] = match signature_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_bytes);

    public_key.verify(message, &signature).is_ok()
}
