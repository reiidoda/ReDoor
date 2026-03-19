use rand::rngs::OsRng;
pub use x25519_dalek::{PublicKey, StaticSecret}; // Re-export publicly

// X25519 Key Exchange
pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn diffie_hellman(secret: &StaticSecret, public: &PublicKey) -> [u8; 32] {
    *secret.diffie_hellman(public).as_bytes()
}
