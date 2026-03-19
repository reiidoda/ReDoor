use anyhow::{anyhow, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::Digest;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Generates a new random Ed25519 signing key (private key).
pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Signs a message with the private key. Returns a 64-byte signature.
pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Verifies a signature against a public key and message.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let public_key_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let signature_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key.verify(message, &signature).is_ok()
}

/// Helper to extract public key bytes from a signing key.
pub fn to_public_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

pub type PublicKey = VerifyingKey;

#[derive(Clone)]
pub struct IdentityKey(pub SigningKey);

impl IdentityKey {
    pub fn generate() -> Self {
        Self(generate_keypair())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        to_public_bytes(&self.0)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        sign(&self.0, message).to_vec()
    }

    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if verify(public_key, message, signature) {
            Ok(())
        } else {
            Err(anyhow!("Signature verification failed"))
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid key length"))?;
        Ok(Self(SigningKey::from_bytes(&key)))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes().to_vec())
    }

    /// Converts the Ed25519 private key to an X25519 private key (StaticSecret)
    /// for use in the X3DH handshake.
    pub fn to_x25519_private(&self) -> StaticSecret {
        let hash = sha2::Sha512::digest(self.0.to_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[0..32]);
        StaticSecret::from(bytes)
    }
}

pub trait ToX25519 {
    fn to_x25519_public(&self) -> Result<X25519PublicKey>;
}

impl ToX25519 for PublicKey {
    fn to_x25519_public(&self) -> Result<X25519PublicKey> {
        let bytes = self.to_bytes();
        let point = CompressedEdwardsY::from_slice(&bytes)?
            .decompress()
            .ok_or(anyhow!("Invalid Ed25519 public key"))?;
        let montgomery = point.to_montgomery();
        Ok(X25519PublicKey::from(montgomery.to_bytes()))
    }
}
