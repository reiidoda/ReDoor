#![allow(dead_code)]

use crate::crypto::chacha20poly1305;
use crate::crypto::x25519;
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

// Double Ratchet Implementation
// We derive Zeroize and ZeroizeOnDrop to ensure keys are wiped from memory when the session is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RatchetSession {
    // DH Ratchet
    #[zeroize(skip)] // StaticSecret handles its own zeroization
    dh_pair: StaticSecret,
    #[zeroize(skip)] // Public keys don't need zeroization
    dh_remote: Option<PublicKey>,

    // Symmetric Ratchet
    root_key: [u8; 32],
    chain_key_send: [u8; 32],
    chain_key_recv: [u8; 32],

    // Message Keys
    next_header_key_send: [u8; 32],
    next_header_key_recv: [u8; 32],

    // Metrics
    pub msg_count_send: u32,
    pub msg_count_recv: u32,
    pub created_at: u64,
}

impl RatchetSession {
    pub fn new(shared_secret: [u8; 32], peer_public_key: Option<PublicKey>) -> Self {
        let (dh_secret, _) = x25519::generate_keypair();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Initialize both send/recv chain keys with the shared secret so the first
        // message can be encrypted immediately. A DH ratchet will quickly replace
        // these values during the session.
        Self {
            dh_pair: dh_secret,
            dh_remote: peer_public_key,
            root_key: shared_secret,
            chain_key_send: shared_secret,
            chain_key_recv: shared_secret,
            next_header_key_send: [0; 32],
            next_header_key_recv: [0; 32],
            msg_count_send: 0,
            msg_count_recv: 0,
            created_at,
        }
    }

    // KDF for Root Key
    fn kdf_rk(&mut self, dh_out: [u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        // Simplified HKDF using HMAC-SHA256
        // In production, use proper HKDF expansion
        let mut mac =
            HmacSha256::new_from_slice(&self.root_key).map_err(|_| anyhow!("HMAC init failed"))?;
        mac.update(&dh_out);
        let result = mac.finalize().into_bytes();

        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(result.as_slice());

        // Derive a fresh chain key by re-running HMAC with different info byte.
        let mut mac_chain =
            HmacSha256::new_from_slice(&root_key).map_err(|_| anyhow!("HMAC init failed"))?;
        mac_chain.update(b"chain");
        let chain_bytes = mac_chain.finalize().into_bytes();
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(chain_bytes.as_slice());

        Ok((root_key, chain_key))
    }

    // KDF for Chain Key
    fn kdf_ck(&mut self, chain_key: [u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        let mut mac =
            HmacSha256::new_from_slice(&chain_key).map_err(|_| anyhow!("HMAC init failed"))?;
        mac.update(b"\x01");
        let next_chain_key_bytes = mac.finalize().into_bytes();

        let mut mac =
            HmacSha256::new_from_slice(&chain_key).map_err(|_| anyhow!("HMAC init failed"))?;
        mac.update(b"\x02");
        let message_key_bytes = mac.finalize().into_bytes();

        let mut next_chain_key = [0u8; 32];
        next_chain_key.copy_from_slice(next_chain_key_bytes.as_slice());

        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(message_key_bytes.as_slice());

        Ok((next_chain_key, message_key))
    }

    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (next_chain, message_key) = self.kdf_ck(self.chain_key_send)?;
        self.chain_key_send = next_chain;
        self.msg_count_send += 1;

        let (ciphertext, nonce) = chacha20poly1305::encrypt(&message_key, plaintext)?;

        // We need to return nonce + ciphertext so the receiver can decrypt
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    pub fn ratchet_decrypt(&mut self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(anyhow!("Ciphertext too short"));
        }
        let (nonce, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce_arr: [u8; 12] = nonce.try_into()?;

        let (next_chain, message_key) = self.kdf_ck(self.chain_key_recv)?;

        // Decrypt first. If this fails (e.g. bad auth tag), we must NOT advance the ratchet.
        let plaintext = chacha20poly1305::decrypt(&message_key, ciphertext, &nonce_arr)?;

        self.chain_key_recv = next_chain;
        self.msg_count_recv += 1;

        Ok(plaintext)
    }

    // Diffie-Hellman Ratchet Step
    pub fn dh_ratchet(&mut self, remote_public: PublicKey) -> Result<()> {
        self.dh_remote = Some(remote_public);
        let dh_out = x25519::diffie_hellman(&self.dh_pair, &remote_public);

        let (next_root, next_chain_recv) = self.kdf_rk(dh_out.into())?;
        self.root_key = next_root;
        self.chain_key_recv = next_chain_recv;

        let (new_pair, _) = x25519::generate_keypair();
        self.dh_pair = new_pair;
        let dh_out_send = x25519::diffie_hellman(&self.dh_pair, &remote_public);

        let (next_root_send, next_chain_send) = self.kdf_rk(dh_out_send.into())?;
        self.root_key = next_root_send;
        self.chain_key_send = next_chain_send;

        Ok(())
    }

    /// Performs a runtime consistency check on the session state.
    /// Returns true if the state appears valid, false if corruption is detected.
    pub fn verify_integrity(&self) -> bool {
        let zero = [0u8; 32];
        // Root key should not be zero if we have activity
        if self.root_key == zero && (self.msg_count_send > 0 || self.msg_count_recv > 0) {
            return false;
        }
        // Chain keys should not be zero if we have activity
        if self.chain_key_send == zero && self.msg_count_send > 0 {
            return false;
        }
        if self.chain_key_recv == zero && self.msg_count_recv > 0 {
            return false;
        }
        true
    }

    /// Serializes the session state to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let s = SerializedRatchetSession {
            dh_pair_secret: self.dh_pair.to_bytes(),
            dh_remote: self.dh_remote.map(|k| k.to_bytes()),
            root_key: self.root_key,
            chain_key_send: self.chain_key_send,
            chain_key_recv: self.chain_key_recv,
            next_header_key_send: self.next_header_key_send,
            next_header_key_recv: self.next_header_key_recv,
            msg_count_send: self.msg_count_send,
            msg_count_recv: self.msg_count_recv,
            created_at: self.created_at,
        };
        Ok(serde_json::to_vec(&s)?)
    }

    /// Restores the session state from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let s: SerializedRatchetSession = serde_json::from_slice(data)?;
        Ok(Self {
            dh_pair: StaticSecret::from(s.dh_pair_secret),
            dh_remote: s.dh_remote.map(PublicKey::from),
            root_key: s.root_key,
            chain_key_send: s.chain_key_send,
            chain_key_recv: s.chain_key_recv,
            next_header_key_send: s.next_header_key_send,
            next_header_key_recv: s.next_header_key_recv,
            msg_count_send: s.msg_count_send,
            msg_count_recv: s.msg_count_recv,
            created_at: s.created_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SerializedRatchetSession {
    dh_pair_secret: [u8; 32],
    dh_remote: Option<[u8; 32]>,
    root_key: [u8; 32],
    chain_key_send: [u8; 32],
    chain_key_recv: [u8; 32],
    next_header_key_send: [u8; 32],
    next_header_key_recv: [u8; 32],
    #[serde(default)]
    msg_count_send: u32,
    #[serde(default)]
    msg_count_recv: u32,
    #[serde(default)]
    created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::RatchetSession;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let shared_secret = [7u8; 32];
        let mut sender = RatchetSession::new(shared_secret, None);
        let mut receiver = RatchetSession::new(shared_secret, None);

        let plaintext = b"forward secrecy";
        let ciphertext = sender.ratchet_encrypt(plaintext).expect("encrypt");
        let decrypted = receiver.ratchet_decrypt(&ciphertext).expect("decrypt");

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
