use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub version: u8, // Added versioning for future upgrades
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: [u8; 32],
    pub hash: [u8; 32],
    pub data: Vec<u8>,       // Serialized Transaction
    pub signature: Vec<u8>,  // Block signature (by the node)
    pub signer_pub: Vec<u8>, // Signer's public key bytes (Ed25519)
}

impl Block {
    pub fn new(
        index: u64,
        timestamp: u64,
        previous_hash: [u8; 32],
        data: Vec<u8>,
        node_keypair: &SigningKey,
    ) -> Self {
        let signer_pub = node_keypair.verifying_key().to_bytes().to_vec();
        let mut block = Self {
            version: 1,
            index,
            timestamp,
            previous_hash,
            hash: [0; 32],
            data,
            signature: Vec::new(),
            signer_pub,
        };
        block.calculate_hash();
        block.sign(node_keypair);
        block
    }

    pub fn calculate_hash(&mut self) {
        let mut hasher = Hasher::new();
        hasher.update(&[self.version]); // Include version in hash
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.previous_hash);
        hasher.update(&self.data);
        self.hash = *hasher.finalize().as_bytes();
    }

    pub fn sign(&mut self, keypair: &SigningKey) {
        self.signature = keypair.sign(&self.hash).to_bytes().to_vec();
        self.signer_pub = keypair.verifying_key().to_bytes().to_vec();
    }
}
