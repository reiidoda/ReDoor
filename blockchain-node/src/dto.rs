use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    #[serde(alias = "sender_id")]
    pub signer_id: String, // Hex encoded public key (ephemeral)
    pub message_hash: String, // Hex encoded
    pub signature: String,    // Hex encoded signature of (message_hash + timestamp)
    pub timestamp: u64,
    #[serde(default, alias = "receiver_id")]
    pub receiver_commitment: String, // Hex encoded blinded receiver commitment
    #[serde(default)]
    pub pq_pub_b64: Option<String>, // Optional PQ pubkey (base64)
    #[serde(default)]
    pub pq_sig_b64: Option<String>, // Optional PQ signature (base64)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DelegatedCoSignature {
    #[serde(alias = "sender_id")]
    pub signer_id: String, // Hex encoded public key (ephemeral)
    pub signature: String, // Hex encoded signature over delegated payload
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DelegatedCommitmentRequest {
    #[serde(alias = "sender_id")]
    pub origin_signer_id: String, // Hex encoded public key (ephemeral)
    pub message_hash: String,     // Hex encoded
    pub origin_signature: String, // Hex encoded signature over delegated payload
    pub timestamp: u64,
    #[serde(default, alias = "receiver_id")]
    pub receiver_commitment: String, // Hex encoded blinded receiver commitment
    #[serde(default)]
    pub auth_threshold: Option<u8>, // Optional requested threshold (1..=32)
    #[serde(default)]
    pub co_signatures: Vec<DelegatedCoSignature>, // Optional additional authorizers
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedBlockRequest {
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash_hex: String, // 32-byte hex
    pub hash_hex: String,          // 32-byte hex
    pub data_b64: String,          // base64 encoded data (serialized transaction or payload)
    pub signature_hex: String,     // 64-byte hex signature of block.hash
    pub signer_pub_hex: String,    // 32-byte hex public key of signer
}
