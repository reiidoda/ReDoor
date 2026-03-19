use super::block::Block;
use crate::metrics;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const CHAIN_FILE: &str = "blockchain.json";

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub node_keypair: SigningKey,
    pub index_by_hash: HashMap<[u8; 32], u64>,
}

#[cfg(test)]
mod tests;

impl Blockchain {
    pub fn new() -> Self {
        // Try to load or generate a persistent node signing key
        let key_file =
            std::env::var("NODE_KEY_FILE").unwrap_or_else(|_| "node_key.hex".to_string());
        let keypair: SigningKey = if std::path::Path::new(&key_file).exists() {
            match std::fs::read_to_string(&key_file) {
                Ok(s) => {
                    let s = s.trim();
                    match hex::decode(s) {
                        Ok(bytes) => {
                            let arr: [u8; 32] = bytes
                                .as_slice()
                                .try_into()
                                .expect("node key file must contain 32 bytes hex");
                            SigningKey::from_bytes(&arr)
                        }
                        Err(e) => {
                            eprintln!("Failed to decode node key file: {}", e);
                            let mut csprng = OsRng {};
                            SigningKey::generate(&mut csprng)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read node key file: {}", e);
                    let mut csprng = OsRng {};
                    SigningKey::generate(&mut csprng)
                }
            }
        } else {
            // generate and persist
            let mut csprng = OsRng {};
            let sk = SigningKey::generate(&mut csprng);
            let hex_s = hex::encode(sk.to_bytes());
            // write atomically
            let _ = std::fs::write(&key_file, hex_s);
            sk
        };

        // Try to load existing chain
        let mut chain = vec![];
        if Path::new(CHAIN_FILE).exists() {
            match Self::load_chain() {
                Ok(c) => {
                    println!("Loaded blockchain from disk. Height: {}", c.len());
                    chain = c;
                }
                Err(e) => {
                    eprintln!("Failed to load blockchain: {}", e);
                    // Fallback to genesis if load fails
                }
            }
        }

        if chain.is_empty() {
            // Genesis block is signed by the node itself for now
            let genesis_block = Block::new(0, 0, [0; 32], b"Genesis Block".to_vec(), &keypair);
            chain.push(genesis_block);
            Self::save_chain(&chain);
        }

        let mut index_by_hash = HashMap::new();
        for block in &chain {
            index_by_hash.insert(block.hash, block.index);
        }

        Self {
            chain,
            node_keypair: keypair,
            index_by_hash,
        }
    }

    /// Create and append a new block signed by the local node keypair.
    pub fn add_block(&mut self, data: Vec<u8>) {
        let previous_block = self.chain.last().unwrap();
        let index = previous_block.index + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Epoch-based logging: Round to nearest 10 minutes (600s) to reduce timing metadata
        let timestamp = (now / 600) * 600;
        let previous_hash = previous_block.hash;

        // If the caller already provided a 32-byte message hash, store it directly.
        // Otherwise compute a BLAKE3 hash of the provided payload and store that hash on-chain.
        let message_hash_vec: Vec<u8> = if data.len() == 32 {
            data
        } else {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&data);
            let msg_hash = *hasher.finalize().as_bytes();
            msg_hash.to_vec()
        };

        let new_block = Block::new(
            index,
            timestamp,
            previous_hash,
            message_hash_vec,
            &self.node_keypair,
        );
        self.index_by_hash.insert(new_block.hash, new_block.index);
        self.chain.push(new_block.clone());
        println!(
            "Block #{} added to chain. Hash: {:?}",
            index,
            hex::encode(new_block.hash)
        );
        // metrics
        metrics::inc_blocks_appended();

        Self::save_chain(&self.chain);
    }

    /// Validate and append a pre-signed block. This will verify the block hash,
    /// the block signature, and that the signing public key is an authorized validator.
    pub fn add_signed_block(&mut self, block: Block) -> Result<(), String> {
        // Basic chain linkage checks
        let previous_block = self.chain.last().unwrap();
        if block.previous_hash != previous_block.hash {
            return Err("previous_hash mismatch".to_string());
        }

        // Recalculate hash to ensure integrity
        let mut temp_block = block.clone();
        let original_hash = temp_block.hash;
        temp_block.calculate_hash();
        if temp_block.hash != original_hash {
            return Err("block hash mismatch".to_string());
        }

        // Use signer_pub from the block
        let signer_pubkey = &block.signer_pub;
        let pk_arr: [u8; 32] = signer_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signer public key length".to_string())?;

        // Verify signature using provided public key
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|_| "invalid signer public key format".to_string())?;

        // Convert signature Vec<u8> to [u8;64]
        let sig_arr: [u8; 64] = block
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signature length".to_string())?;

        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

        if let Err(_) = vk.verify(&block.hash, &sig) {
            return Err("signature verification failed".to_string());
        }

        // Check consensus (is signer authorized?)
        if !crate::consensus::validate_signer(
            crate::consensus::ConsensusEngine::Authority,
            signer_pubkey,
        ) {
            return Err("signer is not an authorized validator".to_string());
        }

        // Passed all checks; append
        self.index_by_hash.insert(block.hash, block.index);
        self.chain.push(block.clone());
        println!(
            "Signed block #{} appended to chain. Hash: {:?}",
            block.index,
            hex::encode(block.hash)
        );
        metrics::inc_signed_blocks_appended();

        Self::save_chain(&self.chain);
        Ok(())
    }

    fn save_chain(chain: &Vec<Block>) {
        let serialized = serde_json::to_string(chain).unwrap();
        // Atomic write: write to temp file then rename
        let temp_file = format!("{}.tmp", CHAIN_FILE);
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file)
        {
            if file.write_all(serialized.as_bytes()).is_ok() {
                let _ = fs::rename(&temp_file, CHAIN_FILE);
            }
        }
    }

    fn load_chain() -> Result<Vec<Block>, Box<dyn std::error::Error>> {
        let mut file = File::open(CHAIN_FILE)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let chain: Vec<Block> = serde_json::from_str(&contents)?;
        Ok(chain)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            if current_block.previous_hash != previous_block.hash {
                return false;
            }

            // Verify hash integrity
            let mut temp_block = current_block.clone();
            // We need to recalculate hash to verify integrity, but we can't easily re-sign without the key if we were just validating.
            // However, since we are the node, we can just check if the hash matches the data.
            // The signature verification would happen against the public key of the signer.

            // For internal integrity check:
            let original_hash = temp_block.hash;
            temp_block.calculate_hash();
            if temp_block.hash != original_hash {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn fuzz_block_validation() {
        let mut chain = Blockchain::new();
        let mut rng = rand::thread_rng();

        for _ in 0..50 {
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            let mut prev_hash = [0u8; 32];
            rng.fill(&mut prev_hash);
            let mut signature = [0u8; 64];
            rng.fill(&mut signature);
            let mut signer = [0u8; 32];
            rng.fill(&mut signer);

            let data_len = rng.gen_range(0..512);
            let mut data = vec![0u8; data_len];
            rng.fill(&mut data[..]);

            let block = Block {
                version: rng.gen(),
                index: rng.gen(),
                timestamp: rng.gen(),
                previous_hash: prev_hash,
                hash,
                data,
                signature: signature.to_vec(),
                signer_pub: signer.to_vec(),
            };

            // Ensure invalid blocks are rejected without panicking
            let res = chain.add_signed_block(block);
            assert!(res.is_err());
        }
    }
}
