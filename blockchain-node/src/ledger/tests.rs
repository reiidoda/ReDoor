use super::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[test]
fn test_add_signed_block_authorized() {
    // Create a chain and keypair for signer
    let mut csprng = OsRng {};
    let signer_sk = SigningKey::generate(&mut csprng);
    let signer_pk = VerifyingKey::from(&signer_sk);

    // Create an empty chain with genesis
    let mut chain = Blockchain::new();

    // Prepare data and create a block signed by signer
    let prev = chain.chain.last().unwrap().hash;
    let index = chain.chain.last().unwrap().index + 1;
    let ts = 1u64;
    let data = b"test data".to_vec();

    let mut block = super::block::Block::new(index, ts, prev, data.clone(), &chain.node_keypair);
    // Overwrite signature to be from signer_sk
    block.sign(&signer_sk);

    // Initialize validators with signer's public key
    let pk_bytes = signer_pk.to_bytes().to_vec();
    crate::consensus::authority::init_validators(vec![pk_bytes.clone()]);

    // Attempt to append signed block
    let res = chain.add_signed_block(block);
    assert!(res.is_ok());
}

#[test]
fn test_add_signed_block_unauthorized() {
    let mut csprng = OsRng {};
    let signer_sk = SigningKey::generate(&mut csprng);
    let signer_pk = VerifyingKey::from(&signer_sk);

    let mut chain = Blockchain::new();

    let prev = chain.chain.last().unwrap().hash;
    let index = chain.chain.last().unwrap().index + 1;
    let ts = 2u64;
    let data = b"test data unauthorized".to_vec();

    let mut block = super::block::Block::new(index, ts, prev, data.clone(), &chain.node_keypair);
    block.sign(&signer_sk);

    // Do not initialize validators (or init with different key)
    crate::consensus::authority::init_validators(vec![b"some-other-key".to_vec()]);

    let pk_bytes = signer_pk.to_bytes().to_vec();
    let res = chain.add_signed_block(block);
    assert!(res.is_err());
}

#[test]
fn test_add_signed_block_bad_signature() {
    let mut csprng = OsRng {};
    let signer_sk = SigningKey::generate(&mut csprng);
    let signer_pk = VerifyingKey::from(&signer_sk);

    let mut chain = Blockchain::new();

    let prev = chain.chain.last().unwrap().hash;
    let index = chain.chain.last().unwrap().index + 1;
    let ts = 3u64;
    let data = b"test data bad sig".to_vec();

    let mut block = super::block::Block::new(index, ts, prev, data.clone(), &chain.node_keypair);
    // Corrupt signature by hashing different data
    block.signature = vec![0u8; 64];

    // Initialize validators with signer's public key
    let pk_bytes = signer_pk.to_bytes().to_vec();
    crate::consensus::authority::init_validators(vec![pk_bytes.clone()]);

    let res = chain.add_signed_block(block);
    assert!(res.is_err());
}
