use super::Blockchain;
use ed25519_dalek::Verifier;

#[test]
fn chain_integrity_holds_after_append() {
    let mut bc = Blockchain::new();
    bc.add_block(b"tx1".to_vec());
    bc.add_block(b"tx2".to_vec());
    assert!(bc.is_valid(), "chain should remain valid after appends");
}

#[test]
fn block_signature_verifies() {
    let mut bc = Blockchain::new();
    bc.add_block(b"tx".to_vec());
    let last = bc.chain.last().unwrap();
    let vk = bc.node_keypair.verifying_key();
    let sig_bytes: [u8; 64] = last.signature.clone().try_into().expect("sig length");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    assert!(
        vk.verify(&last.hash, &sig).is_ok(),
        "block signature must verify with node public key"
    );
}

#[test]
fn tamper_detection_fails_validation() {
    let mut bc = Blockchain::new();
    bc.add_block(b"tx".to_vec());
    // Corrupt the second block's data
    if bc.chain.len() > 1 {
        bc.chain[1].data = b"tampered".to_vec();
    }
    assert!(
        !bc.is_valid(),
        "is_valid must fail when data/hash linkage is broken"
    );
}

#[test]
fn add_block_does_not_store_clear_receiver_metadata() {
    let mut bc = Blockchain::new();
    let receiver = "receiver-cleartext-id";
    let payload = format!(r#"{{"receiver_id":"{receiver}","message":"opaque"}}"#).into_bytes();

    bc.add_block(payload.clone());
    let last = bc.chain.last().expect("last block");

    // Non-32-byte payloads are reduced to a fixed hash before persistence.
    assert_eq!(last.data.len(), 32);
    assert_ne!(last.data, payload);
    assert!(
        !String::from_utf8_lossy(&last.data).contains(receiver),
        "clear receiver identifier must not be persisted on-chain"
    );
}
