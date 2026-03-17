use crate::blockchain_client::verify_blockchain::BlockchainClient;
use crate::crypto;
use crate::network;
use crate::network::onion::OnionRouter;
use crate::network::p2p::P2PClient;
use crate::orchestrator;
use crate::ratchet;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use x25519_dalek::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageSignaturePolicy {
    DeniableDefault,
    Enforce,
}

fn parse_message_signature_policy(raw: Option<&str>) -> MessageSignaturePolicy {
    match raw
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("enforce") | Some("required") | Some("strict") => MessageSignaturePolicy::Enforce,
        _ => MessageSignaturePolicy::DeniableDefault,
    }
}

fn message_signature_policy() -> MessageSignaturePolicy {
    parse_message_signature_policy(
        std::env::var("REDOOR_MESSAGE_SIGNATURE_POLICY")
            .ok()
            .as_deref(),
    )
}

fn verify_optional_message_signature(
    sender_public_key: &[u8],
    ciphertext: &[u8],
    signature: Option<&[u8]>,
    policy: MessageSignaturePolicy,
) -> Result<()> {
    match policy {
        // Deniable by default: do not accept/reject based on globally verifiable signatures.
        MessageSignaturePolicy::DeniableDefault => Ok(()),
        MessageSignaturePolicy::Enforce => {
            let signature = signature.filter(|value| !value.is_empty()).ok_or_else(|| {
                anyhow::anyhow!(
                    "message signature is required when REDOOR_MESSAGE_SIGNATURE_POLICY=enforce"
                )
            })?;
            crypto::ed25519::IdentityKey::verify(sender_public_key, ciphertext, signature)
        }
    }
}

// Non-interactive end-to-end send/receive for embedding (e.g., iOS).
pub async fn scripted_loopback(msg_text: &str) -> Result<()> {
    let relay_url = crate::config::default_relay_url();
    let blockchain_url = crate::config::default_blockchain_url();
    scripted_loopback_custom(&relay_url, &blockchain_url, msg_text, false, false).await
}

pub async fn scripted_loopback_onion(msg_text: &str) -> Result<()> {
    let relay_url = crate::config::default_relay_url();
    let blockchain_url = crate::config::default_blockchain_url();
    scripted_loopback_custom(&relay_url, &blockchain_url, msg_text, true, false).await
}

pub async fn scripted_loopback_p2p(msg_text: &str) -> Result<()> {
    let relay_url = crate::config::default_relay_url();
    let blockchain_url = crate::config::default_blockchain_url();
    scripted_loopback_custom(&relay_url, &blockchain_url, msg_text, false, true).await
}

// Same flow but caller supplies endpoints (used by FFI for mobile).
pub async fn scripted_loopback_custom(
    relay_url: &str,
    blockchain_addr: &str,
    msg_text: &str,
    onion_route: bool,
    p2p_mode: bool,
) -> Result<()> {
    let relay_client = network::relay::RelayClient::new(relay_url);
    let blockchain_client = BlockchainClient::new(blockchain_addr.to_string());

    // Hardcoded relay nodes
    let nodes = vec![
        (
            "http://localhost:8081".to_string(),
            PublicKey::from([0; 32]),
        ),
        (
            "http://localhost:8082".to_string(),
            PublicKey::from([0; 32]),
        ),
        (
            "http://localhost:8083".to_string(),
            PublicKey::from([0; 32]),
        ),
    ];
    let onion_router = OnionRouter::new(nodes);

    // Hardcoded peer multiaddresses
    let mut peer_addrs = HashMap::new();
    let p2p_client = P2PClient::new().await?;
    let local_peer_id = p2p_client.local_peer_id_base58();
    let local_addr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", local_peer_id);
    peer_addrs.insert(local_peer_id, local_addr);

    // Identity
    let id = crypto::ed25519::IdentityKey::generate();
    let receiver_id = hex::encode(id.public_key_bytes());

    // Classical X25519
    let (my_secret, my_public) = crypto::x25519::generate_keypair();
    let shared_secret_classic = crypto::x25519::diffie_hellman(&my_secret, &my_public);

    // Optional PQ hybrid (runtime-toggle-aware)
    // For now, just use classic secret as we removed hybrid module
    let combined_secret = shared_secret_classic;

    // Session
    let mut session =
        ratchet::double_ratchet::RatchetSession::new(combined_secret, Some(my_public));

    // Encrypt
    let ciphertext = session.ratchet_encrypt(msg_text.as_bytes())?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    #[derive(Serialize, Deserialize)]
    struct Envelope {
        sender_id: String,
        receiver_id: String,
        timestamp: u64,
        ciphertext: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<Vec<u8>>,
    }

    let envelope = Envelope {
        sender_id: hex::encode(id.public_key_bytes()),
        receiver_id: receiver_id.clone(),
        timestamp,
        ciphertext: ciphertext.clone(),
        // Keep signatures optional for deniable transcripts. Ratchet AEAD already
        // authenticates ciphertext to the active session state.
        signature: None,
    };
    let serialized = serde_json::to_vec(&envelope)?;
    let msg_hash = crypto::blake3::hash(&serialized);
    let msg_id_hex = hex::encode(msg_hash);

    // Send to relay with retries
    if p2p_mode {
        let target_addr = peer_addrs.values().next().unwrap();
        orchestrator::send_p2p_blob_with_retry(
            &p2p_client,
            target_addr,
            &serialized,
            3,
            Duration::from_millis(200),
            Duration::from_secs(3),
        )
        .await?;
    } else if onion_route {
        orchestrator::send_onion_blob_with_retry(
            &onion_router,
            &relay_client,
            &msg_id_hex,
            &receiver_id,
            &serialized,
            3,
            Duration::from_millis(200),
            Duration::from_secs(3),
        )
        .await?;
    } else {
        orchestrator::send_blob_with_retry(
            &relay_client,
            &msg_id_hex,
            &receiver_id,
            &serialized,
            3,
            Duration::from_millis(200),
            Duration::from_secs(3),
        )
        .await?;
    }

    // Log to blockchain
    orchestrator::submit_tx_with_retry(
        &blockchain_client,
        &id,
        receiver_id.clone(),
        &msg_hash,
        3,
        Duration::from_millis(200),
        Duration::from_secs(2),
    )
    .await?;

    // Fetch pending
    let (_id, blob) = orchestrator::fetch_pending_with_retry(
        &relay_client,
        &receiver_id,
        5,
        Duration::from_millis(200),
        Duration::from_secs(3),
    )
    .await?;

    // Verify hash
    let computed_hash = crypto::blake3::hash(&blob);
    if computed_hash != msg_hash {
        anyhow::bail!("hash mismatch in scripted loopback");
    }

    let env: Envelope = serde_json::from_slice(&blob)?;
    let sender_pk = hex::decode(env.sender_id)?;
    verify_optional_message_signature(
        &sender_pk,
        &env.ciphertext,
        env.signature.as_deref(),
        message_signature_policy(),
    )?;

    let plaintext = session.ratchet_decrypt(&env.ciphertext)?;
    let msg_out = String::from_utf8_lossy(&plaintext);
    println!("Decrypted message: {}", msg_out);
    if msg_out != msg_text {
        anyhow::bail!("decrypted text mismatch");
    }

    // Small pause to let logs flush in embedded contexts
    sleep(Duration::from_millis(10)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_message_signature_policy, verify_optional_message_signature, MessageSignaturePolicy,
    };
    use crate::crypto::ed25519::IdentityKey;

    #[test]
    fn deniable_policy_accepts_missing_signature() {
        let identity = IdentityKey::generate();
        let sender_pk = identity.public_key_bytes();

        let result = verify_optional_message_signature(
            &sender_pk,
            b"ciphertext",
            None,
            MessageSignaturePolicy::DeniableDefault,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn deniable_policy_ignores_invalid_signature() {
        let identity = IdentityKey::generate();
        let sender_pk = identity.public_key_bytes();
        let invalid_signature = [7_u8; 64];

        let result = verify_optional_message_signature(
            &sender_pk,
            b"ciphertext",
            Some(&invalid_signature),
            MessageSignaturePolicy::DeniableDefault,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn enforce_policy_rejects_missing_signature() {
        let identity = IdentityKey::generate();
        let sender_pk = identity.public_key_bytes();

        let result = verify_optional_message_signature(
            &sender_pk,
            b"ciphertext",
            None,
            MessageSignaturePolicy::Enforce,
        );

        assert!(result.is_err());
    }

    #[test]
    fn enforce_policy_accepts_valid_signature() {
        let identity = IdentityKey::generate();
        let sender_pk = identity.public_key_bytes();
        let ciphertext = b"ciphertext";
        let signature = identity.sign(ciphertext);

        let result = verify_optional_message_signature(
            &sender_pk,
            ciphertext,
            Some(&signature),
            MessageSignaturePolicy::Enforce,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn parse_signature_policy_defaults_to_deniable() {
        assert_eq!(
            parse_message_signature_policy(None),
            MessageSignaturePolicy::DeniableDefault
        );
        assert_eq!(
            parse_message_signature_policy(Some("disabled")),
            MessageSignaturePolicy::DeniableDefault
        );
    }

    #[test]
    fn parse_signature_policy_supports_enforce_aliases() {
        assert_eq!(
            parse_message_signature_policy(Some("enforce")),
            MessageSignaturePolicy::Enforce
        );
        assert_eq!(
            parse_message_signature_policy(Some("required")),
            MessageSignaturePolicy::Enforce
        );
        assert_eq!(
            parse_message_signature_policy(Some("strict")),
            MessageSignaturePolicy::Enforce
        );
    }
}
