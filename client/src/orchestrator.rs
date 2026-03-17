use crate::blockchain_client::verify_blockchain::BlockchainClient;
use crate::crypto::ed25519::IdentityKey;
use crate::network::directory::DirectoryClient;
use crate::network::onion::OnionRouter;
use crate::network::p2p::P2PClient;
use crate::network::relay::RelayClient;
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

/// Sends an encrypted blob to the relay with retry logic.
pub async fn send_blob_with_retry(
    client: &RelayClient,
    msg_id: &str,
    receiver_id: &str,
    blob: &[u8],
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<()> {
    let mut attempt = 0;
    loop {
        match tokio::time::timeout(timeout, client.send_blob(msg_id, receiver_id, blob)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => {
                if attempt >= retries {
                    return Err(e).context("Max retries reached for send_blob");
                }
            }
            Err(_) => {
                if attempt >= retries {
                    return Err(anyhow!("Timeout sending blob"));
                }
            }
        }
        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}

pub async fn send_onion_blob_with_retry(
    router: &OnionRouter,
    client: &RelayClient,
    msg_id: &str,
    receiver_id: &str,
    blob: &[u8],
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<()> {
    let (entry_node, onion) = router.build_circuit(receiver_id, blob, 3)?;
    let entry_client = if entry_node == client.base_url {
        client.clone()
    } else {
        RelayClient::new(&entry_node)
    };
    let mut attempt = 0;
    loop {
        // Mix packet destination is encoded end-to-end in packet layers;
        // transport receiver stays opaque at each hop.
        match tokio::time::timeout(timeout, entry_client.send_blob(msg_id, "__mix__", &onion)).await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => {
                if attempt >= retries {
                    return Err(e).context("Max retries reached for send_blob");
                }
            }
            Err(_) => {
                if attempt >= retries {
                    return Err(anyhow!("Timeout sending blob"));
                }
            }
        }
        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}

pub async fn send_p2p_blob_with_retry(
    client: &P2PClient,
    target: &str,
    blob: &[u8],
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<()> {
    let mut attempt = 0;
    loop {
        match tokio::time::timeout(timeout, client.send_once(target, blob)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => {
                if attempt >= retries {
                    return Err(e).context("Max retries reached for send_p2p_blob");
                }
            }
            Err(_) => {
                if attempt >= retries {
                    return Err(anyhow!("Timeout sending p2p blob"));
                }
            }
        }
        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}

/// Fetches a pending message from the relay with retry logic.
pub async fn fetch_pending_with_retry(
    client: &RelayClient,
    receiver_id: &str,
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<(String, Vec<u8>)> {
    let mut attempt = 0;
    loop {
        match tokio::time::timeout(timeout, client.fetch_pending(receiver_id)).await {
            Ok(Ok(res)) => return Ok(res),
            Ok(Err(e)) => {
                if attempt >= retries {
                    return Err(e);
                }
            }
            Err(_) => {
                if attempt >= retries {
                    return Err(anyhow!("Timeout fetching pending"));
                }
            }
        }
        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}

#[derive(Serialize)]
struct BlockchainEntry {
    message_hash: String,
    sender_id: String,
    receiver_commitment: String,
    timestamp: u64,
    signature: String,
}

#[derive(Serialize)]
struct DelegatedCoSignature {
    signer_id: String,
    signature: String,
}

#[derive(Serialize)]
struct DelegatedBlockchainEntry {
    origin_signer_id: String,
    message_hash: String,
    receiver_commitment: String,
    timestamp: u64,
    origin_signature: String,
    auth_threshold: u8,
    co_signatures: Vec<DelegatedCoSignature>,
}

fn delegated_commitment_endpoint(base_url: &str) -> String {
    let normalized = base_url.trim_end_matches('/');
    if normalized.ends_with("/delegate/commitment") {
        normalized.to_string()
    } else {
        format!("{}/delegate/commitment", normalized)
    }
}

fn delegated_signing_payload(
    timestamp: u64,
    sender_pubkey: &[u8],
    receiver_commitment: &str,
    message_hash: &[u8; 32],
    auth_threshold: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(sender_pubkey);
    payload.extend_from_slice(receiver_commitment.as_bytes());
    payload.extend_from_slice(message_hash);
    payload.push(auth_threshold);
    payload
}

fn build_delegate_cosignatures(payload: &[u8]) -> Result<Vec<DelegatedCoSignature>> {
    let Some(raw_keys) = crate::config::blockchain_commitment_cosigner_secrets_hex() else {
        return Ok(Vec::new());
    };

    let mut signatures = Vec::new();
    for (idx, key_hex) in raw_keys
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .enumerate()
    {
        let key_bytes = hex::decode(key_hex).with_context(|| {
            format!(
                "Invalid REDOOR_COMMITMENT_COSIGNER_SECRETS_HEX entry {}",
                idx + 1
            )
        })?;
        if key_bytes.len() != 32 {
            return Err(anyhow!(
                "REDOOR_COMMITMENT_COSIGNER_SECRETS_HEX entry {} must be 32-byte Ed25519 secret key hex",
                idx + 1
            ));
        }

        let signer = IdentityKey::from_bytes(&key_bytes).with_context(|| {
            format!(
                "Invalid REDOOR_COMMITMENT_COSIGNER_SECRETS_HEX entry {}",
                idx + 1
            )
        })?;
        signatures.push(DelegatedCoSignature {
            signer_id: hex::encode(signer.public_key_bytes()),
            signature: hex::encode(signer.sign(payload)),
        });
    }

    Ok(signatures)
}

async fn post_json_with_retry<T: Serialize>(
    http_client: &reqwest::Client,
    url: &str,
    body: &T,
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<()> {
    let mut attempt = 0;
    loop {
        let req = http_client.post(url).json(body);
        let send_result = tokio::time::timeout(timeout, req.send()).await;
        if let Ok(Ok(response)) = send_result {
            if response.status().is_success() {
                return Ok(());
            }
        }

        if attempt >= retries {
            return Err(anyhow!("Failed to submit request to {}", url));
        }
        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}

/// Submits a transaction log to the blockchain node with retry logic.
pub async fn submit_tx_with_retry(
    client: &BlockchainClient,
    sender_id: &IdentityKey,
    receiver_id: String,
    msg_hash: &[u8; 32],
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sender_pub_hex = hex::encode(sender_id.public_key_bytes());
    let hash_hex = hex::encode(msg_hash);

    // Avoid leaking the clear receiver identifier to blockchain ingress by signing
    // and sending a deterministic receiver commitment instead.
    let receiver_commitment = hex::encode(crate::crypto::blake3::hash(receiver_id.as_bytes()));

    // Construct payload to sign: timestamp + sender + receiver commitment + hash
    let payload_to_sign = [
        &timestamp.to_be_bytes()[..],
        &sender_id.public_key_bytes(),
        receiver_commitment.as_bytes(),
        msg_hash,
    ]
    .concat();

    let signature = sender_id.sign(&payload_to_sign);
    let signature_hex = hex::encode(signature);

    let http_client = reqwest::Client::new();
    let delegate_required = crate::config::blockchain_commitment_delegate_required();
    let requested_threshold = crate::config::blockchain_commitment_auth_threshold();

    if let Some(delegate_base_url) = crate::config::blockchain_commitment_delegate_url() {
        let delegate_payload = delegated_signing_payload(
            timestamp,
            &sender_id.public_key_bytes(),
            &receiver_commitment,
            msg_hash,
            requested_threshold,
        );
        let delegated_entry = DelegatedBlockchainEntry {
            origin_signer_id: sender_pub_hex.clone(),
            message_hash: hash_hex.clone(),
            receiver_commitment: receiver_commitment.clone(),
            timestamp,
            origin_signature: hex::encode(sender_id.sign(&delegate_payload)),
            auth_threshold: requested_threshold,
            co_signatures: build_delegate_cosignatures(&delegate_payload)?,
        };

        let delegate_url = delegated_commitment_endpoint(&delegate_base_url);
        match post_json_with_retry(
            &http_client,
            &delegate_url,
            &delegated_entry,
            retries,
            base_delay,
            timeout,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) => {
                if delegate_required {
                    return Err(err.context(
                        "Delegated commitment submitter failed and direct fallback is disabled",
                    ));
                }
            }
        }
    }

    let entry = BlockchainEntry {
        message_hash: hash_hex,
        sender_id: sender_pub_hex,
        receiver_commitment,
        timestamp,
        signature: signature_hex,
    };

    let url = format!("{}/tx", client.base_url);
    post_json_with_retry(&http_client, &url, &entry, retries, base_delay, timeout).await
}

pub async fn upload_prekey_bundle(
    client: &DirectoryClient,
    key_id: &str,
    blob: &[u8],
    ttl_secs: u64,
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<()> {
    let mut attempt = 0;
    loop {
        // Prekey bundles are published to directory storage with bounded TTL.
        match tokio::time::timeout(
            timeout,
            client.publish_prekey_bundle(key_id, blob, ttl_secs),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => {
                if attempt >= retries {
                    return Err(e).context("Max retries reached for upload_prekey_bundle");
                }
            }
            Err(_) => {
                if attempt >= retries {
                    return Err(anyhow!("Timeout uploading prekey bundle"));
                }
            }
        }

        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}

pub async fn fetch_prekey_bundle(
    client: &DirectoryClient,
    key_id: &str,
    retries: u32,
    base_delay: Duration,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut attempt = 0;
    loop {
        match tokio::time::timeout(timeout, client.fetch_prekey_bundle(key_id)).await {
            Ok(Ok(bytes)) => return Ok(bytes),
            Ok(Err(e)) => {
                if attempt >= retries {
                    return Err(e).context("Max retries reached for fetch_prekey_bundle");
                }
            }
            Err(_) => {
                if attempt >= retries {
                    return Err(anyhow!("Timeout fetching prekey bundle"));
                }
            }
        }

        attempt += 1;
        sleep(base_delay * attempt).await;
    }
}
