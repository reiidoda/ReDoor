use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signer;
use hex;
use redoor_blockchain::ledger::block::Block;
use redoor_blockchain::ledger::chain::Blockchain;
use reqwest::Client;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task;
use warp::Filter;

// Start a local warp server bound to an ephemeral port and return the address.
async fn spawn_test_server(blockchain: Arc<Mutex<Blockchain>>) -> SocketAddr {
    let blockchain_tx = blockchain.clone();
    let blockchain_sb = blockchain.clone();

    let tx_route = warp::post()
        .and(warp::path("transaction"))
        .and(warp::body::json())
        .and_then(move |tx: serde_json::Value| {
            let blockchain = blockchain_tx.clone();
            async move {
                // naive acceptance for test
                let mut chain: tokio::sync::MutexGuard<'_, Blockchain> = blockchain.lock().await;
                let data = serde_json::to_vec(&tx).unwrap();
                chain.add_block(data);
                drop(chain);
                Ok::<_, warp::Rejection>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
            }
        });

    let sb_route = warp::post()
        .and(warp::path("signed_block"))
        .and(warp::body::json())
        .and_then(move |sb: serde_json::Value| {
            let blockchain = blockchain_sb.clone();
            async move {
                // For testing, reconstruct Block from JSON fields
                let prev_hex = sb["previous_hash_hex"].as_str().unwrap();
                let hash_hex = sb["hash_hex"].as_str().unwrap();
                let data_b64 = sb["data_b64"].as_str().unwrap();
                let sig_hex = sb["signature_hex"].as_str().unwrap();
                let signer_hex = sb["signer_pub_hex"].as_str().unwrap();

                let previous_hash_bytes = hex::decode(prev_hex).unwrap();
                let hash_bytes = hex::decode(hash_hex).unwrap();
                let data_bytes = B64.decode(data_b64).unwrap();
                let sig_bytes = hex::decode(sig_hex).unwrap();
                let signer_pub = hex::decode(signer_hex).unwrap();

                let mut prev_arr = [0u8; 32];
                prev_arr.copy_from_slice(&previous_hash_bytes);
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash_bytes);

                let block = Block {
                    version: 1,
                    index: sb["index"].as_u64().unwrap(),
                    timestamp: sb["timestamp"].as_u64().unwrap(),
                    previous_hash: prev_arr,
                    hash: hash_arr,
                    data: data_bytes,
                    signature: sig_bytes,
                    signer_pub,
                };

                let mut chain: tokio::sync::MutexGuard<'_, Blockchain> = blockchain.lock().await;
                let _ = chain.add_signed_block(block);
                drop(chain);

                Ok::<_, warp::Rejection>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
            }
        });

    let routes = tx_route.or(sb_route);

    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    task::spawn(async move {
        let (addr, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
        let _ = addr_tx.send(addr);
        server.await;
    });

    addr_rx.await.unwrap()
}

#[tokio::test]
async fn test_http_endpoints() {
    // create blockchain
    let bc = Arc::new(Mutex::new(Blockchain::new()));
    let addr = spawn_test_server(bc.clone()).await;

    let client = Client::new();
    let base = format!("http://{}", addr);

    // POST transaction
    let tx = json!({
        "sender_id": hex::encode(b"sender"),
        "receiver_commitment": hex::encode(b"receiver"),
        "message_hash": hex::encode(b"mh"),
        "signature": hex::encode(b"sig"),
        "timestamp": 123u64
    });

    let res = client
        .post(&format!("{}/transaction", base))
        .json(&tx)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    // Prepare a signed block: create a block via chain.add_block to get prev hash
    let mut chain: tokio::sync::MutexGuard<'_, Blockchain> = bc.lock().await;
    chain.add_block(b"payload".to_vec());
    let prev = chain.chain.last().unwrap().hash;
    let index = chain.chain.last().unwrap().index + 1;
    drop(chain);

    // We'll sign with a fresh key for test
    let mut csprng = rand::rngs::OsRng {};
    let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
    let pk = sk.verifying_key();

    // Create block hash and signature
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(&[1u8]); // block version
    hasher.update(&index.to_le_bytes());
    hasher.update(&123u64.to_le_bytes());
    hasher.update(&prev);
    hasher.update(b"payload2");
    let block_hash = hasher.finalize().as_bytes().to_vec();
    let sig = sk.sign(&block_hash).to_bytes().to_vec();

    let sb = json!({
        "index": index,
        "timestamp": 123u64,
        "previous_hash_hex": hex::encode(prev),
        "hash_hex": hex::encode(block_hash),
        "data_b64": B64.encode(b"payload2"),
        "signature_hex": hex::encode(sig.clone()),
        "signer_pub_hex": hex::encode(pk.to_bytes())
    });

    let res2 = client
        .post(&format!("{}/signed_block", base))
        .json(&sb)
        .send()
        .await
        .unwrap();
    assert!(res2.status().is_success());
}
