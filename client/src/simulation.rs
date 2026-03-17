use crate::builder::ClientEngineBuilder;
use crate::crypto::{self, x3dh};
use crate::engine::{ClientEngine, SessionEntry};
use crate::ratchet::double_ratchet::RatchetSession;
use crate::service;
use std::thread;
use std::time::Duration;

pub fn simulate_conversation(relay_url: &str, chain_addr: &str) -> Result<(), String> {
    let alice = ClientEngineBuilder::new()
        .with_relay(relay_url)
        .with_blockchain(chain_addr)
        .build();

    let bob = ClientEngineBuilder::new()
        .with_relay(relay_url)
        .with_blockchain(chain_addr)
        .build();

    // 2. Create Identities
    let alice_id = crypto::ed25519::IdentityKey::generate();
    let alice_id_hex = hex::encode(alice_id.public_key_bytes());
    alice.state.lock().unwrap().identity = Some(alice_id.clone());

    let bob_id = crypto::ed25519::IdentityKey::generate();
    let bob_id_hex = hex::encode(bob_id.public_key_bytes());
    bob.state.lock().unwrap().identity = Some(bob_id.clone());

    // 3. Bob generates prekeys (Simulate publishing)
    let (bob_bundle, bob_secrets) = x3dh::generate_prekey_bundle(&bob_id)
        .map_err(|e| format!("Bob prekey gen failed: {}", e))?;
    {
        let mut guard = bob.state.lock().unwrap();
        guard.prekey_secrets = Some(bob_secrets.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        guard.signed_prekey_last_rotated_at = Some(now);
        guard.prekey_last_replenished_at = Some(now);
    }

    // 4. Alice initiates session (X3DH Handshake)
    let (alice_shared_secret, initial_msg) = x3dh::initiate_handshake(&alice_id, &bob_bundle)
        .map_err(|e| format!("Alice handshake failed: {}", e))?;

    // Alice creates session
    let bob_spk = crypto::x25519::PublicKey::from(
        TryInto::<[u8; 32]>::try_into(bob_bundle.signed_prekey.clone()).unwrap(),
    );
    let alice_session = SessionEntry {
        wrapped_state: None,
        inner: Some(RatchetSession::new(alice_shared_secret, Some(bob_spk))),
        pending_handshake: Some(serde_json::to_string(&initial_msg).unwrap()),
        peer_seal_key: Some(bob_bundle.signed_prekey),
    };
    alice
        .state
        .lock()
        .unwrap()
        .sessions
        .insert(bob_id_hex.clone(), alice_session);

    // 5. Send Handshake to Bob via Relay (Verify engine::poll_messages handles it)
    let handshake_bytes = serde_json::to_vec(&initial_msg).unwrap();
    let mailbox_id = hex::encode(crypto::blake3::hash(bob_id_hex.as_bytes()));
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let envelope = crate::engine::Envelope {
        mailbox_id,
        sender_id: alice_id_hex.clone(),
        timestamp,
        ciphertext: handshake_bytes,
        pow_nonce: 0,
    };

    let blob = serde_json::to_vec(&envelope).unwrap();
    let msg_hash = crypto::blake3::hash(&blob);
    let msg_id = hex::encode(msg_hash);

    let relay_client = alice.state.lock().unwrap().relay_client.clone().unwrap();
    alice
        .runtime
        .block_on(async {
            crate::orchestrator::send_blob_with_retry(
                &relay_client,
                &msg_id,
                &bob_id_hex,
                &blob,
                3,
                Duration::from_millis(100),
                Duration::from_secs(5),
            )
            .await
        })
        .map_err(|e| format!("Failed to send handshake: {}", e))?;

    // 6. Start Polling (Network Layer)
    service::start_fixed_polling(&alice, 200);
    service::start_fixed_polling(&bob, 200);

    // Wait for Bob to receive handshake and establish session
    thread::sleep(Duration::from_secs(2));

    // 7. Alice sends an encrypted message to Bob
    let msg_content = "Hello Bob, this is Alice!";
    alice.send_payload(&bob_id_hex, msg_content, "text", None, false, false, None);

    // 8. Wait for delivery
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(200));
        let msgs = bob.poll_messages();
        if msgs.contains(msg_content) {
            return Ok(());
        }
        // Trigger processing of pending blobs if necessary (usually poll_messages does it or the background task)
        // In this simulation, we rely on the engine's internal loop or poll_messages to process the fetched blobs.
    }

    Err("Bob did not receive the message from Alice".to_string())
}

pub fn verify_duress_mode() -> Result<(), String> {
    let client = ClientEngine::new();

    // 1. Setup real data
    {
        let mut g = client.state.lock().unwrap();
        let id = crypto::ed25519::IdentityKey::generate();
        g.identity = Some(id);
        g.sessions.insert(
            "real_peer".to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(RatchetSession::new([0u8; 32], None)),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );
        g.message_store.insert(
            "real_peer".to_string(),
            vec![crate::engine::StoredMessage {
                id: "msg1".to_string(),
                timestamp: 100,
                sender: "real_peer".to_string(),
                content: "Secret Message".to_string(),
                msg_type: "text".to_string(),
                group_id: None,
                read: true,
            }],
        );
    }

    // 2. Trigger Duress Mode
    service::enter_duress_mode(&client);

    // 3. Verify
    let g = client.state.lock().unwrap();

    // Check real data is gone
    if g.sessions.contains_key("real_peer") {
        return Err("Real session was not wiped".to_string());
    }
    if g.message_store.contains_key("real_peer") {
        return Err("Real messages were not wiped".to_string());
    }

    // Check fake data exists
    if g.sessions.is_empty() {
        return Err("No fake sessions generated".to_string());
    }
    if g.message_store.is_empty() {
        return Err("No fake messages generated".to_string());
    }

    Ok(())
}

pub fn benchmark_handshake_and_messaging(
    relay_url: &str,
    chain_addr: &str,
) -> Result<String, String> {
    use std::time::Instant;

    let alice = ClientEngineBuilder::new()
        .with_relay(relay_url)
        .with_blockchain(chain_addr)
        .build();

    let bob = ClientEngineBuilder::new()
        .with_relay(relay_url)
        .with_blockchain(chain_addr)
        .build();

    // 2. Create Identities
    let alice_id = crypto::ed25519::IdentityKey::generate();
    let alice_id_hex = hex::encode(alice_id.public_key_bytes());
    alice.state.lock().unwrap().identity = Some(alice_id.clone());

    let bob_id = crypto::ed25519::IdentityKey::generate();
    let bob_id_hex = hex::encode(bob_id.public_key_bytes());
    bob.state.lock().unwrap().identity = Some(bob_id.clone());

    // 3. Bob generates prekeys
    let (bob_bundle, mut bob_secrets) = x3dh::generate_prekey_bundle(&bob_id)
        .map_err(|e| format!("Bob prekey gen failed: {}", e))?;
    {
        let mut guard = bob.state.lock().unwrap();
        guard.prekey_secrets = Some(bob_secrets.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        guard.signed_prekey_last_rotated_at = Some(now);
        guard.prekey_last_replenished_at = Some(now);
    }

    // Start Handshake Timer
    let start_handshake = Instant::now();

    // 4. Alice initiates session (X3DH Handshake)
    let (alice_shared_secret, initial_msg) = x3dh::initiate_handshake(&alice_id, &bob_bundle)
        .map_err(|e| format!("Alice handshake failed: {}", e))?;

    // Alice creates session
    let bob_spk = crypto::x25519::PublicKey::from(
        TryInto::<[u8; 32]>::try_into(bob_bundle.signed_prekey.clone()).unwrap(),
    );
    let alice_session = SessionEntry {
        wrapped_state: None,
        inner: Some(RatchetSession::new(alice_shared_secret, Some(bob_spk))),
        pending_handshake: Some(serde_json::to_string(&initial_msg).unwrap()),
        peer_seal_key: Some(bob_bundle.signed_prekey),
    };
    alice
        .state
        .lock()
        .unwrap()
        .sessions
        .insert(bob_id_hex.clone(), alice_session);

    // 5. Bob processes handshake
    let bob_shared_secret = x3dh::respond_to_handshake(&bob_id, &mut bob_secrets, &initial_msg)
        .map_err(|e| format!("Bob respond failed: {}", e))?;

    // Bob creates session
    let alice_ek = crypto::x25519::PublicKey::from(
        TryInto::<[u8; 32]>::try_into(initial_msg.ephemeral_key.as_slice()).unwrap(),
    );
    let bob_session = SessionEntry {
        wrapped_state: None,
        inner: Some(RatchetSession::new(bob_shared_secret, Some(alice_ek))),
        pending_handshake: None,
        peer_seal_key: None,
    };
    bob.state
        .lock()
        .unwrap()
        .sessions
        .insert(alice_id_hex.clone(), bob_session);

    let handshake_duration = start_handshake.elapsed();

    // 6. Start Polling (Fast polling for benchmark)
    service::start_fixed_polling(&alice, 50);
    service::start_fixed_polling(&bob, 50);

    // Start Message Round-Trip Timer
    let start_rtt = Instant::now();

    // 7. Alice sends message to Bob
    let msg_content = "Ping";
    alice.send_payload(&bob_id_hex, msg_content, "text", None, false, false, None);

    // 8. Wait for delivery to Bob
    let mut bob_received = false;
    for _ in 0..40 {
        // Wait up to 2s
        thread::sleep(Duration::from_millis(50));
        let msgs = bob.poll_messages();
        if msgs.contains(msg_content) {
            bob_received = true;
            break;
        }
    }

    if !bob_received {
        return Err("Bob did not receive message".to_string());
    }

    // 9. Bob replies to Alice
    let reply_content = "Pong";
    bob.send_payload(
        &alice_id_hex,
        reply_content,
        "text",
        None,
        false,
        false,
        None,
    );

    // 10. Wait for delivery to Alice
    let mut alice_received = false;
    for _ in 0..40 {
        thread::sleep(Duration::from_millis(50));
        let msgs = alice.poll_messages();
        if msgs.contains(reply_content) {
            alice_received = true;
            break;
        }
    }

    if !alice_received {
        return Err("Alice did not receive reply".to_string());
    }

    let rtt_duration = start_rtt.elapsed();

    Ok(format!(
        "Benchmark Results:\nX3DH Handshake: {:?}\nMessage Round-Trip: {:?}",
        handshake_duration, rtt_duration
    ))
}
