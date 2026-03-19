use anyhow::Result;
use redoor_client::api;
use redoor_client::blockchain_client;
use redoor_client::config;
use redoor_client::crypto;
use redoor_client::crypto::x3dh;
use redoor_client::engine::{self, ClientEngine, Envelope, SessionEntry};
use redoor_client::network;
use redoor_client::network::directory::{self, DirectoryClient};
use redoor_client::network::onion::OnionRouter;
use redoor_client::network::p2p::P2PClient;
use redoor_client::orchestrator;
use redoor_client::ratchet;

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use x25519_dalek::PublicKey;

#[tokio::main]

async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if engine::is_untrusted_parser_worker_command(&args) {
        std::process::exit(engine::run_untrusted_parser_worker_main());
    }

    println!("Starting ReDoor Client (Engine Mode)...");

    // Scripted non-interactive mode for integration tests

    if args.len() >= 2 && args[1] == "scripted-loopback" {
        let msg = if args.len() >= 3 {
            &args[2]
        } else {
            "hello loopback"
        };

        return api::scripted_loopback(msg).await;
    } else if args.len() >= 2 && args[1] == "scripted-loopback-onion" {
        let msg = if args.len() >= 3 {
            &args[2]
        } else {
            "hello onion loopback"
        };

        return api::scripted_loopback_onion(msg).await;
    } else if args.len() >= 2 && args[1] == "scripted-loopback-p2p" {
        let msg = if args.len() >= 3 {
            &args[2]
        } else {
            "hello p2p loopback"
        };

        return api::scripted_loopback_p2p(msg).await;
    }

    let engine = ClientEngine::new();

    let mut onion_routing = false;

    let mut p2p_mode = false;

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

    peer_addrs.insert(
        "peer1_id".to_string(),
        "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWL7B2r5L5gJ1h".to_string(),
    );

    let p2p_client = P2PClient::new().await?;

    let directory_url = config::default_directory_url();
    let directory_client = DirectoryClient::new(&directory_url);

    let relay_url = config::default_relay_url();
    let blockchain_url = config::default_blockchain_url();

    // Initialize components in Engine state

    {
        let mut guard = engine.state.lock().unwrap();

        guard.relay_client = Some(network::relay::RelayClient::new(&relay_url));

        guard.blockchain_client = Some(
            blockchain_client::verify_blockchain::BlockchainClient::new(blockchain_url),
        );

        guard.onion_router = Some(onion_router);

        guard.p2p_client = Some(p2p_client);

        guard.directory_client = Some(directory_client);
    }

    loop {
        println!("\n--- ReDoor Secure CLI ---");

        println!("1. Generate Identity");

        println!("2. Generate Prekeys (Copy JSON)");

        println!("3. Connect to Peer (Paste JSON or Username)");

        println!("4. Send Message");

        println!("5. Poll Messages");

        println!(
            "6. Toggle Onion Routing (Currently: {})",
            if onion_routing { "On" } else { "Off" }
        );

        println!(
            "7. Toggle P2P Mode (Currently: {})",
            if p2p_mode { "On" } else { "Off" }
        );

        println!("8. Publish Username (and Prekeys)");

        println!("9. Exit");

        print!("Select: ");

        io::stdout().flush()?;

        let mut input = String::new();

        io::stdin().read_line(&mut input)?;

        let choice = input.trim();

        match choice {
            "1" => {
                engine.initialize_keys();

                let guard = engine.state.lock().unwrap();

                if let Some(id) = &guard.identity {
                    println!("Identity generated: {}", hex::encode(id.public_key_bytes()));
                }
            }

            "2" => {
                let identity = engine.state.lock().unwrap().identity.clone();

                if let Some(id) = identity {
                    match x3dh::generate_prekey_bundle(&id) {
                        Ok((bundle, secrets)) => {
                            let json = serde_json::to_string(&bundle).unwrap();

                            let mut guard = engine.state.lock().unwrap();

                            guard.prekey_secrets = Some(secrets);
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            guard.signed_prekey_last_rotated_at = Some(now);
                            guard.prekey_last_replenished_at = Some(now);

                            println!("\n--- Prekey Bundle (Share this with peer) ---");

                            println!("{}", json);

                            println!("--------------------------------------------");
                        }

                        Err(e) => println!("Error generating prekeys: {:?}", e),
                    }
                } else {
                    println!("Error: No identity. Run step 1 first.");
                }
            }

            "3" => {
                println!("Enter Peer ID (hex), Username, or paste JSON:");

                let mut input = String::new();

                io::stdin().read_line(&mut input)?;

                let input = input.trim();

                let bundle_json = if input.starts_with("{") {
                    input.to_string()
                } else {
                    let directory_client = {
                        let guard = engine.state.lock().unwrap();
                        guard.directory_client.clone()
                    };

                    if let Some(directory_client) = directory_client {
                        let result = engine.runtime.block_on(directory_client.resolve(input));

                        match result {
                            Ok(pk) => {
                                let bytes =
                                    engine.runtime.block_on(orchestrator::fetch_prekey_bundle(
                                        &directory_client,
                                        &pk,
                                        3,
                                        std::time::Duration::from_millis(200),
                                        std::time::Duration::from_secs(5),
                                    ));
                                match bytes {
                                    Ok(payload) => match String::from_utf8(payload) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            println!(
                                                "Prekey bundle for {} was not valid UTF-8: {}",
                                                input, e
                                            );
                                            String::new()
                                        }
                                    },
                                    Err(e) => {
                                        println!(
                                            "Failed to fetch prekey bundle for {}: {}",
                                            input, e
                                        );
                                        String::new()
                                    }
                                }
                            }

                            Err(e) => {
                                println!("Failed to resolve username: {}", e);

                                String::new()
                            }
                        }
                    } else {
                        String::new()
                    }
                };

                let bundle_res: Result<x3dh::PrekeyBundle, _> = serde_json::from_str(&bundle_json);

                if let Ok(peer_bundle) = bundle_res {
                    let mut guard = engine.state.lock().unwrap();

                    if let Some(my_id) = &guard.identity {
                        // Perform X3DH

                        match x3dh::initiate_handshake(my_id, &peer_bundle) {
                            Ok((shared_secret, initial_msg)) => {
                                let peer_id = hex::encode(&peer_bundle.identity_key);

                                let spk_bytes: [u8; 32] =
                                    peer_bundle.signed_prekey.clone().try_into().unwrap();

                                let peer_spk = crypto::x25519::PublicKey::from(spk_bytes);

                                let session = SessionEntry {
                                    wrapped_state: None,

                                    inner: Some(ratchet::double_ratchet::RatchetSession::new(
                                        shared_secret,
                                        Some(peer_spk),
                                    )),

                                    pending_handshake: Some(
                                        serde_json::to_string(&initial_msg).unwrap(),
                                    ),

                                    peer_seal_key: Some(peer_bundle.signed_prekey.to_vec()),
                                };

                                guard.sessions.insert(peer_id.clone(), session);

                                println!("Session established with {}", peer_id);

                                // Send InitialMessage (Handshake) to peer so they can establish session

                                let relay_client = guard.relay_client.clone();

                                let my_identity = guard.identity.clone();

                                let onion_router = guard.onion_router.clone().unwrap();

                                drop(guard); // Unlock to perform async IO

                                if let Some(client) = relay_client {
                                    let handshake_bytes = serde_json::to_vec(&initial_msg).unwrap();

                                    let mailbox_id =
                                        hex::encode(crypto::blake3::hash(peer_id.as_bytes()));

                                    let timestamp = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();

                                    let envelope = Envelope {
                                        mailbox_id,

                                        sender_id: hex::encode(
                                            my_identity.as_ref().unwrap().public_key_bytes(),
                                        ),

                                        timestamp,

                                        ciphertext: handshake_bytes,

                                        pow_nonce: 0,
                                    };

                                    let blob = serde_json::to_vec(&envelope).unwrap();

                                    println!("Sending handshake message...");

                                    let res = engine.runtime.block_on(async {
                                        if onion_routing {
                                            orchestrator::send_onion_blob_with_retry(
                                                &onion_router,
                                                &client,
                                                &hex::encode(crypto::blake3::hash(&blob)),
                                                &peer_id,
                                                &blob,
                                                3,
                                                std::time::Duration::from_millis(100),
                                                std::time::Duration::from_secs(5),
                                            )
                                            .await
                                        } else {
                                            orchestrator::send_blob_with_retry(
                                                &client,
                                                &hex::encode(crypto::blake3::hash(&blob)),
                                                &peer_id,
                                                &blob,
                                                3,
                                                std::time::Duration::from_millis(100),
                                                std::time::Duration::from_secs(5),
                                            )
                                            .await
                                        }
                                    });

                                    if let Err(e) = res {
                                        println!("Failed to send handshake: {}", e);
                                    }
                                }
                            }

                            Err(e) => println!("Handshake failed: {:?}", e),
                        }
                    } else {
                        println!("Error: No identity. Run step 1 first.");
                    }
                } else {
                    println!("Invalid JSON or username.");
                }
            }

            "4" => {
                print!("Enter Peer ID (hex): ");

                io::stdout().flush()?;

                let mut peer_id = String::new();

                io::stdin().read_line(&mut peer_id)?;

                print!("Enter Message: ");

                io::stdout().flush()?;

                let mut msg = String::new();

                io::stdin().read_line(&mut msg)?;

                let res = engine.send_payload(
                    peer_id.trim(),
                    msg.trim(),
                    "text",
                    None,
                    onion_routing,
                    p2p_mode,
                    peer_addrs.get(peer_id.trim()).cloned(),
                );

                if res == 0 {
                    println!("Message sent.");
                } else {
                    println!("Failed to send: error code {}", res);
                }
            }

            "5" => {
                let msgs = engine.poll_messages();

                println!("Messages: {}", msgs);
            }

            "6" => {
                onion_routing = !onion_routing;
            }

            "7" => {
                p2p_mode = !p2p_mode;
            }

            "8" => {
                print!("Enter username to publish: ");

                io::stdout().flush()?;

                let mut username = String::new();

                io::stdin().read_line(&mut username)?;

                let username = username.trim();

                let (directory_client, identity) = {
                    let guard = engine.state.lock().unwrap();
                    (guard.directory_client.clone(), guard.identity.clone())
                };

                if let (Some(directory_client), Some(identity)) = (directory_client, identity) {
                    let public_key_hex = hex::encode(identity.public_key_bytes());

                    let (bundle, secrets) = match x3dh::generate_prekey_bundle(&identity) {
                        Ok(v) => v,
                        Err(e) => {
                            println!("Failed to generate prekey bundle: {}", e);
                            continue;
                        }
                    };
                    let bundle_bytes = match serde_json::to_vec(&bundle) {
                        Ok(b) => b,
                        Err(e) => {
                            println!("Failed to serialize prekey bundle: {}", e);
                            continue;
                        }
                    };

                    {
                        let mut guard = engine.state.lock().unwrap();
                        guard.prekey_secrets = Some(secrets);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        guard.signed_prekey_last_rotated_at = Some(now);
                        guard.prekey_last_replenished_at = Some(now);
                    }

                    let upload_result =
                        engine.runtime.block_on(orchestrator::upload_prekey_bundle(
                            &directory_client,
                            &public_key_hex,
                            &bundle_bytes,
                            3600,
                            3,
                            std::time::Duration::from_millis(200),
                            std::time::Duration::from_secs(5),
                        ));
                    if let Err(e) = upload_result {
                        println!("Failed to upload prekey bundle to directory: {}", e);
                        continue;
                    }

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let expires_at = now.saturating_add(24 * 60 * 60);

                    let seq = match engine
                        .runtime
                        .block_on(directory_client.resolve_record_optional(username))
                    {
                        Ok(Some(record)) => {
                            if record.public_key != public_key_hex {
                                println!(
                                    "Username is already owned by another identity and cannot be updated."
                                );
                                continue;
                            }
                            record.seq.saturating_add(1)
                        }
                        Ok(None) => 1,
                        Err(e) => {
                            println!("Failed to resolve existing username record: {}", e);
                            continue;
                        }
                    };

                    let signature =
                        hex::encode(identity.sign(&directory::publish_signing_message(
                            username,
                            &public_key_hex,
                            seq,
                            expires_at,
                        )));

                    match engine.runtime.block_on(directory_client.publish(
                        username,
                        &public_key_hex,
                        &signature,
                        seq,
                        expires_at,
                    )) {
                        Ok(_) => println!("Username and prekey bundle published successfully."),

                        Err(e) => println!("Failed to publish username: {}", e),
                    }
                } else {
                    println!("Directory client or identity not initialized.");
                }
            }

            "9" => break,

            _ => {
                println!("Invalid option, please try again.");
            }
        }
    }

    Ok(())
}

// NOTE: scripted_loopback lives in src/api.rs for embedding (CLI path calls it).
