use crate::blockchain_client::verify_blockchain::BlockchainClient;
use crate::config::set_pq_enabled;
use crate::crypto;
use crate::network::relay::RelayClient;
use crate::network::onion::{OnionRouter, MixnetConfig};
use crate::orchestrator;
use crate::ratchet::double_ratchet::RatchetSession;
use crate::crypto::x3dh;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering}};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use zeroize::Zeroize;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::traits::SerDes;
use rand::Rng;

// --- Data Structures ---

#[derive(Clone)]
pub struct SessionEntry {
    pub wrapped_state: Option<Vec<u8>>,
    pub inner: Option<RatchetSession>,
    pub pending_handshake: Option<String>,
    pub peer_seal_key: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub struct RateLimitConfig {
    pub max_messages: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Copy)]
pub struct BackgroundConfig {
    pub mode: i32,
    pub grace_period_ms: u64,
}

#[derive(Clone, Copy)]
pub struct CoverTrafficConfig {
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
}

#[derive(Clone, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct StoredMessage {
    pub id: String,
    pub timestamp: u64,
    pub sender: String,
    pub content: String,
    pub msg_type: String,
    pub group_id: Option<String>,
    #[serde(default)]
    pub read: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct InnerPayload {
    pub sender_id: String,
    pub content: String,
    pub msg_type: String,
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default)]
    pub counter: u32,
    #[serde(default)]
    pub commitment_nonce: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub mailbox_id: String,
    pub timestamp: u64,
    pub ciphertext: Vec<u8>,
    #[serde(default)]
    pub pow_nonce: u64,
}

pub struct OutgoingMessage {
    pub peer_id: String,
    pub msg_id: String,
    pub blob: Vec<u8>,
    pub msg_hash: Vec<u8>,
}

#[derive(Default)]
pub struct TrafficStats {
    pub real_messages_sent: u64,
    pub cover_messages_sent: u64,
}

// --- AppState (Internal) ---

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct AppState {
    pub identity: Option<crypto::ed25519::IdentityKey>,
    #[zeroize(skip)]
    pub prekey_secrets: Option<x3dh::PrekeySecrets>,
    #[zeroize(skip)]
    pub relay_client: Option<RelayClient>,
    #[zeroize(skip)]
    pub kyber_keys: Option<(kyber1024::PublicKey, kyber1024::SecretKey)>,
    #[zeroize(skip)]
    pub blockchain_client: Option<BlockchainClient>,
    #[zeroize(skip)]
    pub sessions: HashMap<String, SessionEntry>,
    pub message_store: HashMap<String, Vec<StoredMessage>>,
    pub attachment_cache: HashMap<String, Vec<u8>>,
    #[zeroize(skip)]
    pub groups: HashMap<String, Vec<String>>,
    #[zeroize(skip)]
    pub blocked_peers: HashSet<String>,
    #[zeroize(skip)]
    pub nicknames: HashMap<String, String>,
    #[zeroize(skip)]
    pub auto_delete_timers: HashMap<String, u64>,
    #[zeroize(skip)]
    pub cover_traffic_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub blockchain_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    #[zeroize(skip)]
    pub batching_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub pow_difficulty: u32,
    #[zeroize(skip)]
    pub rate_limit_config: Option<RateLimitConfig>,
    #[zeroize(skip)]
    pub rate_limit_state: HashMap<String, Vec<u64>>,
    #[zeroize(skip)]
    pub traffic_stats: Arc<Mutex<TrafficStats>>,
    #[zeroize(skip)]
    pub onion_router: Option<OnionRouter>,
    #[zeroize(skip)]
    pub background_config: BackgroundConfig,
    #[zeroize(skip)]
    pub background_generation: Arc<AtomicU64>,
    #[zeroize(skip)]
    pub log_buffer: VecDeque<String>,
    #[zeroize(skip)]
    pub cover_traffic_config: CoverTrafficConfig,
    #[zeroize(skip)]
    pub low_power_mode: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub read_receipts_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub log_level: Arc<AtomicU8>,
    #[zeroize(skip)]
    pub theme: String,
    #[zeroize(skip)]
    pub outgoing_queue: Arc<Mutex<VecDeque<OutgoingMessage>>>,
    #[zeroize(skip)]
    pub outgoing_batching_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub outgoing_batch_interval_ms: Arc<AtomicU64>,
    #[zeroize(skip)]
    pub pending_blobs: Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
    #[zeroize(skip)]
    pub fixed_polling_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub anonymity_mode_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub constant_rate_enabled: Arc<AtomicBool>,
    #[zeroize(skip)]
    pub mixnet_config: MixnetConfig,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            identity: None,
            prekey_secrets: None,
            kyber_keys: None,
            relay_client: None,
            blockchain_client: None,
            sessions: HashMap::new(),
            message_store: HashMap::new(),
            attachment_cache: HashMap::new(),
            groups: HashMap::new(),
            blocked_peers: HashSet::new(),
            nicknames: HashMap::new(),
            auto_delete_timers: HashMap::new(),
            cover_traffic_enabled: Arc::new(AtomicBool::new(false)),
            blockchain_queue: Arc::new(Mutex::new(Vec::new())),
            batching_enabled: Arc::new(AtomicBool::new(false)),
            pow_difficulty: 0,
            rate_limit_config: None,
            rate_limit_state: HashMap::new(),
            traffic_stats: Arc::new(Mutex::new(TrafficStats::default())),
            onion_router: None,
            background_config: BackgroundConfig { mode: 0, grace_period_ms: 0 },
            background_generation: Arc::new(AtomicU64::new(0)),
            log_buffer: VecDeque::with_capacity(1000),
            cover_traffic_config: CoverTrafficConfig { min_delay_ms: 30_000, max_delay_ms: 300_000 },
            low_power_mode: Arc::new(AtomicBool::new(false)),
            read_receipts_enabled: Arc::new(AtomicBool::new(true)),
            log_level: Arc::new(AtomicU8::new(2)),
            theme: "system".to_string(),
            outgoing_queue: Arc::new(Mutex::new(VecDeque::new())),
            outgoing_batching_enabled: Arc::new(AtomicBool::new(false)),
            outgoing_batch_interval_ms: Arc::new(AtomicU64::new(0)),
            pending_blobs: Arc::new(Mutex::new(VecDeque::new())),
            fixed_polling_enabled: Arc::new(AtomicBool::new(false)),
            anonymity_mode_enabled: Arc::new(AtomicBool::new(false)),
            constant_rate_enabled: Arc::new(AtomicBool::new(false)),
            mixnet_config: MixnetConfig { min_hops: 3, max_hops: 5 },
        }
    }

    pub fn secure_wipe(&mut self) {
        for messages in self.message_store.values_mut() {
            for msg in messages.iter_mut() {
                msg.zeroize();
            }
        }
        self.message_store.clear();
        for data in self.attachment_cache.values_mut() {
            data.zeroize();
        }
        self.attachment_cache.clear();
    }
}

// --- ClientEngine (Service Layer) ---

pub struct ClientEngine {
    pub state: Arc<Mutex<AppState>>,
    pub runtime: Runtime,
}

impl ClientEngine {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        ClientEngine {
            state: Arc::new(Mutex::new(AppState::new())),
            runtime,
        }
    }

    pub fn log_internal(&self, msg: String) {
        let mut guard = self.state.lock().unwrap();
        let current_level = guard.log_level.load(Ordering::Relaxed);
        if 0 <= current_level {
            if guard.log_buffer.len() >= 1000 {
                guard.log_buffer.pop_front();
            }
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            guard.log_buffer.push_back(format!("[{}] [ERR] {}", ts, msg));
        }
    }

    pub fn wipe_memory(&self) {
        let mut guard = self.state.lock().unwrap();
        guard.secure_wipe();
        
        // Preserve configuration
        let bg_config = guard.background_config;
        let bg_gen = guard.background_generation.clone();
        let cover_config = guard.cover_traffic_config;
        let low_power = guard.low_power_mode.clone();
        let read_receipts = guard.read_receipts_enabled.clone();
        let log_lvl = guard.log_level.clone();
        let theme_val = guard.theme.clone();
        let out_batch = guard.outgoing_batching_enabled.clone();
        let out_int = guard.outgoing_batch_interval_ms.clone();
        let fix_poll = guard.fixed_polling_enabled.clone();
        let anon_mode = guard.anonymity_mode_enabled.clone();
        let const_rate = guard.constant_rate_enabled.clone();
        let mix_conf = guard.mixnet_config;

        bg_gen.fetch_add(1, Ordering::Relaxed);

        *guard = AppState::new();
        guard.background_config = bg_config;
        guard.background_generation = bg_gen;
        guard.cover_traffic_config = cover_config;
        guard.low_power_mode = low_power;
        guard.read_receipts_enabled = read_receipts;
        guard.log_level = log_lvl;
        guard.theme = theme_val;
        guard.outgoing_batching_enabled = out_batch;
        guard.outgoing_batch_interval_ms = out_int;
        guard.fixed_polling_enabled = fix_poll;
        guard.anonymity_mode_enabled = anon_mode;
        guard.constant_rate_enabled = const_rate;
        guard.mixnet_config = mix_conf;
    }

    pub fn send_payload(&self, peer_id: &str, content: &str, msg_type: &str, group_id: Option<&str>, skip_blockchain: bool) -> i32 {
        if peer_id.is_empty() { return -1; }

        let (ciphertext, relay_client, blockchain_client, shaping, blockchain_queue, batching_enabled, pow_difficulty, traffic_stats, onion_router, outgoing_batching, outgoing_queue, anonymity_mode, commitment_nonce, constant_rate, handshake, peer_seal_key, mixnet_config) = {
            let mut guard = self.state.lock().unwrap();
            
            if guard.blocked_peers.contains(peer_id) { return -6; }
            if guard.anonymity_mode_enabled.load(Ordering::Relaxed) && guard.onion_router.is_none() { return -9; }

            if let Some(config) = guard.rate_limit_config {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let history = guard.rate_limit_state.entry(peer_id.to_string()).or_default();
                history.retain(|&t| now.saturating_sub(t) < config.window_seconds);
                if history.len() as u32 >= config.max_messages { return -7; }
                history.push(now);
            }

            let entry = match guard.sessions.get_mut(peer_id) {
                Some(s) => s,
                None => return -2,
            };
            let session = match entry.inner.as_mut() {
                Some(s) => s,
                None => return -8,
            };

            let handshake = if let Some(json) = entry.pending_handshake.take() {
                serde_json::from_str(&json).ok()
            } else { None };
            let peer_seal_key = entry.peer_seal_key.clone();
            let shaping = crate::config::get_traffic_shaping();
            let id = match &guard.identity {
                Some(i) => i.clone(),
                None => return -4,
            };
            
            let signature = id.sign(content.as_bytes());
            let my_id_hex = hex::encode(id.public_key_bytes());
            let commitment_nonce: u64 = rand::thread_rng().gen();

            let inner = InnerPayload {
                sender_id: my_id_hex,
                content: content.to_string(),
                msg_type: msg_type.to_string(),
                signature,
                group_id: group_id.map(|s| s.to_string()),
                counter: session.msg_count_send,
                commitment_nonce,
            };
            let inner_bytes = serde_json::to_vec(&inner).unwrap();
            let ct = match session.ratchet_encrypt(&inner_bytes) {
                Ok(c) => c,
                Err(_) => return -3,
            };

            let rc = guard.relay_client.clone().expect("Relay client not initialized");
            let bc = guard.blockchain_client.clone().expect("Blockchain client not initialized");

            (ct, rc, bc, shaping, guard.blockchain_queue.clone(), guard.batching_enabled.clone(), guard.pow_difficulty, guard.traffic_stats.clone(), guard.onion_router.clone(), guard.outgoing_batching_enabled.clone(), guard.outgoing_queue.clone(), guard.anonymity_mode_enabled.clone(), commitment_nonce, guard.constant_rate_enabled.clone(), handshake, peer_seal_key, guard.mixnet_config)
        };

        let res = self.runtime.block_on(async {
            if shaping.max_delay_ms > 0 {
                let delay_ms = if shaping.min_delay_ms >= shaping.max_delay_ms { shaping.min_delay_ms } else { rand::thread_rng().gen_range(shaping.min_delay_ms..=shaping.max_delay_ms) };
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let timestamp = (now / 60) * 60;
            let mailbox_id = hex::encode(crypto::blake3::hash(peer_id.as_bytes()));
            let mut final_envelope = Envelope { mailbox_id, timestamp, ciphertext, pow_nonce: 0 };

            if pow_difficulty > 0 {
                let mut hasher = crypto::blake3::Hasher::new();
                hasher.update(final_envelope.mailbox_id.as_bytes());
                hasher.update(&final_envelope.timestamp.to_le_bytes());
                hasher.update(&final_envelope.ciphertext);
                final_envelope.pow_nonce = solve_pow(&hasher, pow_difficulty);
            }

            let mut serialized = serde_json::to_vec(&final_envelope).unwrap();
            serialized = pad_envelope(serialized);
            let msg_hash = crypto::blake3::hash(&serialized);
            let msg_id_hex = hex::encode(msg_hash);
            
            let mut hasher = crypto::blake3::Hasher::new();
            hasher.update(msg_hash.as_bytes());
            hasher.update(&commitment_nonce.to_le_bytes());
            let commitment = hasher.finalize();

            if outgoing_batching.load(Ordering::Relaxed) || constant_rate.load(Ordering::Relaxed) {
                outgoing_queue.lock().unwrap().push_back(OutgoingMessage {
                    peer_id: peer_id.to_string(),
                    msg_id: msg_id_hex,
                    blob: serialized,
                    msg_hash: msg_hash.to_vec(),
                });
                if batching_enabled.load(Ordering::Relaxed) {
                    blockchain_queue.lock().unwrap().push(commitment.as_bytes().to_vec());
                }
                return Ok(());
            }
            
            if anonymity_mode.load(Ordering::Relaxed) && onion_router.is_none() {
                 return Err(anyhow::anyhow!("Anonymity mode enabled but no onion router"));
            }

            let (target_url, payload_to_send) = if let Some(router) = &onion_router {
                 match router.build_circuit_from_config(&relay_client.base_url, &serialized, mixnet_config) {
                     Ok(res) => res,
                     Err(_) => return Err(anyhow::anyhow!("Failed to build onion circuit")),
                 }
            } else {
                 (relay_client.base_url.clone(), serialized)
            };
            
            let client_to_use = if target_url == relay_client.base_url { relay_client.clone() } else { RelayClient::new(&target_url) };

            orchestrator::send_blob_with_retry(&client_to_use, &msg_id_hex, peer_id, &payload_to_send, 3, Duration::from_millis(100), Duration::from_secs(2)).await?;

            if let Ok(mut stats) = traffic_stats.lock() { stats.real_messages_sent += 1; }
            if skip_blockchain { return Ok(()); }
            if batching_enabled.load(Ordering::Relaxed) {
                blockchain_queue.lock().unwrap().push(commitment.as_bytes().to_vec());
                return Ok(());
            }

            let ephemeral_signer = crypto::ed25519::IdentityKey::generate();
            orchestrator::submit_tx_with_retry(&blockchain_client, &ephemeral_signer, &commitment.as_bytes(), 3, Duration::from_millis(100), Duration::from_secs(2)).await?;
            Ok::<(), anyhow::Error>(())
        });

        match res { Ok(_) => 0, Err(_) => -5 }
    }

    pub fn poll_messages(&self) -> String {
        let guard = self.state.lock().unwrap();
        let pending_blob = {
            let mut q = guard.pending_blobs.lock().unwrap();
            q.pop_front()
        };
        let my_id = match &guard.identity {
            Some(id) => hex::encode(id.public_key_bytes()),
            None => return "[]".to_string(),
        };
        let relay_client = match &guard.relay_client {
            Some(rc) => rc.clone(),
            None => return "[]".to_string(),
        };
        let fixed_polling = guard.fixed_polling_enabled.load(Ordering::Relaxed);
        drop(guard);

        let fetch_res = if let Some(pb) = pending_blob {
            Ok(pb)
        } else if !fixed_polling {
            self.runtime.block_on(async {
                orchestrator::fetch_pending_with_retry(&relay_client, &my_id, 1, Duration::from_millis(100), Duration::from_millis(100)).await
            })
        } else {
            Err(anyhow::anyhow!("Polling handled in background"))
        };

        match fetch_res {
            Ok((msg_id, blob)) => {
                let mut guard = self.state.lock().unwrap();
                let mut decrypted = false;
                if let Ok(env) = serde_json::from_slice::<Envelope>(&blob) {
                    let mut ratchet_ciphertext = &env.ciphertext[..];
                    let mut handshake_opt: Option<x3dh::InitialMessage> = None;

                    if !env.ciphertext.is_empty() {
                        if env.ciphertext[0] == 0x01 {
                            if env.ciphertext.len() >= 5 {
                                let len_bytes: [u8; 4] = env.ciphertext[1..5].try_into().unwrap();
                                let len = u32::from_le_bytes(len_bytes) as usize;
                                if env.ciphertext.len() >= 5 + len {
                                    let sealed = &env.ciphertext[5..5+len];
                                    ratchet_ciphertext = &env.ciphertext[5+len..];
                                    if let Some(secrets) = &guard.prekey_secrets {
                                        if let Some(plain) = unseal_handshake(&secrets.signed_prekey, sealed) {
                                            if let Ok(h) = serde_json::from_slice(&plain) { handshake_opt = Some(h); }
                                        }
                                    }
                                }
                            }
                        } else if env.ciphertext[0] == 0x00 {
                            ratchet_ciphertext = &env.ciphertext[1..];
                        }
                    }

                    if let Some(handshake) = handshake_opt {
                        let sender_bytes = &handshake.identity_key;
                        let sender_id = hex::encode(sender_bytes);
                        if let Some(our_id) = &guard.identity {
                            if let Some(our_prekeys) = &mut guard.prekey_secrets {
                                if let Ok(shared_secret) = x3dh::respond_to_handshake(our_id, our_prekeys, &handshake) {
                                    let peer_ek_pub = crypto::x25519::PublicKey::from(handshake.ephemeral_key.try_into().unwrap());
                                    let session = SessionEntry { wrapped_state: None, inner: Some(RatchetSession::new(shared_secret, Some(peer_ek_pub))), pending_handshake: None, peer_seal_key: None };
                                    guard.sessions.insert(sender_id.clone(), session);
                                }
                            }
                        }
                    }

                    for (peer_id, sess) in guard.sessions.iter_mut() {
                        let active_sess = match sess.inner.as_mut() { Some(s) => s, None => continue };
                        if let Ok(plaintext) = active_sess.ratchet_decrypt(ratchet_ciphertext) {
                            decrypted = true;
                            if let Ok(inner) = serde_json::from_slice::<InnerPayload>(&plaintext) {
                                if inner.sender_id != *peer_id { continue; }
                                if inner.msg_type == "cover" { continue; }
                                if guard.blocked_peers.contains(peer_id) { return "[]".to_string(); }
                                if let Ok(peer_bytes) = hex::decode(peer_id) {
                                    if let Ok(peer_key) = crypto::ed25519::IdentityKey::from_public_bytes(&peer_bytes) {
                                        if !peer_key.verify(inner.content.as_bytes(), &inner.signature) { continue; }
                                    }
                                }
                                let stored = StoredMessage { id: msg_id.clone(), timestamp: env.timestamp, sender: peer_id.clone(), content: inner.content.clone(), msg_type: inner.msg_type.clone(), group_id: inner.group_id.clone(), read: false };
                                guard.message_store.entry(peer_id.clone()).or_default().push(stored);
                                let gid_json = match inner.group_id { Some(g) => format!(", \"group_id\": \"{}\"", g), None => "".to_string() };
                                return format!("[{{\"id\": \"{}\", \"sender\": \"{}\", \"text\": \"{}\", \"type\": \"{}\"{}}}]", msg_id, peer_id, inner.content, inner.msg_type, gid_json);
                            }
                        }
                    }
                }
                if !decrypted { guard.attachment_cache.insert(msg_id, blob); }
            }
            Err(_) => {}
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ttls: Vec<(String, u64)> = guard.auto_delete_timers.iter().map(|(k,v)| (k.clone(), *v)).collect();
        for (peer_id, ttl) in ttls {
            if ttl > 0 {
                 if let Some(msgs) = guard.message_store.get_mut(&peer_id) {
                     msgs.retain(|m| now.saturating_sub(m.timestamp) < ttl);
                 }
            }
        }
        "[]".to_string()
    }

    pub fn send_file(&self, peer_id: &str, data: &[u8], filename: &str) -> i32 {
        if peer_id.is_empty() || data.is_empty() { return -1; }
        
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut key);
        rng.fill(&mut nonce);

        let encrypted_file = match crate::crypto::chacha20poly1305::encrypt_with_nonce(&key, &nonce, data) {
            Ok(c) => c,
            Err(_) => return -2,
        };

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mailbox_id = hex::encode(crypto::blake3::hash(peer_id.as_bytes()));
        let file_env = Envelope { receiver_id: mailbox_id, timestamp, ciphertext: encrypted_file, pow_nonce: 0 };
        
        // Envelope struct in engine.rs uses mailbox_id, but here we used receiver_id in previous code.
        // Let's align: Envelope has mailbox_id.
        // Wait, the previous code had `receiver_id` in `Envelope` inside `send_file` but `mailbox_id` in `Envelope` struct.
        // I will use the `Envelope` struct defined in this file which has `mailbox_id`.
        
        let mut file_blob = serde_json::to_vec(&file_env).unwrap();
        file_blob = pad_envelope(file_blob);
        let file_hash = crypto::blake3::hash(&file_blob);
        let file_id = hex::encode(file_hash);

        let (relay_client, onion_router, anonymity_mode, mixnet_config) = {
            let guard = self.state.lock().unwrap();
            if guard.anonymity_mode_enabled.load(Ordering::Relaxed) && guard.onion_router.is_none() { return -9; }
            let rc = match guard.relay_client.clone() { Some(rc) => rc, None => return -3 };
            (rc, guard.onion_router.clone(), guard.anonymity_mode_enabled.clone(), guard.mixnet_config)
        };

        let send_res = self.runtime.block_on(async {
            let (target_url, payload_to_send) = if let Some(router) = &onion_router {
                 match router.build_circuit_from_config(&relay_client.base_url, &file_blob, mixnet_config) {
                     Ok(res) => res,
                     Err(_) => return Err(anyhow::anyhow!("Failed to build onion circuit for file")),
                 }
            } else {
                 (relay_client.base_url.clone(), file_blob)
            };
            let client_to_use = if target_url == relay_client.base_url { relay_client.clone() } else { RelayClient::new(&target_url) };
            orchestrator::send_blob_with_retry(&client_to_use, &file_id, peer_id, &payload_to_send, 3, Duration::from_millis(100), Duration::from_secs(2)).await
        });

        if send_res.is_err() { return -4; }

        #[derive(serde::Serialize)]
        struct FileMetadata { file_id: String, key: String, nonce: String, filename: String, size: usize }
        let meta = FileMetadata { file_id, key: hex::encode(key), nonce: hex::encode(nonce), filename: filename.to_string(), size: data.len() };
        let meta_json = serde_json::to_string(&meta).unwrap();
        self.send_payload(peer_id, &meta_json, "text", None, false)
    }
}

// --- Helpers ---

pub fn pad_envelope(mut data: Vec<u8>) -> Vec<u8> {
    let len = data.len();
    let target = if len <= 512 { 512 } else if len <= 1024 { 1024 } else if len <= 2048 { 2048 } else if len <= 4096 { 4096 } else { ((len + 4095) / 4096) * 4096 };
    if target > len {
        let padding = target - len;
        data.extend(std::iter::repeat(b' ').take(padding));
    }
    data
}

pub fn pad_storage(mut data: Vec<u8>) -> Vec<u8> {
    let len = data.len();
    let target = ((len + 65536 - 1) / 65536) * 65536;
    if target > len { data.resize(target, 0x20); }
    data
}

fn unseal_handshake(receiver_priv_bytes: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 32 + 16 { return None; }
    let (eph_pub_bytes, ciphertext) = blob.split_at(32);
    let eph_pub = crypto::x25519::PublicKey::from(TryInto::<[u8;32]>::try_into(eph_pub_bytes).ok()?);
    let recv_priv = crypto::x25519::PrivateKey::from(TryInto::<[u8;32]>::try_into(receiver_priv_bytes).ok()?);
    let shared_secret = crypto::x25519::diffie_hellman(&recv_priv, &eph_pub);
    let mut kdf = crypto::blake3::Hasher::new();
    kdf.update(&shared_secret);
    kdf.update(eph_pub_bytes);
    let key = kdf.finalize();
    let nonce = [0u8; 12];
    crate::crypto::chacha20poly1305::decrypt_with_nonce(key.as_bytes().try_into().unwrap(), &nonce, ciphertext).ok()
}

fn solve_pow(base_hasher: &crypto::blake3::Hasher, difficulty: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        let mut h = base_hasher.clone();
        h.update(&nonce.to_le_bytes());
        let hash = h.finalize();
        let bytes = hash.as_bytes();
        let mut zeros = 0;
        for &b in bytes {
            if b == 0 { zeros += 8; } else { zeros += b.leading_zeros(); break; }
        }
        if zeros >= difficulty { return nonce; }
        nonce += 1;
    }
}

pub fn compute_safety_fingerprint(our_key: &[u8], peer_key: &[u8]) -> String {
    let (k1, k2) = if our_key < peer_key { (our_key, peer_key) } else { (peer_key, our_key) };
    let mut combined = Vec::new();
    combined.extend_from_slice(k1);
    combined.extend_from_slice(k2);
    let hash = crypto::blake3::hash(&combined);
    hex::encode(hash)
}