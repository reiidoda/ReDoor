use crate::blockchain_client::verify_blockchain::BlockchainClient;
use crate::crypto;
use crate::engine::{AppState, BlockchainBatchObservation, ClientEngine, CommitmentInclusionProof};
use crate::network::onion::{MixnetConfig, OnionRouter};
use crate::network::relay::RelayClient;
use crate::orchestrator;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_SECURE_FIXED_POLL_MS: u64 = 1000;
const DEFAULT_SECURE_CONSTANT_RATE_MS: u64 = 1000;
const DEFAULT_SECURE_JITTER_PCT: u64 = 5;
const MAX_SECURE_JITTER_PCT: u64 = 10;
const DEFAULT_SECURE_JITTER_BUDGET_MS: u64 = 120;
const MAX_SECURE_JITTER_BUDGET_MS: u64 = 400;
const DEFAULT_SECURE_PHASE_OFFSET_PCT: u64 = 35;
const MAX_SECURE_PHASE_OFFSET_PCT: u64 = 90;
const DEFAULT_SECURE_PHASE_WINDOW_TICKS: u64 = 16;
const MAX_SECURE_PHASE_WINDOW_TICKS: u64 = 256;
const DEFAULT_SECURE_PHASE_WINDOW_PCT: u64 = 20;
const MAX_SECURE_PHASE_WINDOW_PCT: u64 = 50;
const SCHEDULER_STREAM_TAG_FIXED_POLL: u64 = 0xF1A0_F1A0_F1A0_F1A0;
const SCHEDULER_STREAM_TAG_CONSTANT_RATE: u64 = 0xC0A5_7A7E_C0A5_7A7E;
const MAX_COMMITMENT_PROOFS: usize = 4096;
const MAX_BATCH_OBSERVATIONS: usize = 128;
type MerkleProofSet = Vec<Vec<[u8; 32]>>;

fn route_payload(
    relay: &RelayClient,
    onion_router: Option<&OnionRouter>,
    mut mixnet_config: MixnetConfig,
    final_receiver: &str,
    blob: Vec<u8>,
    strict_anonymity: bool,
) -> Result<(RelayClient, String, Vec<u8>, bool), String> {
    let allow_direct_fallback = crate::config::mixnet_allow_direct_fallback();
    if strict_anonymity {
        mixnet_config.min_unique_operators = mixnet_config.min_unique_operators.max(2);
        mixnet_config.min_unique_jurisdictions = mixnet_config.min_unique_jurisdictions.max(2);
        mixnet_config.min_unique_asns = mixnet_config.min_unique_asns.max(2);
        mixnet_config.route_attempts = mixnet_config.route_attempts.max(16);
    }

    if let Some(router) = onion_router {
        match router.build_circuit_from_config(final_receiver, &blob, mixnet_config) {
            Ok((target_url, payload)) => {
                let client = if target_url == relay.base_url {
                    relay.clone()
                } else {
                    RelayClient::new(&target_url)
                };
                return Ok((client, "__mix__".to_string(), payload, false));
            }
            Err(err) => {
                if strict_anonymity {
                    return Err(format!(
                        "Strict anonymity route policy rejected mix path: {}",
                        err
                    ));
                }
                if !allow_direct_fallback {
                    return Err(format!(
                        "fallback_disabled: direct relay fallback blocked by policy ({})",
                        err
                    ));
                }
            }
        }
    } else if strict_anonymity {
        return Err("Strict anonymity requires a configured onion router".to_string());
    }

    Ok((relay.clone(), final_receiver.to_string(), blob, true))
}

fn record_route_policy_violation(state: &Arc<Mutex<AppState>>, reason: &str) {
    if let Ok(mut guard) = state.lock() {
        if let Ok(mut stats) = guard.traffic_stats.lock() {
            stats.route_policy_violations = stats.route_policy_violations.saturating_add(1);
            if reason.contains("fallback_disabled:") {
                stats.route_fallback_direct_blocked =
                    stats.route_fallback_direct_blocked.saturating_add(1);
            }
        }
        if guard.log_buffer.len() >= 1000 {
            guard.log_buffer.pop_front();
        }
        guard
            .log_buffer
            .push_back(format!("Mix route policy violation: {}", reason));
    }
}

fn record_route_fallback_usage(state: &Arc<Mutex<AppState>>, direct_fallback_used: bool) {
    if !direct_fallback_used {
        return;
    }
    if let Ok(guard) = state.lock() {
        if let Ok(mut stats) = guard.traffic_stats.lock() {
            stats.route_fallback_direct_used = stats.route_fallback_direct_used.saturating_add(1);
        }
    }
}

pub fn lock_all_sessions(engine: &ClientEngine) {
    {
        let mut guard = engine.state.lock().unwrap();
        for session in guard.sessions.values_mut() {
            session.inner = None;
        }
    }
    engine.log_internal("All sessions locked.".to_string());
}

pub fn handle_background_signal(engine: &ClientEngine) -> i32 {
    let guard = engine.state.lock().unwrap();

    let mode = guard.background_config.mode;
    let delay = guard.background_config.grace_period_ms;
    let gen = guard.background_generation.load(Ordering::Relaxed);

    let current_gen = gen;

    if mode == 0 {
        // Keep Alive
        return 0;
    } else if mode == 1 {
        // Immediate Wipe
        drop(guard);
        engine.mark_all_sessions_for_rekey("lifecycle_background_immediate");
        lock_all_sessions(engine);
        return 0;
    } else if mode == 2 {
        // Grace Period
        drop(guard);
        let state_clone = engine.state.clone();

        engine.runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;

            let bg_gen = state_clone
                .lock()
                .unwrap()
                .background_generation
                .load(Ordering::Relaxed);
            if bg_gen == current_gen {
                let mut guard = state_clone.lock().unwrap();
                guard.mark_all_sessions_rekey_pending("lifecycle_background_grace");
                for session in guard.sessions.values_mut() {
                    session.inner = None;
                }
                if guard.log_buffer.len() >= 1000 {
                    guard.log_buffer.pop_front();
                }
                guard
                    .log_buffer
                    .push_back("All sessions locked (background grace period).".to_string());
            }
        });
    }

    0
}

pub fn handle_foreground_signal(engine: &ClientEngine) -> i32 {
    let guard = engine.state.lock().unwrap();
    guard.background_generation.fetch_add(1, Ordering::Relaxed);
    drop(guard);
    engine.mark_all_sessions_for_rekey("lifecycle_foreground_resume");
    0
}

pub fn start_cover_traffic(engine: &ClientEngine, enable: bool) -> i32 {
    let guard = engine.state.lock().unwrap();

    guard.cover_traffic_enabled.store(enable, Ordering::Relaxed);
    let state_clone = engine.state.clone();
    let onion_router = guard.onion_router.clone();
    let mixnet_config = guard.mixnet_config;
    let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);

    if enable {
        let relay = match &guard.relay_client {
            Some(rc) => rc.clone(),
            None => return -1,
        };

        engine.runtime.spawn(async move {
            loop {
                let (is_enabled, is_low_power) = {
                    let g = state_clone.lock().unwrap();
                    (
                        g.cover_traffic_enabled.load(Ordering::Relaxed),
                        g.low_power_mode.load(Ordering::Relaxed),
                    )
                };

                if !is_enabled {
                    break;
                }

                if is_low_power {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }

                let sleep_ms = {
                    let mut rng = rand::thread_rng();
                    let (min, max) = {
                        let g = state_clone.lock().unwrap();
                        (
                            g.cover_traffic_config.min_delay_ms,
                            g.cover_traffic_config.max_delay_ms,
                        )
                    };
                    if min >= max {
                        min
                    } else {
                        rng.gen_range(min..=max)
                    }
                };

                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

                let (peer_id, ciphertext, blockchain_client) = {
                    let mut rng = rand::thread_rng();
                    let mut g = state_clone.lock().unwrap();
                    if !g.cover_traffic_enabled.load(Ordering::Relaxed) {
                        break;
                    }

                    let my_id_hex = g
                        .identity
                        .as_ref()
                        .map(|id| hex::encode(id.public_key_bytes()));

                    let keys: Vec<String> = g.sessions.keys().cloned().collect();
                    if !keys.is_empty() {
                        let idx = rng.gen_range(0..keys.len());
                        let pid = keys[idx].clone();

                        if let Some(entry) = g.sessions.get_mut(&pid) {
                            if let Some(session) = entry.inner.as_mut() {
                                if let Some(sender_id) = my_id_hex {
                                    let inner = crate::engine::InnerPayload {
                                        sender_id,
                                        content: "".to_string(),
                                        msg_type: "cover".to_string(),
                                        signature: vec![],
                                        group_id: None,
                                        counter: session.msg_count_send,
                                        commitment_nonce: rng.gen(),
                                    };
                                    if let Ok(inner_bytes) = serde_json::to_vec(&inner) {
                                        if let Ok(ct) = session.ratchet_encrypt(&inner_bytes) {
                                            (Some(pid), Some(ct), g.blockchain_client.clone())
                                        } else {
                                            (None, None, None)
                                        }
                                    } else {
                                        (None, None, None)
                                    }
                                } else {
                                    (None, None, None)
                                }
                            } else {
                                (None, None, None)
                            }
                        } else {
                            (None, None, None)
                        }
                    } else {
                        (None, None, None)
                    }
                };

                if let (Some(pid), Some(ct), Some(_)) = (peer_id, ciphertext, blockchain_client) {
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let mailbox_id = if let Ok(key) = std::env::var("RELAY_HMAC_KEY") {
                        let mut input = key.as_bytes().to_vec();
                        input.extend_from_slice(pid.as_bytes());
                        hex::encode(crypto::blake3::hash(&input))
                    } else {
                        hex::encode(crypto::blake3::hash(pid.as_bytes()))
                    };

                    let sender_id = state_clone
                        .lock()
                        .unwrap()
                        .identity
                        .as_ref()
                        .map(|id| hex::encode(id.public_key_bytes()))
                        .unwrap_or_default();
                    let envelope = crate::engine::Envelope {
                        mailbox_id,
                        sender_id,
                        timestamp,
                        ciphertext: ct,
                        pow_nonce: 0,
                    };
                    if let Ok(mut blob) = serde_json::to_vec(&envelope) {
                        blob = crate::engine::pad_envelope(blob);
                        let msg_hash = crypto::blake3::hash(&blob);
                        let msg_id = hex::encode(msg_hash);
                        let (client_to_use, transport_receiver, payload, direct_fallback_used) =
                            match route_payload(
                                &relay,
                                onion_router.as_ref(),
                                mixnet_config,
                                &pid,
                                blob,
                                strict_anonymity,
                            ) {
                                Ok(v) => v,
                                Err(reason) => {
                                    record_route_policy_violation(&state_clone, &reason);
                                    continue;
                                }
                            };
                        record_route_fallback_usage(&state_clone, direct_fallback_used);
                        let _ = orchestrator::send_blob_with_retry(
                            &client_to_use,
                            &msg_id,
                            &transport_receiver,
                            &payload,
                            1,
                            Duration::from_millis(100),
                            Duration::from_secs(1),
                        )
                        .await;
                    }
                } else {
                    let (msg_id, transport_receiver, payload, client_to_use) = {
                        let mut rng = rand::thread_rng();
                        let mut fake_pid = [0u8; 32];
                        rng.fill(&mut fake_pid);
                        let pid = hex::encode(fake_pid);
                        let mut ciphertext = vec![0u8; 200];
                        rng.fill(&mut ciphertext[..]);
                        let mailbox_id = hex::encode(crypto::blake3::hash(pid.as_bytes()));
                        let sender_id = hex::encode(fake_pid);
                        let envelope = crate::engine::Envelope {
                            mailbox_id,
                            sender_id,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            ciphertext,
                            pow_nonce: 0,
                        };

                        let mut blob = serde_json::to_vec(&envelope).unwrap_or_default();
                        blob = crate::engine::pad_envelope(blob);
                        let msg_id = hex::encode(crypto::blake3::hash(&blob));

                        let (client_to_use, transport_receiver, payload, direct_fallback_used) =
                            match route_payload(
                                &relay,
                                onion_router.as_ref(),
                                mixnet_config,
                                &pid,
                                blob,
                                strict_anonymity,
                            ) {
                                Ok(v) => v,
                                Err(reason) => {
                                    record_route_policy_violation(&state_clone, &reason);
                                    continue;
                                }
                            };
                        record_route_fallback_usage(&state_clone, direct_fallback_used);
                        (msg_id, transport_receiver, payload, client_to_use)
                    };

                    let _ = orchestrator::send_blob_with_retry(
                        &client_to_use,
                        &msg_id,
                        &transport_receiver,
                        &payload,
                        1,
                        Duration::from_millis(100),
                        Duration::from_secs(1),
                    )
                    .await;
                }

                if let Ok(g) = state_clone.lock() {
                    if let Ok(mut stats) = g.traffic_stats.lock() {
                        stats.cover_messages_sent += 1;
                    }
                }
            }
        });
    }

    0
}

fn normalize_leaf_hash(hash: &[u8]) -> [u8; 32] {
    if hash.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(hash);
        arr
    } else {
        crypto::blake3::hash(hash)
    }
}

pub fn build_merkle_root_and_proofs(leaves: &[[u8; 32]]) -> Option<([u8; 32], MerkleProofSet)> {
    if leaves.is_empty() {
        return None;
    }

    let mut level = leaves.to_vec();
    let mut positions: Vec<usize> = (0..leaves.len()).collect();
    let mut proofs = vec![Vec::<[u8; 32]>::new(); leaves.len()];

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }

        for (leaf_index, pos) in positions.iter_mut().enumerate() {
            let sibling_pos = if *pos % 2 == 0 { *pos + 1 } else { *pos - 1 };
            proofs[leaf_index].push(level[sibling_pos]);
            *pos /= 2;
        }

        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&pair[0]);
            combined.extend_from_slice(&pair[1]);
            next_level.push(crypto::blake3::hash(&combined));
        }
        level = next_level;
    }

    Some((level[0], proofs))
}

pub fn verify_merkle_inclusion(
    leaf: [u8; 32],
    leaf_index: usize,
    siblings: &[[u8; 32]],
    expected_root: [u8; 32],
) -> bool {
    let mut current = leaf;
    let mut index = leaf_index;

    for sibling in siblings {
        let mut combined = Vec::with_capacity(64);
        if index.is_multiple_of(2) {
            combined.extend_from_slice(&current);
            combined.extend_from_slice(sibling);
        } else {
            combined.extend_from_slice(sibling);
            combined.extend_from_slice(&current);
        }
        current = crypto::blake3::hash(&combined);
        index /= 2;
    }

    current == expected_root
}

pub fn compute_merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    let leaves: Vec<[u8; 32]> = hashes.iter().map(|h| normalize_leaf_hash(h)).collect();
    build_merkle_root_and_proofs(&leaves)
        .map(|(root, _)| root.to_vec())
        .unwrap_or_default()
}

fn compute_randomized_batch_delay_ms<R: Rng + ?Sized>(
    base_interval_ms: u64,
    jitter_pct: u64,
    rng: &mut R,
) -> u64 {
    let base = base_interval_ms.max(1);
    let bounded_jitter = jitter_pct.min(200);
    let max_extra = base.saturating_mul(bounded_jitter).saturating_div(100);
    if max_extra == 0 {
        return base;
    }
    base.saturating_add(rng.gen_range(0..=max_extra))
}

fn build_decoy_roots<R: Rng + ?Sized>(
    real_root: [u8; 32],
    batch_size: usize,
    decoy_count: usize,
    rng: &mut R,
) -> Vec<[u8; 32]> {
    if decoy_count == 0 {
        return Vec::new();
    }

    let mut decoys = Vec::with_capacity(decoy_count);
    for idx in 0..decoy_count {
        let mut noise = [0u8; 32];
        rng.fill(&mut noise);

        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(b"redoor-batch-decoy-v1");
        payload.extend_from_slice(&real_root);
        payload.extend_from_slice(&(batch_size as u64).to_be_bytes());
        payload.extend_from_slice(&(idx as u64).to_be_bytes());
        payload.extend_from_slice(&noise);
        decoys.push(crypto::blake3::hash(&payload));
    }
    decoys
}

pub fn start_blockchain_batching(engine: &ClientEngine, interval_ms: u64) -> i32 {
    let guard = engine.state.lock().unwrap();

    let fallback_per_message = crate::config::blockchain_batch_per_message_fallback();
    let scheduler_jitter_pct = crate::config::blockchain_batch_jitter_pct();
    let decoy_count = crate::config::blockchain_batch_decoy_count();
    let scheduler_seed = crate::config::blockchain_batch_scheduler_seed();
    let enabled = interval_ms > 0 && !fallback_per_message;
    guard.batching_enabled.store(enabled, Ordering::Relaxed);

    if let Ok(mut telemetry) = guard.blockchain_batch_telemetry.lock() {
        *telemetry = Default::default();
        telemetry.enabled = enabled;
        telemetry.configured_interval_ms = interval_ms;
        telemetry.scheduler_jitter_pct = scheduler_jitter_pct;
        telemetry.decoy_count = decoy_count;
        telemetry.scheduler_seed = scheduler_seed;
    }

    if enabled {
        let state_clone = engine.state.clone();
        if guard.blockchain_client.is_none() {
            guard.batching_enabled.store(false, Ordering::Relaxed);
            if let Ok(mut telemetry) = guard.blockchain_batch_telemetry.lock() {
                telemetry.enabled = false;
            }
            return -1;
        }

        let mut scheduler_rng = scheduler_seed
            .map(StdRng::seed_from_u64)
            .unwrap_or_else(StdRng::from_entropy);
        let mut last_tick_ms: Option<u64> = None;

        engine.runtime.spawn(async move {
            loop {
                let is_enabled = {
                    state_clone
                        .lock()
                        .unwrap()
                        .batching_enabled
                        .load(Ordering::Relaxed)
                };
                if !is_enabled {
                    break;
                }

                let scheduled_delay_ms = compute_randomized_batch_delay_ms(
                    interval_ms,
                    scheduler_jitter_pct,
                    &mut scheduler_rng,
                );
                tokio::time::sleep(Duration::from_millis(scheduled_delay_ms)).await;

                let now_ms = unix_now_millis();
                let observed_interval_ms = last_tick_ms
                    .map(|prev| now_ms.saturating_sub(prev))
                    .unwrap_or(0);
                let drift_ms = observed_interval_ms as i64 - scheduled_delay_ms as i64;
                last_tick_ms = Some(now_ms);

                {
                    let g = state_clone.lock().unwrap();
                    if let Ok(mut telemetry) = g.blockchain_batch_telemetry.lock() {
                        telemetry.ticks_total = telemetry.ticks_total.saturating_add(1);
                        telemetry.last_scheduled_delay_ms = scheduled_delay_ms;
                        telemetry.last_tick_interval_ms = observed_interval_ms;
                        if drift_ms >= 0 {
                            telemetry.max_positive_drift_ms =
                                telemetry.max_positive_drift_ms.max(drift_ms as u64);
                        } else {
                            telemetry.max_negative_drift_ms =
                                telemetry.max_negative_drift_ms.max((-drift_ms) as u64);
                        }
                    };
                }

                let (queued, client, signer) = {
                    let g = state_clone.lock().unwrap();
                    let mut q = g.blockchain_queue.lock().unwrap();
                    if q.is_empty() {
                        if let Ok(mut telemetry) = g.blockchain_batch_telemetry.lock() {
                            telemetry.empty_ticks = telemetry.empty_ticks.saturating_add(1);
                        }
                        continue;
                    }
                    let batch = q.clone();
                    q.clear();
                    (batch, g.blockchain_client.clone(), g.identity.clone())
                };
                let (Some(client), Some(signer)) = (client, signer) else {
                    continue;
                };

                let leaves: Vec<[u8; 32]> = queued.iter().map(|item| item.message_hash).collect();
                let Some((root, proofs)) = build_merkle_root_and_proofs(&leaves) else {
                    continue;
                };

                let submitted_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let decoy_roots =
                    build_decoy_roots(root, queued.len(), decoy_count, &mut scheduler_rng);

                {
                    let g = state_clone.lock().unwrap();
                    let mut proof_map = g.commitment_proofs.lock().unwrap();

                    for (idx, item) in queued.iter().enumerate() {
                        let siblings = proofs[idx].iter().map(hex::encode).collect::<Vec<String>>();
                        let receiver_commitment =
                            hex::encode(crypto::blake3::hash(item.receiver_id.as_bytes()));
                        let proof = CommitmentInclusionProof {
                            message_hash: hex::encode(item.message_hash),
                            merkle_root: hex::encode(root),
                            receiver_commitment,
                            leaf_index: idx,
                            siblings,
                            batch_size: queued.len(),
                            submitted_at,
                        };
                        proof_map.insert(hex::encode(item.message_hash), proof);
                    }

                    while proof_map.len() > MAX_COMMITMENT_PROOFS {
                        if let Some(first_key) = proof_map.keys().next().cloned() {
                            proof_map.remove(&first_key);
                        } else {
                            break;
                        }
                    }
                }

                let mut submit_ok = 0usize;
                let mut submit_failed = 0usize;
                let mut real_submitted = false;

                if orchestrator::submit_tx_with_retry(
                    &client,
                    &signer,
                    format!("batch-root:{}", queued.len()),
                    &root,
                    3,
                    Duration::from_millis(100),
                    Duration::from_secs(2),
                )
                .await
                .is_ok()
                {
                    submit_ok += 1;
                    real_submitted = true;
                } else {
                    submit_failed += 1;
                }

                let mut decoys_submitted = 0usize;
                for (idx, decoy_root) in decoy_roots.iter().enumerate() {
                    let decoy_receiver = format!("batch-decoy:{}:{}", queued.len(), idx);
                    if orchestrator::submit_tx_with_retry(
                        &client,
                        &signer,
                        decoy_receiver,
                        decoy_root,
                        3,
                        Duration::from_millis(100),
                        Duration::from_secs(2),
                    )
                    .await
                    .is_ok()
                    {
                        submit_ok += 1;
                        decoys_submitted += 1;
                    } else {
                        submit_failed += 1;
                    }
                }

                {
                    let g = state_clone.lock().unwrap();
                    if let Ok(mut telemetry) = g.blockchain_batch_telemetry.lock() {
                        telemetry.flushes_total = telemetry.flushes_total.saturating_add(1);
                        if real_submitted {
                            telemetry.real_commits_submitted =
                                telemetry.real_commits_submitted.saturating_add(1);
                        }
                        telemetry.decoy_commits_submitted = telemetry
                            .decoy_commits_submitted
                            .saturating_add(decoys_submitted as u64);
                        telemetry.submit_failures = telemetry
                            .submit_failures
                            .saturating_add(submit_failed as u64);
                        telemetry.last_submitted_at = submitted_at;
                        telemetry.recent_batches.push(BlockchainBatchObservation {
                            submitted_at,
                            real_batch_size: queued.len(),
                            real_root: hex::encode(root),
                            decoy_roots: decoy_roots.iter().map(hex::encode).collect(),
                            scheduled_delay_ms,
                            observed_interval_ms,
                            drift_ms,
                            submissions_ok: submit_ok,
                            submissions_failed: submit_failed,
                        });
                        if telemetry.recent_batches.len() > MAX_BATCH_OBSERVATIONS {
                            let trim = telemetry.recent_batches.len() - MAX_BATCH_OBSERVATIONS;
                            telemetry.recent_batches.drain(0..trim);
                        }
                    };
                }
            }
        });
    }
    0
}

pub fn send_cover_traffic_immediate(engine: &ClientEngine, size: usize) -> i32 {
    let relay_client = {
        let guard = engine.state.lock().unwrap();
        match guard.relay_client.clone() {
            Some(rc) => rc,
            None => return -2,
        }
    };

    engine.runtime.block_on(async {
        match relay_client.send_cover(size).await {
            Ok(_) => 0,
            Err(_) => -3,
        }
    })
}

pub fn wipe_sensitive_state(engine: &ClientEngine) {
    // Centralize wipe semantics in AppState::secure_wipe to avoid drift.
    engine.wipe_memory();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::crypto::ed25519::IdentityKey;
    use crate::engine::{ClientEngine, SessionEntry, StoredMessage};
    use crate::network::relay::RelayClient;
    use crate::ratchet::double_ratchet::RatchetSession;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn insert_active_session(engine: &ClientEngine, peer_id: &str) {
        engine.state.lock().unwrap().sessions.insert(
            peer_id.to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(RatchetSession::new([0u8; 32], None)),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );
    }

    #[test]
    fn test_lock_all_sessions() {
        let engine = ClientEngine::new();

        // Simulate an active session
        insert_active_session(&engine, "peer_test");

        lock_all_sessions(&engine);

        assert!(engine
            .state
            .lock()
            .unwrap()
            .sessions
            .get("peer_test")
            .unwrap()
            .inner
            .is_none());
    }

    #[test]
    fn test_background_grace_period_locks_session_after_delay() {
        let engine = ClientEngine::new();
        insert_active_session(&engine, "peer_background");

        {
            let mut guard = engine.state.lock().unwrap();
            guard.background_config.mode = 2;
            guard.background_config.grace_period_ms = 25;
        }

        assert_eq!(handle_background_signal(&engine), 0);
        engine
            .runtime
            .block_on(async { tokio::time::sleep(Duration::from_millis(100)).await });

        let guard = engine.state.lock().unwrap();
        let entry = guard
            .sessions
            .get("peer_background")
            .expect("session should exist");
        assert!(
            entry.inner.is_none(),
            "session should be locked after grace period"
        );
        assert!(
            guard
                .log_buffer
                .iter()
                .any(|line| line.contains("background grace period")),
            "expected lifecycle lock log entry"
        );
    }

    #[test]
    fn test_background_grace_period_cancelled_on_foreground_signal() {
        let engine = ClientEngine::new();
        insert_active_session(&engine, "peer_foreground");

        {
            let mut guard = engine.state.lock().unwrap();
            guard.background_config.mode = 2;
            guard.background_config.grace_period_ms = 50;
        }

        assert_eq!(handle_background_signal(&engine), 0);
        assert_eq!(handle_foreground_signal(&engine), 0);
        engine
            .runtime
            .block_on(async { tokio::time::sleep(Duration::from_millis(120)).await });

        let guard = engine.state.lock().unwrap();
        let entry = guard
            .sessions
            .get("peer_foreground")
            .expect("session should exist");
        assert!(
            entry.inner.is_some(),
            "foreground signal must cancel pending lifecycle lock"
        );
    }

    #[test]
    fn test_background_immediate_marks_sessions_for_rekey() {
        let engine = ClientEngine::new();
        insert_active_session(&engine, "peer_immediate");
        {
            let mut guard = engine.state.lock().unwrap();
            guard.background_config.mode = 1;
        }

        assert_eq!(handle_background_signal(&engine), 0);
        let mut guard = engine.state.lock().unwrap();
        let reason = guard.evaluate_session_rekey_requirement("peer_immediate");
        assert_eq!(reason.as_deref(), Some("lifecycle_background_immediate"));
    }

    #[test]
    fn test_foreground_signal_marks_sessions_for_rekey() {
        let engine = ClientEngine::new();
        insert_active_session(&engine, "peer_fg_rekey");

        assert_eq!(handle_foreground_signal(&engine), 0);
        let mut guard = engine.state.lock().unwrap();
        let reason = guard.evaluate_session_rekey_requirement("peer_fg_rekey");
        assert_eq!(reason.as_deref(), Some("lifecycle_foreground_resume"));
    }

    #[test]
    fn test_wipe_sensitive_state_clears_memory_structures() {
        let engine = ClientEngine::new();

        {
            let mut guard = engine.state.lock().unwrap();
            guard.identity = Some(IdentityKey::generate());
            guard.sessions.insert(
                "peer_sensitive".to_string(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new([0u8; 32], None)),
                    pending_handshake: None,
                    peer_seal_key: None,
                },
            );
            guard.message_store.insert(
                "peer_sensitive".to_string(),
                vec![StoredMessage {
                    id: "m1".to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    sender: "peer_sensitive".to_string(),
                    content: "top secret payload".to_string(),
                    msg_type: "text".to_string(),
                    group_id: None,
                    read: false,
                }],
            );
            guard
                .attachment_cache
                .insert("a1".to_string(), vec![1, 2, 3, 4, 5]);
        }

        wipe_sensitive_state(&engine);

        let guard = engine.state.lock().unwrap();
        assert!(guard.identity.is_none(), "identity should be wiped");
        assert!(guard.sessions.is_empty(), "sessions should be wiped");
        assert!(
            guard.message_store.is_empty(),
            "message store should be wiped"
        );
        assert!(
            guard.attachment_cache.is_empty(),
            "attachment cache should be wiped"
        );
    }

    #[test]
    fn test_enter_duress_mode_replaces_real_state_with_fake_history() {
        let engine = ClientEngine::new();

        {
            let mut guard = engine.state.lock().unwrap();
            guard.identity = Some(IdentityKey::generate());
            guard.sessions.insert(
                "peer_real".to_string(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new([0u8; 32], None)),
                    pending_handshake: None,
                    peer_seal_key: None,
                },
            );
            guard.message_store.insert(
                "peer_real".to_string(),
                vec![StoredMessage {
                    id: "real-1".to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    sender: "peer_real".to_string(),
                    content: "ultra-sensitive real message".to_string(),
                    msg_type: "text".to_string(),
                    group_id: None,
                    read: false,
                }],
            );
        }

        assert_eq!(enter_duress_mode(&engine), 0);

        let guard = engine.state.lock().unwrap();
        assert!(
            guard.identity.is_some(),
            "duress mode should seed fake identity"
        );
        assert!(
            !guard.sessions.is_empty(),
            "duress mode should generate fake sessions"
        );
        assert!(
            !guard.message_store.is_empty(),
            "duress mode should generate fake history"
        );
        assert!(
            !guard.sessions.contains_key("peer_real"),
            "real session should not survive duress mode"
        );
        assert!(
            !guard.message_store.contains_key("peer_real"),
            "real message history should not survive duress mode"
        );
        assert!(
            guard
                .log_buffer
                .iter()
                .any(|line| line.contains("Duress mode activated")),
            "duress mode should emit an audit log entry"
        );
    }

    #[test]
    fn test_secure_profile_enforces_fixed_polling_when_strict() {
        assert_eq!(
            normalize_fixed_poll_interval(0, true),
            secure_profile_fixed_poll_ms()
        );
        assert_eq!(normalize_fixed_poll_interval(1200, true), 1200);
        assert_eq!(normalize_fixed_poll_interval(0, false), 0);
    }

    #[test]
    fn test_secure_profile_enforces_constant_rate_when_strict() {
        assert_eq!(
            normalize_constant_rate_interval(0, true),
            secure_profile_constant_rate_ms()
        );
        assert_eq!(normalize_constant_rate_interval(800, true), 800);
        assert_eq!(normalize_constant_rate_interval(0, false), 0);
    }

    #[test]
    fn test_secure_profile_enforces_fixed_transport_cell_default() {
        let engine = ClientEngine::new();
        config::set_traffic_shaping(config::TrafficShapingConfig {
            pad_to: 0,
            min_delay_ms: 0,
            max_delay_ms: 0,
        });

        {
            let mut guard = engine.state.lock().unwrap();
            guard.identity = Some(IdentityKey::generate());
            guard.relay_client = Some(RelayClient::new("https://relay.example"));
            guard.anonymity_mode_enabled.store(true, Ordering::Relaxed);
        }

        assert_eq!(start_constant_rate_traffic(&engine, 0), 0);
        let shaping = config::get_traffic_shaping();
        assert_eq!(shaping.pad_to, 4096);

        // Stop spawned loop for test hygiene.
        let guard = engine.state.lock().unwrap();
        guard.constant_rate_enabled.store(false, Ordering::Relaxed);
    }

    #[test]
    fn test_bounded_jitter_stays_within_profile_limits() {
        let base = 1000u64;
        let jitter_pct = 5u64;
        for _ in 0..128 {
            let value = apply_bounded_jitter(base, jitter_pct, u64::MAX);
            assert!((950..=1050).contains(&value));
        }
    }

    #[test]
    fn test_bounded_jitter_respects_budget_cap() {
        let base = 1000u64;
        let jitter_pct = 10u64;
        let jitter_budget_ms = 20u64;
        for _ in 0..128 {
            let value = apply_bounded_jitter(base, jitter_pct, jitter_budget_ms);
            assert!((980..=1020).contains(&value));
        }
    }

    #[test]
    fn test_scheduler_rng_sequence_is_deterministic_with_seed_override() {
        let prev = std::env::var("REDOOR_SECURE_SCHEDULER_SEED").ok();
        std::env::set_var("REDOOR_SECURE_SCHEDULER_SEED", "424242");

        let base = 1000u64;
        let mut rng_a = scheduler_rng_for_loop(base, true, SCHEDULER_STREAM_TAG_FIXED_POLL);
        let mut rng_b = scheduler_rng_for_loop(base, true, SCHEDULER_STREAM_TAG_FIXED_POLL);

        let mut seq_a = Vec::new();
        let mut seq_b = Vec::new();
        for tick in 0..64u64 {
            let a_shift = sample_phase_window_shift_ms_with_rng(base, true, tick, &mut rng_a);
            let a_step = apply_bounded_jitter_with_rng(base, 5, 120, &mut rng_a);
            seq_a.push((a_shift, a_step));

            let b_shift = sample_phase_window_shift_ms_with_rng(base, true, tick, &mut rng_b);
            let b_step = apply_bounded_jitter_with_rng(base, 5, 120, &mut rng_b);
            seq_b.push((b_shift, b_step));
        }
        assert_eq!(
            seq_a, seq_b,
            "seed override should produce deterministic schedule"
        );

        if let Some(value) = prev {
            std::env::set_var("REDOOR_SECURE_SCHEDULER_SEED", value);
        } else {
            std::env::remove_var("REDOOR_SECURE_SCHEDULER_SEED");
        }
    }

    #[test]
    fn test_scheduler_rng_stream_tags_avoid_identical_sequences() {
        let prev = std::env::var("REDOOR_SECURE_SCHEDULER_SEED").ok();
        std::env::set_var("REDOOR_SECURE_SCHEDULER_SEED", "424242");

        let base = 1000u64;
        let mut fixed_rng = scheduler_rng_for_loop(base, true, SCHEDULER_STREAM_TAG_FIXED_POLL);
        let mut constant_rng =
            scheduler_rng_for_loop(base, true, SCHEDULER_STREAM_TAG_CONSTANT_RATE);

        let fixed: Vec<u64> = (0..32)
            .map(|tick| {
                sample_phase_window_shift_ms_with_rng(base, true, tick, &mut fixed_rng)
                    + apply_bounded_jitter_with_rng(base, 5, 120, &mut fixed_rng)
            })
            .collect();
        let constant: Vec<u64> = (0..32)
            .map(|tick| {
                sample_phase_window_shift_ms_with_rng(base, true, tick, &mut constant_rng)
                    + apply_bounded_jitter_with_rng(base, 5, 120, &mut constant_rng)
            })
            .collect();

        assert_ne!(
            fixed, constant,
            "distinct scheduler streams must not share identical timing sequence"
        );

        if let Some(value) = prev {
            std::env::set_var("REDOOR_SECURE_SCHEDULER_SEED", value);
        } else {
            std::env::remove_var("REDOOR_SECURE_SCHEDULER_SEED");
        }
    }

    #[test]
    fn test_secure_phase_offset_stays_within_bounds() {
        let prev = std::env::var("REDOOR_SECURE_PHASE_OFFSET_PCT").ok();
        std::env::set_var("REDOOR_SECURE_PHASE_OFFSET_PCT", "40");

        let base = 1000u64;
        for _ in 0..128 {
            let value = sample_phase_offset_ms(base, true);
            assert!(value <= 400);
        }
        assert_eq!(sample_phase_offset_ms(base, false), 0);
        assert_eq!(sample_phase_offset_ms(0, true), 0);

        if let Some(value) = prev {
            std::env::set_var("REDOOR_SECURE_PHASE_OFFSET_PCT", value);
        } else {
            std::env::remove_var("REDOOR_SECURE_PHASE_OFFSET_PCT");
        }
    }

    #[test]
    fn test_secure_phase_window_shift_applies_only_on_boundaries() {
        let prev_ticks = std::env::var("REDOOR_SECURE_PHASE_WINDOW_TICKS").ok();
        let prev_pct = std::env::var("REDOOR_SECURE_PHASE_WINDOW_PCT").ok();
        std::env::set_var("REDOOR_SECURE_PHASE_WINDOW_TICKS", "4");
        std::env::set_var("REDOOR_SECURE_PHASE_WINDOW_PCT", "30");

        let base = 1000u64;
        assert_eq!(sample_phase_window_shift_ms(base, true, 1), 0);
        assert_eq!(sample_phase_window_shift_ms(base, true, 2), 0);
        assert_eq!(sample_phase_window_shift_ms(base, true, 3), 0);
        assert_eq!(sample_phase_window_shift_ms(base, false, 4), 0);
        assert!(sample_phase_window_shift_ms(base, true, 4) <= 300);
        assert!(sample_phase_window_shift_ms(base, true, 8) <= 300);

        if let Some(value) = prev_ticks {
            std::env::set_var("REDOOR_SECURE_PHASE_WINDOW_TICKS", value);
        } else {
            std::env::remove_var("REDOOR_SECURE_PHASE_WINDOW_TICKS");
        }
        if let Some(value) = prev_pct {
            std::env::set_var("REDOOR_SECURE_PHASE_WINDOW_PCT", value);
        } else {
            std::env::remove_var("REDOOR_SECURE_PHASE_WINDOW_PCT");
        }
    }

    #[test]
    fn test_merkle_proofs_verify_each_leaf() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];
        let (root, proofs) =
            build_merkle_root_and_proofs(&leaves).expect("merkle root should be produced");

        for (index, leaf) in leaves.iter().enumerate() {
            assert!(
                verify_merkle_inclusion(*leaf, index, &proofs[index], root),
                "proof should validate for leaf index {}",
                index
            );
        }
    }

    #[test]
    fn test_merkle_proof_detects_tampered_leaf() {
        let leaves = vec![[7u8; 32], [8u8; 32], [9u8; 32]];
        let (root, proofs) =
            build_merkle_root_and_proofs(&leaves).expect("merkle root should be produced");

        let mut tampered = leaves[1];
        tampered[0] ^= 0xFF;
        assert!(
            !verify_merkle_inclusion(tampered, 1, &proofs[1], root),
            "tampered leaf must fail inclusion proof verification"
        );
    }

    #[test]
    fn test_start_blockchain_batching_respects_fallback_flag() {
        std::env::set_var("REDOOR_BLOCKCHAIN_PER_MESSAGE_FALLBACK", "1");
        let engine = ClientEngine::new();
        let rc = start_blockchain_batching(&engine, 1000);
        assert_eq!(rc, 0);
        let guard = engine.state.lock().unwrap();
        assert!(
            !guard.batching_enabled.load(Ordering::Relaxed),
            "fallback mode must disable aggregated batching"
        );
        std::env::remove_var("REDOOR_BLOCKCHAIN_PER_MESSAGE_FALLBACK");
    }

    #[test]
    fn test_randomized_batch_delay_is_deterministic_with_seed() {
        let mut rng_a = StdRng::seed_from_u64(42);
        let mut rng_b = StdRng::seed_from_u64(42);

        let mut seq_a = Vec::new();
        let mut seq_b = Vec::new();
        for _ in 0..16 {
            seq_a.push(compute_randomized_batch_delay_ms(5_000, 35, &mut rng_a));
            seq_b.push(compute_randomized_batch_delay_ms(5_000, 35, &mut rng_b));
        }

        assert_eq!(seq_a, seq_b, "seeded scheduler sequence must be stable");
    }

    #[test]
    fn test_randomized_batch_delay_respects_bounds() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..128 {
            let delay = compute_randomized_batch_delay_ms(4_000, 25, &mut rng);
            assert!((4_000..=5_000).contains(&delay));
        }
    }

    #[test]
    fn test_decoy_roots_are_deterministic_and_distinct() {
        let real_root = [9u8; 32];
        let mut rng_a = StdRng::seed_from_u64(99);
        let mut rng_b = StdRng::seed_from_u64(99);

        let decoys_a = build_decoy_roots(real_root, 5, 3, &mut rng_a);
        let decoys_b = build_decoy_roots(real_root, 5, 3, &mut rng_b);

        assert_eq!(decoys_a, decoys_b, "seeded decoys must be deterministic");
        assert_eq!(decoys_a.len(), 3);
        assert!(decoys_a.iter().all(|root| root != &real_root));
        assert_ne!(decoys_a[0], decoys_a[1]);
    }

    #[test]
    fn test_start_blockchain_batching_records_scheduler_telemetry() {
        std::env::set_var("REDOOR_SECURE_BLOCKCHAIN_BATCH_JITTER_PCT", "50");
        std::env::set_var("REDOOR_SECURE_BLOCKCHAIN_BATCH_DECOY_COUNT", "2");
        std::env::set_var("REDOOR_SECURE_BLOCKCHAIN_BATCH_SEED", "1337");

        let engine = ClientEngine::new();
        {
            let mut guard = engine.state.lock().unwrap();
            guard.identity = Some(IdentityKey::generate());
            guard.blockchain_client =
                Some(BlockchainClient::new("http://127.0.0.1:9444".to_string()));
        }

        assert_eq!(start_blockchain_batching(&engine, 1_000), 0);
        let guard = engine.state.lock().unwrap();
        let telemetry = guard.blockchain_batch_telemetry.lock().unwrap().clone();
        assert_eq!(telemetry.configured_interval_ms, 1_000);
        assert_eq!(telemetry.scheduler_jitter_pct, 50);
        assert_eq!(telemetry.decoy_count, 2);
        assert_eq!(telemetry.scheduler_seed, Some(1337));
        guard.batching_enabled.store(false, Ordering::Relaxed);

        std::env::remove_var("REDOOR_SECURE_BLOCKCHAIN_BATCH_JITTER_PCT");
        std::env::remove_var("REDOOR_SECURE_BLOCKCHAIN_BATCH_DECOY_COUNT");
        std::env::remove_var("REDOOR_SECURE_BLOCKCHAIN_BATCH_SEED");
    }
}

pub fn generate_fake_history(engine: &ClientEngine, num_peers: i32, msgs_per_peer: i32) -> i32 {
    let mut guard = engine.state.lock().unwrap();
    let mut rng = rand::thread_rng();

    for _ in 0..num_peers {
        // Generate fake peer ID
        let mut pid_bytes = [0u8; 32];
        rng.fill(&mut pid_bytes);
        let peer_id = hex::encode(pid_bytes);

        // Generate fake nickname
        let nicknames = [
            "Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi",
        ];
        let nick = format!("{} (Fake)", nicknames[rng.gen_range(0..nicknames.len())]);
        guard.nicknames.insert(peer_id.clone(), nick);

        // Generate fake session (locked/empty)
        let session = crate::engine::SessionEntry {
            wrapped_state: Some(vec![0u8; 32]), // Fake wrapped data
            inner: None,                        // Locked
            pending_handshake: None,
            peer_seal_key: None,
        };
        guard.sessions.insert(peer_id.clone(), session);

        // Generate fake messages
        let mut msgs = Vec::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for _ in 0..msgs_per_peer {
            let time_offset = rng.gen_range(0..86400 * 30); // Up to 30 days ago
            let timestamp = now - time_offset;

            let is_sent = rng.gen_bool(0.5);
            let sender = if is_sent {
                if let Some(id) = &guard.identity {
                    hex::encode(id.public_key_bytes())
                } else {
                    "me".to_string()
                }
            } else {
                peer_id.clone()
            };

            let vocab = [
                "lorem",
                "ipsum",
                "dolor",
                "sit",
                "amet",
                "consectetur",
                "adipiscing",
                "elit",
                "sed",
                "do",
                "eiusmod",
                "tempor",
                "incididunt",
                "ut",
                "labore",
                "et",
                "dolore",
                "magna",
                "aliqua",
            ];
            let content = (0..rng.gen_range(3..15))
                .map(|_| vocab[rng.gen_range(0..vocab.len())])
                .collect::<Vec<&str>>()
                .join(" ");

            let mut msg_id_bytes = [0u8; 16];
            rng.fill(&mut msg_id_bytes);
            let msg_id = hex::encode(msg_id_bytes);

            msgs.push(crate::engine::StoredMessage {
                id: msg_id,
                timestamp,
                sender,
                content,
                msg_type: "text".to_string(),
                group_id: None,
                read: true,
            });
        }

        msgs.sort_by_key(|m| m.timestamp);
        guard.message_store.insert(peer_id, msgs);
    }
    0
}

pub fn enter_duress_mode(engine: &ClientEngine) -> i32 {
    engine.wipe_memory();

    // Generate a fresh random identity for the fake profile so it looks functional
    {
        let mut guard = engine.state.lock().unwrap();
        let id = crypto::ed25519::IdentityKey::generate();
        guard.identity = Some(id.clone());

        // Generate prekeys and Kyber keys to complete the fake profile appearance
        if let Ok((_, secrets)) = crate::crypto::x3dh::generate_prekey_bundle(&id) {
            guard.prekey_secrets = Some(secrets);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            guard.signed_prekey_last_rotated_at = Some(now);
            guard.prekey_last_replenished_at = Some(now);
        }
        #[cfg(feature = "pq")]
        {
            use pqcrypto_kyber::kyber1024;
            guard.kyber_keys = Some(kyber1024::keypair());
        }
    }

    generate_fake_history(engine, 5, 20);
    engine.log_internal("Duress mode activated. Real data wiped, fake data generated.".to_string());
    0
}

pub fn configure_network(engine: &ClientEngine, relay_url: &str, blockchain_addr: &str) {
    let mut guard = engine.state.lock().unwrap();
    guard.relay_client = Some(RelayClient::new(relay_url));
    guard.blockchain_client = Some(BlockchainClient::new(blockchain_addr.to_string()));
    let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);
    engine.log_internal(format!(
        "Network configured. Relay: {}, Blockchain: {}",
        relay_url, blockchain_addr
    ));
    drop(guard);

    if strict_anonymity {
        let poll_rc = start_fixed_polling(engine, 0);
        let traffic_rc = start_constant_rate_traffic(engine, 0);
        if poll_rc != 0 || traffic_rc != 0 {
            engine.log_internal(
                "Secure profile pending: runtime prerequisites are not ready yet.".to_string(),
            );
        } else {
            engine.log_internal(
                "Secure profile enforced: fixed polling + mandatory cover-capable constant-rate traffic."
                    .to_string(),
            );
        }
    }
}

pub fn start_message_batching(engine: &ClientEngine, interval_ms: u64) -> i32 {
    let guard = engine.state.lock().unwrap();

    let enabled = interval_ms > 0;
    guard
        .outgoing_batching_enabled
        .store(enabled, Ordering::Relaxed);
    guard
        .outgoing_batch_interval_ms
        .store(interval_ms, Ordering::Relaxed);

    if enabled {
        let relay = match &guard.relay_client {
            Some(rc) => rc.clone(),
            None => return -1,
        };
        let onion_router = guard.onion_router.clone();
        let mixnet_config = guard.mixnet_config;
        let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);
        let state_clone = engine.state.clone();

        engine.runtime.spawn(async move {
            loop {
                let is_enabled = state_clone
                    .lock()
                    .unwrap()
                    .outgoing_batching_enabled
                    .load(Ordering::Relaxed);
                if !is_enabled {
                    break;
                }

                let jitter = rand::thread_rng().gen_range(0..=interval_ms / 5);
                tokio::time::sleep(Duration::from_millis(interval_ms + jitter)).await;

                let batch = {
                    let g = state_clone.lock().unwrap();
                    let mut q = g.outgoing_queue.lock().unwrap();
                    if q.is_empty() {
                        continue;
                    }
                    let mut b = Vec::new();
                    while let Some(msg) = q.pop_front() {
                        b.push(msg);
                    }
                    b
                };

                for msg in batch {
                    let (client_to_use, transport_receiver, payload, direct_fallback_used) =
                        match route_payload(
                            &relay,
                            onion_router.as_ref(),
                            mixnet_config,
                            &msg.peer_id,
                            msg.blob.clone(),
                            strict_anonymity,
                        ) {
                            Ok(v) => v,
                            Err(reason) => {
                                record_route_policy_violation(&state_clone, &reason);
                                continue;
                            }
                        };
                    record_route_fallback_usage(&state_clone, direct_fallback_used);
                    let _ = orchestrator::send_blob_with_retry(
                        &client_to_use,
                        &msg.msg_id,
                        &transport_receiver,
                        &payload,
                        3,
                        Duration::from_millis(100),
                        Duration::from_secs(2),
                    )
                    .await;
                }
            }
        });
    }
    0
}

pub fn start_fixed_polling(engine: &ClientEngine, interval_ms: u64) -> i32 {
    let guard = engine.state.lock().unwrap();
    let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);
    let interval_ms = normalize_fixed_poll_interval(interval_ms, strict_anonymity);
    let jitter_pct = secure_profile_jitter_pct();
    let jitter_budget_ms = if strict_anonymity {
        secure_profile_jitter_budget_ms()
    } else {
        u64::MAX
    };

    let enabled = interval_ms > 0;
    let was_enabled = guard.fixed_polling_enabled.swap(enabled, Ordering::Relaxed);
    if enabled && was_enabled {
        return 0;
    }
    if !enabled {
        return 0;
    }

    let relay = match &guard.relay_client {
        Some(rc) => rc.clone(),
        None => {
            guard.fixed_polling_enabled.store(false, Ordering::Relaxed);
            return -1;
        }
    };
    let my_id = match &guard.identity {
        Some(id) => hex::encode(id.public_key_bytes()),
        None => {
            guard.fixed_polling_enabled.store(false, Ordering::Relaxed);
            return -1;
        }
    };

    let state_clone = engine.state.clone();
    let mut scheduler_rng = scheduler_rng_for_loop(
        interval_ms,
        strict_anonymity,
        SCHEDULER_STREAM_TAG_FIXED_POLL,
    );
    let initial_phase_offset_ms =
        sample_phase_offset_ms_with_rng(interval_ms, strict_anonymity, &mut scheduler_rng);

    engine.runtime.spawn(async move {
        let mut tick_count = 0u64;
        let mut scheduler_rng = scheduler_rng;
        if initial_phase_offset_ms > 0 {
            tokio::time::sleep(Duration::from_millis(initial_phase_offset_ms)).await;
        }
        loop {
            let is_enabled = state_clone
                .lock()
                .unwrap()
                .fixed_polling_enabled
                .load(Ordering::Relaxed);
            if !is_enabled {
                break;
            }

            let phase_window_shift_ms = sample_phase_window_shift_ms_with_rng(
                interval_ms,
                strict_anonymity,
                tick_count,
                &mut scheduler_rng,
            );
            if phase_window_shift_ms > 0 {
                tokio::time::sleep(Duration::from_millis(phase_window_shift_ms)).await;
            }

            let sleep_ms = apply_bounded_jitter_with_rng(
                interval_ms,
                jitter_pct,
                jitter_budget_ms,
                &mut scheduler_rng,
            );
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            tick_count = tick_count.saturating_add(1);

            if let Ok(g) = state_clone.lock() {
                if let Ok(mut stats) = g.traffic_stats.lock() {
                    stats.poll_ticks += 1;
                    stats.last_poll_tick_unix_ms = unix_now_millis();
                }
            }

            match orchestrator::fetch_pending_with_retry(
                &relay,
                &my_id,
                1,
                Duration::from_millis(100),
                Duration::from_millis(100),
            )
            .await
            {
                Ok((msg_id, blob)) => {
                    state_clone
                        .lock()
                        .unwrap()
                        .pending_blobs
                        .lock()
                        .unwrap()
                        .push_back((msg_id, blob));
                }
                Err(_) => {
                    if let Ok(g) = state_clone.lock() {
                        if let Ok(mut stats) = g.traffic_stats.lock() {
                            stats.poll_failures += 1;
                        }
                    }
                }
            }
        }
    });
    0
}

pub fn start_constant_rate_traffic(engine: &ClientEngine, interval_ms: u64) -> i32 {
    let guard = engine.state.lock().unwrap();
    let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);
    let interval_ms = normalize_constant_rate_interval(interval_ms, strict_anonymity);
    let jitter_pct = secure_profile_jitter_pct();
    let jitter_budget_ms = if strict_anonymity {
        secure_profile_jitter_budget_ms()
    } else {
        u64::MAX
    };
    drop(guard);

    if strict_anonymity {
        let mut shaping = crate::config::get_traffic_shaping();
        if shaping.pad_to == 0 {
            shaping.pad_to = 4096;
            crate::config::set_traffic_shaping(shaping);
            engine.log_internal(
                "Secure profile enforced fixed-size transport cells (pad_to=4096).".to_string(),
            );
        }
    }

    let enabled = interval_ms > 0;
    let guard = engine.state.lock().unwrap();
    let was_enabled = guard.constant_rate_enabled.swap(enabled, Ordering::Relaxed);
    if enabled && was_enabled {
        return 0;
    }
    if !enabled {
        return 0;
    }

    let relay = match &guard.relay_client {
        Some(rc) => rc.clone(),
        None => {
            guard.constant_rate_enabled.store(false, Ordering::Relaxed);
            return -1;
        }
    };
    let onion_router = guard.onion_router.clone();
    let mixnet_config = guard.mixnet_config;
    let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);
    let state_clone = engine.state.clone();
    let bg_gen = guard.background_generation.load(Ordering::Relaxed);
    let current_gen = bg_gen;
    let mut scheduler_rng = scheduler_rng_for_loop(
        interval_ms,
        strict_anonymity,
        SCHEDULER_STREAM_TAG_CONSTANT_RATE,
    );
    let initial_phase_offset_ms =
        sample_phase_offset_ms_with_rng(interval_ms, strict_anonymity, &mut scheduler_rng);

    engine.runtime.spawn(async move {
        let mut tick_count = 0u64;
        let mut scheduler_rng = scheduler_rng;
        if initial_phase_offset_ms > 0 {
            tokio::time::sleep(Duration::from_millis(initial_phase_offset_ms)).await;
        }
        loop {
            let (is_enabled, bg_gen) = {
                let g = state_clone.lock().unwrap();
                (
                    g.constant_rate_enabled.load(Ordering::Relaxed),
                    g.background_generation.load(Ordering::Relaxed),
                )
            };

            if !is_enabled || bg_gen != current_gen {
                break;
            }

            let phase_window_shift_ms = sample_phase_window_shift_ms_with_rng(
                interval_ms,
                strict_anonymity,
                tick_count,
                &mut scheduler_rng,
            );
            if phase_window_shift_ms > 0 {
                tokio::time::sleep(Duration::from_millis(phase_window_shift_ms)).await;
            }

            let sleep_ms = apply_bounded_jitter_with_rng(
                interval_ms,
                jitter_pct,
                jitter_budget_ms,
                &mut scheduler_rng,
            );
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            tick_count = tick_count.saturating_add(1);

            if let Ok(g) = state_clone.lock() {
                if let Ok(mut stats) = g.traffic_stats.lock() {
                    stats.send_ticks += 1;
                    stats.last_send_tick_unix_ms = unix_now_millis();
                }
            }

            let real_msg = {
                let g = state_clone.lock().unwrap();
                let msg = g.outgoing_queue.lock().unwrap().pop_front();
                msg
            };

            if let Some(msg) = real_msg {
                let (client_to_use, transport_receiver, payload, direct_fallback_used) =
                    match route_payload(
                        &relay,
                        onion_router.as_ref(),
                        mixnet_config,
                        &msg.peer_id,
                        msg.blob.clone(),
                        strict_anonymity,
                    ) {
                        Ok(v) => v,
                        Err(reason) => {
                            if let Ok(g) = state_clone.lock() {
                                if let Ok(mut stats) = g.traffic_stats.lock() {
                                    stats.send_failures += 1;
                                }
                            }
                            record_route_policy_violation(&state_clone, &reason);
                            continue;
                        }
                    };
                record_route_fallback_usage(&state_clone, direct_fallback_used);
                let send_result = orchestrator::send_blob_with_retry(
                    &client_to_use,
                    &msg.msg_id,
                    &transport_receiver,
                    &payload,
                    3,
                    Duration::from_millis(100),
                    Duration::from_secs(2),
                )
                .await;
                if let Ok(g) = state_clone.lock() {
                    if let Ok(mut stats) = g.traffic_stats.lock() {
                        if send_result.is_ok() {
                            stats.real_messages_sent += 1;
                        } else {
                            stats.send_failures += 1;
                        }
                    }
                }
            } else {
                let (peer_id, ciphertext) = {
                    let mut rng = rand::thread_rng();
                    let mut g = state_clone.lock().unwrap();
                    let my_id_hex = g
                        .identity
                        .as_ref()
                        .map(|id| hex::encode(id.public_key_bytes()));
                    let keys: Vec<String> = g.sessions.keys().cloned().collect();
                    if !keys.is_empty() {
                        let idx = rng.gen_range(0..keys.len());
                        let pid = keys[idx].clone();
                        if let Some(entry) = g.sessions.get_mut(&pid) {
                            if let Some(session) = entry.inner.as_mut() {
                                if let Some(sender_id) = my_id_hex {
                                    let inner = crate::engine::InnerPayload {
                                        sender_id,
                                        content: "".to_string(),
                                        msg_type: "cover".to_string(),
                                        signature: vec![],
                                        group_id: None,
                                        counter: session.msg_count_send,
                                        commitment_nonce: rng.gen(),
                                    };
                                    if let Ok(ib) = serde_json::to_vec(&inner) {
                                        if let Ok(ct) = session.ratchet_encrypt(&ib) {
                                            (Some(pid), Some(ct))
                                        } else {
                                            (None, None)
                                        }
                                    } else {
                                        (None, None)
                                    }
                                } else {
                                    (None, None)
                                }
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                };

                if let (Some(pid), Some(ct)) = (peer_id, ciphertext) {
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mailbox_id = hex::encode(crypto::blake3::hash(pid.as_bytes()));
                    let sender_id = state_clone
                        .lock()
                        .unwrap()
                        .identity
                        .as_ref()
                        .map(|id| hex::encode(id.public_key_bytes()))
                        .unwrap_or_default();
                    let envelope = crate::engine::Envelope {
                        mailbox_id,
                        sender_id,
                        timestamp,
                        ciphertext: ct,
                        pow_nonce: 0,
                    };
                    if let Ok(mut blob) = serde_json::to_vec(&envelope) {
                        blob = crate::engine::pad_envelope(blob);
                        let msg_hash = crypto::blake3::hash(&blob);
                        let msg_id = hex::encode(msg_hash);
                        let (client_to_use, transport_receiver, payload, direct_fallback_used) =
                            match route_payload(
                                &relay,
                                onion_router.as_ref(),
                                mixnet_config,
                                &pid,
                                blob,
                                strict_anonymity,
                            ) {
                                Ok(v) => v,
                                Err(reason) => {
                                    if let Ok(g) = state_clone.lock() {
                                        if let Ok(mut stats) = g.traffic_stats.lock() {
                                            stats.send_failures += 1;
                                        }
                                    }
                                    record_route_policy_violation(&state_clone, &reason);
                                    continue;
                                }
                            };
                        record_route_fallback_usage(&state_clone, direct_fallback_used);
                        let send_result = orchestrator::send_blob_with_retry(
                            &client_to_use,
                            &msg_id,
                            &transport_receiver,
                            &payload,
                            1,
                            Duration::from_millis(100),
                            Duration::from_secs(1),
                        )
                        .await;
                        if let Ok(g) = state_clone.lock() {
                            if let Ok(mut stats) = g.traffic_stats.lock() {
                                if send_result.is_ok() {
                                    stats.cover_messages_sent += 1;
                                } else {
                                    stats.send_failures += 1;
                                }
                            }
                        }
                    }
                } else {
                    let (msg_id, transport_receiver, payload, client_to_use) = {
                        let mut rng = rand::thread_rng();
                        let mut fake_pid = [0u8; 32];
                        rng.fill(&mut fake_pid);
                        let pid = hex::encode(fake_pid);
                        let mut ciphertext = vec![0u8; 200];
                        rng.fill(&mut ciphertext[..]);
                        let mailbox_id = hex::encode(crypto::blake3::hash(pid.as_bytes()));
                        let sender_id = hex::encode(fake_pid);
                        let envelope = crate::engine::Envelope {
                            mailbox_id,
                            sender_id,
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            ciphertext,
                            pow_nonce: 0,
                        };

                        let mut blob = serde_json::to_vec(&envelope).unwrap_or_default();
                        blob = crate::engine::pad_envelope(blob);
                        let msg_id = hex::encode(crypto::blake3::hash(&blob));
                        let (client_to_use, transport_receiver, payload, direct_fallback_used) =
                            match route_payload(
                                &relay,
                                onion_router.as_ref(),
                                mixnet_config,
                                &pid,
                                blob,
                                strict_anonymity,
                            ) {
                                Ok(v) => v,
                                Err(reason) => {
                                    if let Ok(g) = state_clone.lock() {
                                        if let Ok(mut stats) = g.traffic_stats.lock() {
                                            stats.send_failures += 1;
                                        }
                                    }
                                    record_route_policy_violation(&state_clone, &reason);
                                    continue;
                                }
                            };
                        record_route_fallback_usage(&state_clone, direct_fallback_used);
                        (msg_id, transport_receiver, payload, client_to_use)
                    };

                    let send_result = orchestrator::send_blob_with_retry(
                        &client_to_use,
                        &msg_id,
                        &transport_receiver,
                        &payload,
                        1,
                        Duration::from_millis(100),
                        Duration::from_secs(1),
                    )
                    .await;
                    if let Ok(g) = state_clone.lock() {
                        if let Ok(mut stats) = g.traffic_stats.lock() {
                            if send_result.is_ok() {
                                stats.cover_messages_sent += 1;
                            } else {
                                stats.send_failures += 1;
                            }
                        }
                    }
                }
            }
        }
    });
    0
}

fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn normalize_fixed_poll_interval(interval_ms: u64, strict_anonymity: bool) -> u64 {
    if interval_ms > 0 {
        return interval_ms;
    }
    if strict_anonymity {
        return secure_profile_fixed_poll_ms();
    }
    0
}

fn normalize_constant_rate_interval(interval_ms: u64, strict_anonymity: bool) -> u64 {
    if interval_ms > 0 {
        return interval_ms;
    }
    if strict_anonymity {
        return secure_profile_constant_rate_ms();
    }
    0
}

fn secure_profile_fixed_poll_ms() -> u64 {
    parse_u64_env("REDOOR_SECURE_FIXED_POLL_MS", DEFAULT_SECURE_FIXED_POLL_MS)
}

fn secure_profile_constant_rate_ms() -> u64 {
    parse_u64_env(
        "REDOOR_SECURE_CONSTANT_RATE_MS",
        DEFAULT_SECURE_CONSTANT_RATE_MS,
    )
}

fn secure_profile_jitter_pct() -> u64 {
    parse_u64_env("REDOOR_SECURE_JITTER_PCT", DEFAULT_SECURE_JITTER_PCT).min(MAX_SECURE_JITTER_PCT)
}

fn secure_profile_jitter_budget_ms() -> u64 {
    parse_u64_env(
        "REDOOR_SECURE_JITTER_BUDGET_MS",
        DEFAULT_SECURE_JITTER_BUDGET_MS,
    )
    .min(MAX_SECURE_JITTER_BUDGET_MS)
}

fn secure_profile_phase_offset_pct() -> u64 {
    parse_u64_env(
        "REDOOR_SECURE_PHASE_OFFSET_PCT",
        DEFAULT_SECURE_PHASE_OFFSET_PCT,
    )
    .min(MAX_SECURE_PHASE_OFFSET_PCT)
}

#[cfg(test)]
fn sample_phase_offset_ms(base_ms: u64, strict_anonymity: bool) -> u64 {
    let mut rng = rand::thread_rng();
    sample_phase_offset_ms_with_rng(base_ms, strict_anonymity, &mut rng)
}

fn sample_phase_offset_ms_with_rng<R: Rng + ?Sized>(
    base_ms: u64,
    strict_anonymity: bool,
    rng: &mut R,
) -> u64 {
    if base_ms == 0 || !strict_anonymity {
        return 0;
    }
    let phase_pct = secure_profile_phase_offset_pct();
    if phase_pct == 0 {
        return 0;
    }
    let max_offset = (base_ms.saturating_mul(phase_pct)) / 100;
    if max_offset == 0 {
        return 0;
    }
    rng.gen_range(0..=max_offset)
}

fn secure_profile_phase_window_ticks() -> u64 {
    parse_u64_env(
        "REDOOR_SECURE_PHASE_WINDOW_TICKS",
        DEFAULT_SECURE_PHASE_WINDOW_TICKS,
    )
    .min(MAX_SECURE_PHASE_WINDOW_TICKS)
}

fn secure_profile_phase_window_pct() -> u64 {
    parse_u64_env(
        "REDOOR_SECURE_PHASE_WINDOW_PCT",
        DEFAULT_SECURE_PHASE_WINDOW_PCT,
    )
    .min(MAX_SECURE_PHASE_WINDOW_PCT)
}

#[cfg(test)]
fn sample_phase_window_shift_ms(base_ms: u64, strict_anonymity: bool, tick_count: u64) -> u64 {
    let mut rng = rand::thread_rng();
    sample_phase_window_shift_ms_with_rng(base_ms, strict_anonymity, tick_count, &mut rng)
}

fn sample_phase_window_shift_ms_with_rng<R: Rng + ?Sized>(
    base_ms: u64,
    strict_anonymity: bool,
    tick_count: u64,
    rng: &mut R,
) -> u64 {
    if base_ms == 0 || !strict_anonymity || tick_count == 0 {
        return 0;
    }

    let window_ticks = secure_profile_phase_window_ticks();
    if window_ticks == 0 || !tick_count.is_multiple_of(window_ticks) {
        return 0;
    }

    let phase_window_pct = secure_profile_phase_window_pct();
    if phase_window_pct == 0 {
        return 0;
    }

    let max_shift = (base_ms.saturating_mul(phase_window_pct)) / 100;
    if max_shift == 0 {
        return 0;
    }

    rng.gen_range(0..=max_shift)
}

#[cfg(test)]
fn apply_bounded_jitter(base_ms: u64, jitter_pct: u64, jitter_budget_ms: u64) -> u64 {
    let mut rng = rand::thread_rng();
    apply_bounded_jitter_with_rng(base_ms, jitter_pct, jitter_budget_ms, &mut rng)
}

fn apply_bounded_jitter_with_rng<R: Rng + ?Sized>(
    base_ms: u64,
    jitter_pct: u64,
    jitter_budget_ms: u64,
    rng: &mut R,
) -> u64 {
    if base_ms == 0 || jitter_pct == 0 {
        return base_ms;
    }
    let max_delta = (base_ms.saturating_mul(jitter_pct)) / 100;
    let max_delta = max_delta.min(jitter_budget_ms);
    if max_delta == 0 {
        return base_ms;
    }
    let delta = rng.gen_range(0..=max_delta);
    if rng.gen_bool(0.5) {
        base_ms.saturating_add(delta)
    } else {
        base_ms.saturating_sub(delta)
    }
}

fn parse_u64_env(key: &str, default_value: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_value)
}

fn scheduler_seed_override() -> Option<u64> {
    std::env::var("REDOOR_SECURE_SCHEDULER_SEED")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
}

fn scheduler_rng_for_loop(base_ms: u64, strict_anonymity: bool, stream_tag: u64) -> StdRng {
    let seed = if let Some(override_seed) = scheduler_seed_override() {
        override_seed
    } else {
        rand::thread_rng().gen::<u64>()
    };
    let strict_tag = if strict_anonymity {
        0xA11C_0001_A11C_0001
    } else {
        0xA11C_0002_A11C_0002
    };
    StdRng::seed_from_u64(seed ^ strict_tag ^ stream_tag ^ base_ms.rotate_left(17))
}
