use crate::crypto;
use crate::engine::{ClientEngine, StoredMessage};
use crate::ratchet::double_ratchet::RatchetSession;
use crate::service;
#[cfg(feature = "pq")]
use pqcrypto_kyber::kyber1024;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Serialize)]
pub struct BenchResult {
    pub x25519_keygen_us: u128,
    pub x25519_dh_us: u128,
    pub ratchet_step_us: u128,
    #[cfg(feature = "pq")]
    pub kyber_encap_us: u128,
}

const POPULATED_MEMORY_BUDGET_BYTES: usize = 512 * 1024;
const POST_WIPE_MEMORY_BUDGET_BYTES: usize = 16 * 1024;
const POST_DURESS_MEMORY_BUDGET_BYTES: usize = 384 * 1024;
const MIN_RECLAIM_RATIO: f64 = 0.90;
const TRAFFIC_ANALYSIS_REPORT_VERSION: &str = "traffic_linkability.v1";
pub const TRAFFIC_ANALYSIS_DEFAULT_SEED: u64 = 0x7A11_1A71_5EED_0126;
const OBSERVER_MIN_LATENCY_MS: u64 = 120;
const OBSERVER_MAX_LATENCY_MS: u64 = 4_000;
const TRAFFIC_ANONYMITY_BASELINE_VERSION: &str = "traffic_linkability_baseline.v1";
const PHASE_SYNC_SAMPLE_CLIENTS: usize = 32;
const PHASE_SYNC_SAMPLE_TICKS: usize = 80;
const PHASE_SYNC_BASE_INTERVAL_MS: u64 = 1_000;
const PHASE_SYNC_EPSILON_MS: u64 = 20;
const PHASE_SYNC_JITTER_PCT: u64 = 5;
const PHASE_SYNC_OFFSET_PCT: u64 = 35;
const PHASE_SYNC_WINDOW_TICKS: usize = 16;
const PHASE_SYNC_WINDOW_PCT: u64 = 20;
const MIN_PHASE_SYNC_IMPROVEMENT: f64 = 0.10;

#[derive(Serialize, Clone, Debug, Default)]
pub struct StorageUsageSnapshot {
    pub message_store: usize,
    pub attachment_cache: usize,
    pub logs: usize,
    pub total: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct MemoryBudgetBenchmarkResult {
    pub populated_budget_bytes: usize,
    pub post_wipe_budget_bytes: usize,
    pub post_duress_budget_bytes: usize,
    pub min_reclaim_ratio: f64,
    pub baseline: StorageUsageSnapshot,
    pub populated: StorageUsageSnapshot,
    pub post_wipe: StorageUsageSnapshot,
    pub post_duress: StorageUsageSnapshot,
    pub reclaim_ratio: f64,
    pub checks_passed: bool,
    pub violations: Vec<String>,
}

pub fn run_crypto_benchmark() -> BenchResult {
    // Benchmark X25519 Keygen
    let start = Instant::now();
    for _ in 0..100 {
        let _ = crypto::x25519::generate_keypair();
    }
    let x25519_keygen = start.elapsed().as_micros() / 100;

    // Benchmark X25519 DH
    let (priv_a, _) = crypto::x25519::generate_keypair();
    let (_, pub_b) = crypto::x25519::generate_keypair();
    let start = Instant::now();
    for _ in 0..100 {
        let _ = crypto::x25519::diffie_hellman(&priv_a, &pub_b);
    }
    let x25519_dh = start.elapsed().as_micros() / 100;

    // Benchmark Ratchet Step (Encrypt)
    let shared = [0u8; 32];
    let mut session = RatchetSession::new(shared, None);
    let msg = b"benchmark message payload";
    let start = Instant::now();
    for _ in 0..100 {
        let _ = session.ratchet_encrypt(msg);
    }
    let ratchet_step = start.elapsed().as_micros() / 100;

    #[cfg(feature = "pq")]
    let kyber_encap = {
        let (pk, _) = kyber1024::keypair();
        let start = Instant::now();
        for _ in 0..100 {
            let _ = kyber1024::encapsulate(&pk);
        }
        start.elapsed().as_micros() / 100
    };

    #[cfg(not(feature = "pq"))]
    let kyber_encap = 0; // Placeholder if PQ disabled

    BenchResult {
        x25519_keygen_us: x25519_keygen,
        x25519_dh_us: x25519_dh,
        ratchet_step_us: ratchet_step,
        #[cfg(feature = "pq")]
        kyber_encap_us: kyber_encap,
    }
}

pub fn snapshot_storage_usage(engine: &ClientEngine) -> StorageUsageSnapshot {
    let guard = engine.state.lock().unwrap();

    let mut msg_store_size = 0usize;
    for msgs in guard.message_store.values() {
        for m in msgs {
            msg_store_size += m.content.len() + m.msg_type.len() + m.sender.len() + m.id.len();
        }
    }

    let mut attach_size = 0usize;
    for (k, v) in &guard.attachment_cache {
        attach_size += k.len() + v.len();
    }

    let mut log_size = 0usize;
    for l in &guard.log_buffer {
        log_size += l.len();
    }

    StorageUsageSnapshot {
        message_store: msg_store_size,
        attachment_cache: attach_size,
        logs: log_size,
        total: msg_store_size + attach_size + log_size,
    }
}

fn seed_memory_budget_fixture(engine: &ClientEngine) {
    let mut guard = engine.state.lock().unwrap();

    guard.message_store.clear();
    guard.attachment_cache.clear();
    guard.log_buffer.clear();

    for peer_idx in 0..6 {
        let peer_id = format!("peer-{peer_idx:02}");
        let mut msgs = Vec::with_capacity(80);
        for msg_idx in 0..80 {
            msgs.push(StoredMessage {
                id: format!("{peer_idx:02x}-{msg_idx:04x}"),
                timestamp: (peer_idx * 1000 + msg_idx) as u64,
                sender: peer_id.clone(),
                content: format!(
                    "fixture-memory-payload-{peer_idx:02}-{msg_idx:04}-{}",
                    "x".repeat(480)
                ),
                msg_type: "text".to_string(),
                group_id: None,
                read: false,
            });
        }
        guard.message_store.insert(peer_id, msgs);
    }

    for idx in 0..64 {
        guard
            .attachment_cache
            .insert(format!("attachment-{idx:03}"), vec![0xAB; 2048]);
    }

    for idx in 0..120 {
        guard
            .log_buffer
            .push_back(format!("memory-budget-log-{idx:03}-{}", "l".repeat(96)));
    }
}

pub fn run_memory_budget_benchmark() -> MemoryBudgetBenchmarkResult {
    let engine = ClientEngine::new();
    let baseline = snapshot_storage_usage(&engine);

    seed_memory_budget_fixture(&engine);
    let populated = snapshot_storage_usage(&engine);

    service::wipe_sensitive_state(&engine);
    let post_wipe = snapshot_storage_usage(&engine);

    service::enter_duress_mode(&engine);
    let post_duress = snapshot_storage_usage(&engine);

    let reclaim_ratio = if populated.total == 0 {
        0.0
    } else {
        (populated.total.saturating_sub(post_wipe.total)) as f64 / populated.total as f64
    };

    let mut violations = Vec::new();
    if populated.total == 0 {
        violations
            .push("Populated benchmark fixture did not increase memory footprint.".to_string());
    }
    if populated.total > POPULATED_MEMORY_BUDGET_BYTES {
        violations.push(format!(
            "Populated memory exceeded budget: {} > {} bytes.",
            populated.total, POPULATED_MEMORY_BUDGET_BYTES
        ));
    }
    if post_wipe.total > POST_WIPE_MEMORY_BUDGET_BYTES {
        violations.push(format!(
            "Post-wipe memory exceeded budget: {} > {} bytes.",
            post_wipe.total, POST_WIPE_MEMORY_BUDGET_BYTES
        ));
    }
    if post_duress.total > POST_DURESS_MEMORY_BUDGET_BYTES {
        violations.push(format!(
            "Post-duress memory exceeded budget: {} > {} bytes.",
            post_duress.total, POST_DURESS_MEMORY_BUDGET_BYTES
        ));
    }
    if post_wipe.total >= populated.total {
        violations.push("Wipe did not reduce populated memory footprint.".to_string());
    }
    if reclaim_ratio < MIN_RECLAIM_RATIO {
        violations.push(format!(
            "Wipe reclaim ratio below threshold: {:.3} < {:.3}.",
            reclaim_ratio, MIN_RECLAIM_RATIO
        ));
    }

    MemoryBudgetBenchmarkResult {
        populated_budget_bytes: POPULATED_MEMORY_BUDGET_BYTES,
        post_wipe_budget_bytes: POST_WIPE_MEMORY_BUDGET_BYTES,
        post_duress_budget_bytes: POST_DURESS_MEMORY_BUDGET_BYTES,
        min_reclaim_ratio: MIN_RECLAIM_RATIO,
        baseline,
        populated,
        post_wipe,
        post_duress,
        reclaim_ratio,
        checks_passed: violations.is_empty(),
        violations,
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TrafficScenario {
    Idle,
    Burst,
    MixedRealChaff,
    RelayChurn,
}

#[derive(Serialize, Clone, Debug)]
pub struct TrafficScenarioReport {
    pub scenario: TrafficScenario,
    pub metric_version: String,
    pub comparable_id: String,
    pub seed: u64,
    pub fixture_hash: String,
    pub total_real_messages: usize,
    pub delivered_real_messages: usize,
    pub dropped_real_messages: usize,
    pub total_chaff_messages: usize,
    pub observer_guesses: usize,
    pub correct_guesses: usize,
    pub unresolved_messages: usize,
    pub top1_linkability: f64,
    pub unresolved_rate: f64,
    pub mean_candidate_set_size: f64,
    pub estimated_anonymity_set_size: f64,
    pub relay_churn_events: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct TrafficAnalysisSimulationReport {
    pub report_version: String,
    pub base_seed: u64,
    pub assumptions: Vec<String>,
    pub limitations: Vec<String>,
    pub scenarios: Vec<TrafficScenarioReport>,
    pub phase_synchronization: PhaseSynchronizationReport,
    pub checks_passed: bool,
    pub violations: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PhaseSynchronizationReport {
    pub sample_clients: usize,
    pub sample_ticks: usize,
    pub base_interval_ms: u64,
    pub sync_epsilon_ms: u64,
    pub baseline_pair_sync_ratio: f64,
    pub hardened_pair_sync_ratio: f64,
    pub improvement_ratio: f64,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SimMessageKind {
    Real,
    Chaff,
}

#[derive(Serialize, Clone, Debug)]
struct SimTraceEvent {
    id: u64,
    sender_id: u8,
    receiver_id: u8,
    send_ts_ms: u64,
    delivery_ts_ms: Option<u64>,
    kind: SimMessageKind,
    route_churned: bool,
}

#[derive(Clone, Copy)]
struct ScenarioConfig {
    real_messages: usize,
    chaff_messages: usize,
    send_interval_ms: u64,
    base_latency_ms: u64,
    latency_jitter_ms: u64,
    churn_events: usize,
    churn_penalty_ms: u64,
    churn_drop_rate_per_thousand: u16,
}

#[derive(Clone, Copy)]
struct ChurnWindow {
    start_ms: u64,
    end_ms: u64,
}

fn scenario_label(scenario: TrafficScenario) -> &'static str {
    match scenario {
        TrafficScenario::Idle => "idle",
        TrafficScenario::Burst => "burst",
        TrafficScenario::MixedRealChaff => "mixed_real_chaff",
        TrafficScenario::RelayChurn => "relay_churn",
    }
}

fn scenario_config(scenario: TrafficScenario) -> ScenarioConfig {
    match scenario {
        TrafficScenario::Idle => ScenarioConfig {
            real_messages: 18,
            chaff_messages: 2,
            send_interval_ms: 2_600,
            base_latency_ms: 720,
            latency_jitter_ms: 60,
            churn_events: 0,
            churn_penalty_ms: 0,
            churn_drop_rate_per_thousand: 0,
        },
        TrafficScenario::Burst => ScenarioConfig {
            real_messages: 72,
            chaff_messages: 8,
            send_interval_ms: 150,
            base_latency_ms: 700,
            latency_jitter_ms: 90,
            churn_events: 0,
            churn_penalty_ms: 0,
            churn_drop_rate_per_thousand: 0,
        },
        TrafficScenario::MixedRealChaff => ScenarioConfig {
            real_messages: 48,
            chaff_messages: 72,
            send_interval_ms: 280,
            base_latency_ms: 760,
            latency_jitter_ms: 240,
            churn_events: 0,
            churn_penalty_ms: 0,
            churn_drop_rate_per_thousand: 0,
        },
        TrafficScenario::RelayChurn => ScenarioConfig {
            real_messages: 56,
            chaff_messages: 40,
            send_interval_ms: 320,
            base_latency_ms: 820,
            latency_jitter_ms: 280,
            churn_events: 10,
            churn_penalty_ms: 500,
            churn_drop_rate_per_thousand: 160,
        },
    }
}

fn scenario_seed(base_seed: u64, scenario: TrafficScenario) -> u64 {
    let offset = match scenario {
        TrafficScenario::Idle => 0xA11CE,
        TrafficScenario::Burst => 0xB0A57,
        TrafficScenario::MixedRealChaff => 0xC0FEBABE,
        TrafficScenario::RelayChurn => 0xD15EA5E,
    };
    base_seed ^ offset
}

fn build_churn_windows(
    config: ScenarioConfig,
    timeline_ms: u64,
    rng: &mut StdRng,
) -> Vec<ChurnWindow> {
    let mut windows = Vec::with_capacity(config.churn_events);
    for _ in 0..config.churn_events {
        let start_ms = rng.gen_range(0..=timeline_ms.saturating_add(config.send_interval_ms));
        let duration_ms = rng.gen_range(220..=920);
        windows.push(ChurnWindow {
            start_ms,
            end_ms: start_ms.saturating_add(duration_ms),
        });
    }
    windows
}

fn is_churned(send_ts_ms: u64, churn_windows: &[ChurnWindow]) -> bool {
    churn_windows
        .iter()
        .any(|window| send_ts_ms >= window.start_ms && send_ts_ms <= window.end_ms)
}

fn generate_scenario_trace(scenario: TrafficScenario, seed: u64) -> (Vec<SimTraceEvent>, usize) {
    let config = scenario_config(scenario);
    let mut rng = StdRng::seed_from_u64(seed);
    let sender_count = 8u8;
    let receiver_count = 8u8;
    let timeline_ms = (config.real_messages as u64 + 4).saturating_mul(config.send_interval_ms);
    let churn_windows = build_churn_windows(config, timeline_ms, &mut rng);

    let mut events = Vec::with_capacity(config.real_messages + config.chaff_messages);
    let mut next_id = 1u64;

    for idx in 0..config.real_messages {
        let send_ts_ms =
            idx as u64 * config.send_interval_ms + rng.gen_range(0..=config.latency_jitter_ms);
        let sender_id = rng.gen_range(0..sender_count);
        let receiver_id = rng.gen_range(0..receiver_count);
        let churned = is_churned(send_ts_ms, &churn_windows);
        let mut latency_ms = config.base_latency_ms + rng.gen_range(0..=config.latency_jitter_ms);
        if churned {
            latency_ms = latency_ms
                .saturating_add(config.churn_penalty_ms)
                .saturating_add(rng.gen_range(0..=config.churn_penalty_ms / 2));
        }
        let dropped =
            churned && rng.gen_range(0..1000) < usize::from(config.churn_drop_rate_per_thousand);
        let delivery_ts_ms = if dropped {
            None
        } else {
            Some(send_ts_ms.saturating_add(latency_ms))
        };
        events.push(SimTraceEvent {
            id: next_id,
            sender_id,
            receiver_id,
            send_ts_ms,
            delivery_ts_ms,
            kind: SimMessageKind::Real,
            route_churned: churned,
        });
        next_id = next_id.saturating_add(1);
    }

    for _ in 0..config.chaff_messages {
        let send_ts_ms = rng.gen_range(0..=timeline_ms);
        let sender_id = rng.gen_range(0..sender_count);
        let receiver_id = rng.gen_range(0..receiver_count);
        let churned = is_churned(send_ts_ms, &churn_windows);
        let mut latency_ms =
            config.base_latency_ms + rng.gen_range(0..=config.latency_jitter_ms * 2);
        if churned {
            latency_ms = latency_ms
                .saturating_add(config.churn_penalty_ms / 2)
                .saturating_add(rng.gen_range(0..=config.churn_penalty_ms / 2));
        }
        let dropped = churned
            && rng.gen_range(0..1000) < usize::from(config.churn_drop_rate_per_thousand / 2);
        let delivery_ts_ms = if dropped {
            None
        } else {
            Some(send_ts_ms.saturating_add(latency_ms))
        };
        events.push(SimTraceEvent {
            id: next_id,
            sender_id,
            receiver_id,
            send_ts_ms,
            delivery_ts_ms,
            kind: SimMessageKind::Chaff,
            route_churned: churned,
        });
        next_id = next_id.saturating_add(1);
    }

    (events, churn_windows.len())
}

fn fixture_hash(events: &[SimTraceEvent]) -> String {
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|event| (event.send_ts_ms, event.id));
    let encoded = serde_json::to_vec(&ordered).unwrap_or_default();
    hex::encode(crypto::blake3::hash(&encoded))
}

#[derive(Clone)]
struct IngressObservation {
    receiver_id: u8,
    delivery_ts_ms: u64,
}

fn evaluate_scenario(
    scenario: TrafficScenario,
    seed: u64,
    events: &[SimTraceEvent],
    churn_events: usize,
) -> TrafficScenarioReport {
    let total_real_messages = events
        .iter()
        .filter(|event| event.kind == SimMessageKind::Real)
        .count();
    let total_chaff_messages = events
        .iter()
        .filter(|event| event.kind == SimMessageKind::Chaff)
        .count();

    let mut delivered_latencies = Vec::new();
    let mut ingress = Vec::new();
    let mut delivered_reals = Vec::new();
    for event in events {
        if let Some(delivery_ts_ms) = event.delivery_ts_ms {
            delivered_latencies.push(delivery_ts_ms.saturating_sub(event.send_ts_ms));
            ingress.push(IngressObservation {
                receiver_id: event.receiver_id,
                delivery_ts_ms,
            });
            if event.kind == SimMessageKind::Real {
                delivered_reals.push(event);
            }
        }
    }

    ingress.sort_by_key(|event| event.delivery_ts_ms);
    delivered_reals.sort_by_key(|event| event.send_ts_ms);

    delivered_latencies.sort_unstable();
    let expected_latency_ms = if delivered_latencies.is_empty() {
        900
    } else {
        delivered_latencies[delivered_latencies.len() / 2]
    };

    let mut used_ingress = vec![false; ingress.len()];
    let mut observer_guesses = 0usize;
    let mut correct_guesses = 0usize;
    let mut unresolved_messages = 0usize;
    let mut candidate_set_size_sum = 0.0f64;

    for real_event in &delivered_reals {
        let mut candidates = Vec::new();
        let mut receiver_candidates = HashSet::new();

        for (idx, observed) in ingress.iter().enumerate() {
            if used_ingress[idx] || observed.delivery_ts_ms < real_event.send_ts_ms {
                continue;
            }
            let delta_ms = observed
                .delivery_ts_ms
                .saturating_sub(real_event.send_ts_ms);
            if !(OBSERVER_MIN_LATENCY_MS..=OBSERVER_MAX_LATENCY_MS).contains(&delta_ms) {
                continue;
            }
            receiver_candidates.insert(observed.receiver_id);
            candidates.push((idx, delta_ms, delta_ms.abs_diff(expected_latency_ms)));
        }

        candidate_set_size_sum += receiver_candidates.len() as f64;
        if candidates.is_empty() {
            unresolved_messages = unresolved_messages.saturating_add(1);
            continue;
        }

        candidates.sort_by_key(|(_, delta_ms, score)| (*score, *delta_ms));
        let selected_idx = candidates[0].0;
        used_ingress[selected_idx] = true;
        observer_guesses = observer_guesses.saturating_add(1);

        if ingress[selected_idx].receiver_id == real_event.receiver_id {
            correct_guesses = correct_guesses.saturating_add(1);
        }
    }

    let delivered_real_messages = delivered_reals.len();
    let dropped_real_messages = total_real_messages.saturating_sub(delivered_real_messages);
    let denom = delivered_real_messages.max(1) as f64;
    let top1_linkability = correct_guesses as f64 / denom;
    let unresolved_rate = unresolved_messages as f64 / denom;
    let mean_candidate_set_size = candidate_set_size_sum / denom;
    let estimated_anonymity_set_size = mean_candidate_set_size.max(1.0);

    TrafficScenarioReport {
        scenario,
        metric_version: TRAFFIC_ANALYSIS_REPORT_VERSION.to_string(),
        comparable_id: format!(
            "{}:{}:{:016x}",
            TRAFFIC_ANALYSIS_REPORT_VERSION,
            scenario_label(scenario),
            seed
        ),
        seed,
        fixture_hash: fixture_hash(events),
        total_real_messages,
        delivered_real_messages,
        dropped_real_messages,
        total_chaff_messages,
        observer_guesses,
        correct_guesses,
        unresolved_messages,
        top1_linkability,
        unresolved_rate,
        mean_candidate_set_size,
        estimated_anonymity_set_size,
        relay_churn_events: churn_events,
    }
}

fn compute_pair_sync_ratio(schedule: &[Vec<u64>], epsilon_ms: u64) -> f64 {
    let clients = schedule.len();
    if clients < 2 {
        return 0.0;
    }
    let ticks = schedule.first().map(|samples| samples.len()).unwrap_or(0);
    if ticks == 0 {
        return 0.0;
    }

    let pairs_per_tick = clients.saturating_mul(clients.saturating_sub(1)) / 2;
    let total_pairs = pairs_per_tick.saturating_mul(ticks);
    if total_pairs == 0 {
        return 0.0;
    }

    let mut synced_pairs = 0usize;
    for (tick_idx, _) in schedule[0].iter().enumerate().take(ticks) {
        for (left_idx, left_client) in schedule.iter().enumerate() {
            let left = left_client[tick_idx];
            for right_client in schedule.iter().skip(left_idx + 1) {
                let right = right_client[tick_idx];
                if left.abs_diff(right) <= epsilon_ms {
                    synced_pairs = synced_pairs.saturating_add(1);
                }
            }
        }
    }

    synced_pairs as f64 / total_pairs as f64
}

fn simulate_phase_synchronization(seed: u64) -> PhaseSynchronizationReport {
    let clients = PHASE_SYNC_SAMPLE_CLIENTS;
    let ticks = PHASE_SYNC_SAMPLE_TICKS;
    let base_interval_ms = PHASE_SYNC_BASE_INTERVAL_MS;
    let sync_epsilon_ms = PHASE_SYNC_EPSILON_MS;

    let mut baseline = vec![vec![0u64; ticks]; clients];
    for client_ticks in &mut baseline {
        for (tick_idx, sample) in client_ticks.iter_mut().enumerate() {
            *sample = tick_idx as u64 * base_interval_ms;
        }
    }

    let mut rng = StdRng::seed_from_u64(seed ^ 0xC1A0_5EED_11A7_7E55);
    let max_initial_offset = (base_interval_ms.saturating_mul(PHASE_SYNC_OFFSET_PCT)) / 100;
    let max_jitter = (base_interval_ms.saturating_mul(PHASE_SYNC_JITTER_PCT)) / 100;
    let max_phase_window_shift = (base_interval_ms.saturating_mul(PHASE_SYNC_WINDOW_PCT)) / 100;
    let mut hardened = vec![vec![0u64; ticks]; clients];

    for client_ticks in &mut hardened {
        let mut current = if max_initial_offset == 0 {
            0
        } else {
            rng.gen_range(0..=max_initial_offset)
        };
        for (tick_idx, sample) in client_ticks.iter_mut().enumerate() {
            if tick_idx > 0 && tick_idx % PHASE_SYNC_WINDOW_TICKS == 0 && max_phase_window_shift > 0
            {
                current = current.saturating_add(rng.gen_range(0..=max_phase_window_shift));
            }

            let delta = if max_jitter == 0 {
                0
            } else {
                rng.gen_range(0..=max_jitter)
            };
            let step = if rng.gen_bool(0.5) {
                base_interval_ms.saturating_add(delta)
            } else {
                base_interval_ms.saturating_sub(delta).max(1)
            };

            current = current.saturating_add(step);
            *sample = current;
        }
    }

    let baseline_pair_sync_ratio = compute_pair_sync_ratio(&baseline, sync_epsilon_ms);
    let hardened_pair_sync_ratio = compute_pair_sync_ratio(&hardened, sync_epsilon_ms);
    let improvement_ratio = (baseline_pair_sync_ratio - hardened_pair_sync_ratio).max(0.0);

    PhaseSynchronizationReport {
        sample_clients: clients,
        sample_ticks: ticks,
        base_interval_ms,
        sync_epsilon_ms,
        baseline_pair_sync_ratio,
        hardened_pair_sync_ratio,
        improvement_ratio,
    }
}

pub fn run_traffic_analysis_simulator(seed: u64) -> TrafficAnalysisSimulationReport {
    let scenarios = [
        TrafficScenario::Idle,
        TrafficScenario::Burst,
        TrafficScenario::MixedRealChaff,
        TrafficScenario::RelayChurn,
    ];
    let mut reports = Vec::with_capacity(scenarios.len());

    for scenario in scenarios {
        let scenario_seed = scenario_seed(seed, scenario);
        let (events, churn_events) = generate_scenario_trace(scenario, scenario_seed);
        reports.push(evaluate_scenario(
            scenario,
            scenario_seed,
            &events,
            churn_events,
        ));
    }

    let mut violations = Vec::new();
    if reports.len() != 4 {
        violations.push("Traffic simulator did not generate all required scenarios.".to_string());
    }

    let idle = reports.iter().find(|r| r.scenario == TrafficScenario::Idle);
    let burst = reports
        .iter()
        .find(|r| r.scenario == TrafficScenario::Burst);
    let mixed = reports
        .iter()
        .find(|r| r.scenario == TrafficScenario::MixedRealChaff);
    let churn = reports
        .iter()
        .find(|r| r.scenario == TrafficScenario::RelayChurn);

    if let (Some(mixed), Some(burst)) = (mixed, burst) {
        if mixed.top1_linkability >= burst.top1_linkability {
            violations.push(format!(
                "Mixed real/chaff scenario should reduce linkability vs burst ({:.3} >= {:.3}).",
                mixed.top1_linkability, burst.top1_linkability
            ));
        }
    } else {
        violations.push("Missing mixed or burst scenario metrics.".to_string());
    }

    if let (Some(churn), Some(idle)) = (churn, idle) {
        if churn.dropped_real_messages <= idle.dropped_real_messages {
            violations.push(format!(
                "Relay churn should increase dropped real messages vs idle ({} <= {}).",
                churn.dropped_real_messages, idle.dropped_real_messages
            ));
        }
        if churn.relay_churn_events == 0 {
            violations.push("Relay churn scenario generated zero churn windows.".to_string());
        }
    } else {
        violations.push("Missing relay churn or idle scenario metrics.".to_string());
    }

    for report in &reports {
        if report.metric_version != TRAFFIC_ANALYSIS_REPORT_VERSION {
            violations.push(format!(
                "Scenario {} has unexpected metric version {}.",
                scenario_label(report.scenario),
                report.metric_version
            ));
        }
    }

    let phase_synchronization = simulate_phase_synchronization(seed);
    if phase_synchronization.hardened_pair_sync_ratio
        >= phase_synchronization.baseline_pair_sync_ratio
    {
        violations.push(format!(
            "Phase randomization failed to reduce synchronization ratio ({:.4} >= {:.4}).",
            phase_synchronization.hardened_pair_sync_ratio,
            phase_synchronization.baseline_pair_sync_ratio
        ));
    }
    if phase_synchronization.improvement_ratio < MIN_PHASE_SYNC_IMPROVEMENT {
        violations.push(format!(
            "Phase synchronization improvement below threshold ({:.4} < {:.4}).",
            phase_synchronization.improvement_ratio, MIN_PHASE_SYNC_IMPROVEMENT
        ));
    }

    TrafficAnalysisSimulationReport {
        report_version: TRAFFIC_ANALYSIS_REPORT_VERSION.to_string(),
        base_seed: seed,
        assumptions: vec![
            "global passive observer can view sender egress and receiver ingress timing"
                .to_string(),
            "observer uses latency-window correlation and one-to-one assignment heuristic"
                .to_string(),
            "chaff packets are transport-indistinguishable from real packets".to_string(),
        ],
        limitations: vec![
            "does not model endpoint compromise or active packet injection".to_string(),
            "uses synthetic traffic and fixed topology, not internet-scale routing".to_string(),
            "single-heuristic baseline; advanced ML deanonymization is out of scope".to_string(),
        ],
        scenarios: reports,
        phase_synchronization,
        checks_passed: violations.is_empty(),
        violations,
    }
}

pub fn run_traffic_analysis_simulator_default() -> TrafficAnalysisSimulationReport {
    run_traffic_analysis_simulator(TRAFFIC_ANALYSIS_DEFAULT_SEED)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrafficScenarioThreshold {
    pub scenario: TrafficScenario,
    pub max_top1_linkability: f64,
    pub max_unresolved_rate: f64,
    pub min_estimated_anonymity_set_size: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrafficGlobalThresholds {
    pub baseline_weighted_top1_linkability: f64,
    pub max_weighted_top1_linkability: f64,
    pub max_weighted_top1_regression_delta: f64,
    pub max_total_unresolved_rate: f64,
    pub min_total_delivered_real_messages: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrafficAnonymityBaseline {
    pub baseline_version: String,
    pub metric_version: String,
    pub seed: u64,
    pub scenario_thresholds: Vec<TrafficScenarioThreshold>,
    pub global_thresholds: TrafficGlobalThresholds,
}

#[derive(Serialize, Clone, Debug)]
pub struct TrafficScenarioRegressionResult {
    pub scenario: TrafficScenario,
    pub top1_linkability: f64,
    pub unresolved_rate: f64,
    pub estimated_anonymity_set_size: f64,
    pub delivered_real_messages: usize,
    pub top1_within_threshold: bool,
    pub unresolved_within_threshold: bool,
    pub anonymity_set_within_threshold: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct TrafficAnonymityRegressionResult {
    pub baseline_version: String,
    pub metric_version: String,
    pub report_seed: u64,
    pub baseline_seed: u64,
    pub weighted_top1_linkability: f64,
    pub weighted_top1_regression_delta: f64,
    pub total_unresolved_rate: f64,
    pub total_delivered_real_messages: usize,
    pub checks_passed: bool,
    pub override_applied: bool,
    pub override_reason: Option<String>,
    pub scenario_results: Vec<TrafficScenarioRegressionResult>,
    pub violations: Vec<String>,
}

fn weighted_top1_linkability(reports: &[TrafficScenarioReport]) -> f64 {
    let delivered_total: usize = reports
        .iter()
        .map(|report| report.delivered_real_messages)
        .sum();
    if delivered_total == 0 {
        return 0.0;
    }
    let weighted_sum: f64 = reports
        .iter()
        .map(|report| report.top1_linkability * report.delivered_real_messages as f64)
        .sum();
    weighted_sum / delivered_total as f64
}

fn total_unresolved_rate(reports: &[TrafficScenarioReport]) -> f64 {
    let unresolved_total: usize = reports
        .iter()
        .map(|report| report.unresolved_messages)
        .sum();
    let delivered_total: usize = reports
        .iter()
        .map(|report| report.delivered_real_messages)
        .sum();
    if delivered_total == 0 {
        return 0.0;
    }
    unresolved_total as f64 / delivered_total as f64
}

pub fn suggest_traffic_anonymity_baseline(seed: u64) -> TrafficAnonymityBaseline {
    let report = run_traffic_analysis_simulator(seed);
    let weighted_top1 = weighted_top1_linkability(&report.scenarios);
    let unresolved_rate = total_unresolved_rate(&report.scenarios);
    let scenario_thresholds = report
        .scenarios
        .iter()
        .map(|scenario| TrafficScenarioThreshold {
            scenario: scenario.scenario,
            max_top1_linkability: (scenario.top1_linkability + 0.04).min(1.0),
            max_unresolved_rate: (scenario.unresolved_rate + 0.06).min(1.0),
            min_estimated_anonymity_set_size: (scenario.estimated_anonymity_set_size - 0.30)
                .max(1.0),
        })
        .collect();

    TrafficAnonymityBaseline {
        baseline_version: TRAFFIC_ANONYMITY_BASELINE_VERSION.to_string(),
        metric_version: TRAFFIC_ANALYSIS_REPORT_VERSION.to_string(),
        seed,
        scenario_thresholds,
        global_thresholds: TrafficGlobalThresholds {
            baseline_weighted_top1_linkability: weighted_top1,
            max_weighted_top1_linkability: (weighted_top1 + 0.03).min(1.0),
            max_weighted_top1_regression_delta: 0.02,
            max_total_unresolved_rate: (unresolved_rate + 0.03).min(1.0),
            min_total_delivered_real_messages: report
                .scenarios
                .iter()
                .map(|scenario| scenario.delivered_real_messages)
                .sum(),
        },
    }
}

pub fn evaluate_traffic_analysis_regression(
    report: &TrafficAnalysisSimulationReport,
    baseline: &TrafficAnonymityBaseline,
) -> TrafficAnonymityRegressionResult {
    let mut violations = Vec::new();
    let threshold_by_scenario: HashMap<TrafficScenario, &TrafficScenarioThreshold> = baseline
        .scenario_thresholds
        .iter()
        .map(|threshold| (threshold.scenario, threshold))
        .collect();

    let mut scenario_results = Vec::with_capacity(report.scenarios.len());
    for scenario_report in &report.scenarios {
        if scenario_report.metric_version != baseline.metric_version {
            violations.push(format!(
                "Scenario {} metric version mismatch: {} != {}.",
                scenario_label(scenario_report.scenario),
                scenario_report.metric_version,
                baseline.metric_version
            ));
        }

        if let Some(threshold) = threshold_by_scenario.get(&scenario_report.scenario) {
            let top1_within = scenario_report.top1_linkability <= threshold.max_top1_linkability;
            let unresolved_within =
                scenario_report.unresolved_rate <= threshold.max_unresolved_rate;
            let anonymity_within = scenario_report.estimated_anonymity_set_size
                >= threshold.min_estimated_anonymity_set_size;

            if !top1_within {
                violations.push(format!(
                    "{} top1 linkability {:.4} exceeds threshold {:.4}.",
                    scenario_label(scenario_report.scenario),
                    scenario_report.top1_linkability,
                    threshold.max_top1_linkability
                ));
            }
            if !unresolved_within {
                violations.push(format!(
                    "{} unresolved rate {:.4} exceeds threshold {:.4}.",
                    scenario_label(scenario_report.scenario),
                    scenario_report.unresolved_rate,
                    threshold.max_unresolved_rate
                ));
            }
            if !anonymity_within {
                violations.push(format!(
                    "{} anonymity set {:.4} below threshold {:.4}.",
                    scenario_label(scenario_report.scenario),
                    scenario_report.estimated_anonymity_set_size,
                    threshold.min_estimated_anonymity_set_size
                ));
            }

            scenario_results.push(TrafficScenarioRegressionResult {
                scenario: scenario_report.scenario,
                top1_linkability: scenario_report.top1_linkability,
                unresolved_rate: scenario_report.unresolved_rate,
                estimated_anonymity_set_size: scenario_report.estimated_anonymity_set_size,
                delivered_real_messages: scenario_report.delivered_real_messages,
                top1_within_threshold: top1_within,
                unresolved_within_threshold: unresolved_within,
                anonymity_set_within_threshold: anonymity_within,
            });
        } else {
            violations.push(format!(
                "No threshold configured for scenario {}.",
                scenario_label(scenario_report.scenario)
            ));
        }
    }

    if threshold_by_scenario.len() != scenario_results.len() {
        violations.push("Simulator report/scenario threshold coverage mismatch.".to_string());
    }

    let weighted_top1 = weighted_top1_linkability(&report.scenarios);
    let weighted_delta = weighted_top1
        - baseline
            .global_thresholds
            .baseline_weighted_top1_linkability;
    let unresolved_rate = total_unresolved_rate(&report.scenarios);
    let delivered_total: usize = report
        .scenarios
        .iter()
        .map(|scenario| scenario.delivered_real_messages)
        .sum();

    if report.report_version != baseline.metric_version {
        violations.push(format!(
            "Report version mismatch: {} != {}.",
            report.report_version, baseline.metric_version
        ));
    }
    if report.base_seed != baseline.seed {
        violations.push(format!(
            "Report seed mismatch: {} != {}.",
            report.base_seed, baseline.seed
        ));
    }
    if weighted_top1 > baseline.global_thresholds.max_weighted_top1_linkability {
        violations.push(format!(
            "Weighted top1 linkability {:.4} exceeds threshold {:.4}.",
            weighted_top1, baseline.global_thresholds.max_weighted_top1_linkability
        ));
    }
    if weighted_delta
        > baseline
            .global_thresholds
            .max_weighted_top1_regression_delta
    {
        violations.push(format!(
            "Weighted top1 regression delta {:.4} exceeds threshold {:.4}.",
            weighted_delta,
            baseline
                .global_thresholds
                .max_weighted_top1_regression_delta
        ));
    }
    if unresolved_rate > baseline.global_thresholds.max_total_unresolved_rate {
        violations.push(format!(
            "Total unresolved rate {:.4} exceeds threshold {:.4}.",
            unresolved_rate, baseline.global_thresholds.max_total_unresolved_rate
        ));
    }
    if delivered_total < baseline.global_thresholds.min_total_delivered_real_messages {
        violations.push(format!(
            "Delivered real-message sample too small: {} < {}.",
            delivered_total, baseline.global_thresholds.min_total_delivered_real_messages
        ));
    }

    TrafficAnonymityRegressionResult {
        baseline_version: baseline.baseline_version.clone(),
        metric_version: baseline.metric_version.clone(),
        report_seed: report.base_seed,
        baseline_seed: baseline.seed,
        weighted_top1_linkability: weighted_top1,
        weighted_top1_regression_delta: weighted_delta,
        total_unresolved_rate: unresolved_rate,
        total_delivered_real_messages: delivered_total,
        checks_passed: violations.is_empty(),
        override_applied: false,
        override_reason: None,
        scenario_results,
        violations,
    }
}

#[derive(Serialize)]
pub struct DiagnosticsReport {
    pub crypto_ok: bool,
    pub relay_configured: bool,
    pub blockchain_configured: bool,
    pub memory_hardening_active: bool,
    pub memory_hardening_required: bool,
    pub memory_hardening_ok: bool,
    pub memory_hardening_last_error: Option<String>,
    pub session_count: usize,
    pub one_time_prekeys: usize,
    pub prekey_low_watermark: usize,
    pub prekey_target_count: usize,
    pub prekey_depleted: bool,
    pub prekey_last_replenished_at: Option<u64>,
    pub signed_prekey_last_rotated_at: Option<u64>,
    pub signed_prekey_rotate_interval_secs: u64,
    pub signed_prekey_rotation_due: bool,
    pub onion_enabled: bool,
    pub route_policy_violations: u64,
    pub route_last_correlation_score: u32,
    pub route_last_concentration_risk_score: u32,
    pub route_last_concentration_operator_dominance_pct: u8,
    pub route_last_concentration_jurisdiction_dominance_pct: u8,
    pub route_last_concentration_asn_dominance_pct: u8,
    pub route_last_correlation_operator_overlap: usize,
    pub route_last_correlation_jurisdiction_overlap: usize,
    pub route_last_correlation_asn_overlap: usize,
    pub route_last_correlation_node_overlap: usize,
    pub route_last_correlation_exact_route_reuse: usize,
    pub route_last_correlation_temporal_reuse_penalty: usize,
    pub route_live_classification_active: bool,
    pub route_live_classification_entries: usize,
    pub route_reject_diversity_policy: u64,
    pub route_reject_correlation_threshold: u64,
    pub route_reject_concentration_threshold: u64,
    pub route_reject_empty_topology: u64,
    pub route_last_reject_reason: Option<String>,
    pub route_fallback_direct_used: u64,
    pub route_fallback_direct_blocked: u64,
    pub untrusted_parser_mode: String,
    pub untrusted_parser_class_allowlist: String,
    pub untrusted_parser_worker_launches: u64,
    pub untrusted_parser_worker_launch_failures: u64,
    pub untrusted_parser_worker_restarts: u64,
    pub untrusted_parser_worker_timeouts: u64,
    pub untrusted_parser_requests_total: u64,
    pub untrusted_parser_parse_denials: u64,
    pub untrusted_parser_io_failures: u64,
    pub untrusted_parser_protocol_mismatches: u64,
    pub untrusted_parser_last_error: Option<String>,
    pub rekey_active_sessions: usize,
    pub rekey_pending_sessions: usize,
    pub forced_rekeys_total: u64,
    pub forced_rekey_last_reason: Option<String>,
    pub protocol_version_current: u16,
    pub protocol_min_accepted_version: u16,
    pub forced_rekey_after_messages: u64,
    pub forced_rekey_after_secs: u64,
    pub pq_ratchet_interval_messages: u64,
    pub background_mode: i32,
    pub theme: String,
}

pub fn run_health_check(engine: &ClientEngine) -> DiagnosticsReport {
    let guard = engine.state.lock().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. Crypto Self-Test
    let crypto_ok = {
        let (priv_k, pub_k) = crypto::x25519::generate_keypair();
        let shared = crypto::x25519::diffie_hellman(&priv_k, &pub_k);
        // Basic sanity check: shared secret shouldn't be all zeros
        shared.iter().any(|&b| b != 0)
    };

    let one_time_prekeys = guard
        .prekey_secrets
        .as_ref()
        .map(|s| s.one_time_prekeys.len())
        .unwrap_or(0);
    let signed_prekey_rotation_due = match guard.signed_prekey_last_rotated_at {
        Some(last) => now.saturating_sub(last) >= guard.signed_prekey_rotate_interval_secs,
        None => true,
    };
    let (route_policy_violations, route_fallback_direct_used, route_fallback_direct_blocked) =
        guard
            .traffic_stats
            .lock()
            .map(|stats| {
                (
                    stats.route_policy_violations,
                    stats.route_fallback_direct_used,
                    stats.route_fallback_direct_blocked,
                )
            })
            .unwrap_or((0, 0, 0));
    let route_corr = guard
        .onion_router
        .as_ref()
        .map(|router| router.route_correlation_telemetry())
        .unwrap_or_default();

    let parser_boundary = engine.untrusted_parser_telemetry();
    let rekey_health = engine.rekey_health_telemetry();

    DiagnosticsReport {
        crypto_ok,
        relay_configured: guard.relay_client.is_some(),
        blockchain_configured: guard.blockchain_client.is_some(),
        memory_hardening_active: crate::config::memory_hardening_active(),
        memory_hardening_required: crate::config::memory_hardening_required(),
        memory_hardening_ok: crate::config::memory_hardening_active()
            || !crate::config::memory_hardening_required(),
        memory_hardening_last_error: crate::config::memory_hardening_last_error(),
        session_count: guard.sessions.len(),
        one_time_prekeys,
        prekey_low_watermark: guard.prekey_low_watermark,
        prekey_target_count: guard.prekey_target_count,
        prekey_depleted: one_time_prekeys < guard.prekey_low_watermark,
        prekey_last_replenished_at: guard.prekey_last_replenished_at,
        signed_prekey_last_rotated_at: guard.signed_prekey_last_rotated_at,
        signed_prekey_rotate_interval_secs: guard.signed_prekey_rotate_interval_secs,
        signed_prekey_rotation_due,
        onion_enabled: guard.onion_router.is_some(),
        route_policy_violations,
        route_last_correlation_score: route_corr.score,
        route_last_concentration_risk_score: route_corr.concentration_risk_score,
        route_last_concentration_operator_dominance_pct: route_corr
            .concentration_operator_dominance_pct,
        route_last_concentration_jurisdiction_dominance_pct: route_corr
            .concentration_jurisdiction_dominance_pct,
        route_last_concentration_asn_dominance_pct: route_corr.concentration_asn_dominance_pct,
        route_last_correlation_operator_overlap: route_corr.operator_overlap,
        route_last_correlation_jurisdiction_overlap: route_corr.jurisdiction_overlap,
        route_last_correlation_asn_overlap: route_corr.asn_overlap,
        route_last_correlation_node_overlap: route_corr.node_overlap,
        route_last_correlation_exact_route_reuse: route_corr.exact_route_reuse,
        route_last_correlation_temporal_reuse_penalty: route_corr.temporal_reuse_penalty,
        route_live_classification_active: route_corr.live_classification_active,
        route_live_classification_entries: route_corr.live_classification_entries,
        route_reject_diversity_policy: route_corr.reject_diversity_policy,
        route_reject_correlation_threshold: route_corr.reject_correlation_threshold,
        route_reject_concentration_threshold: route_corr.reject_concentration_threshold,
        route_reject_empty_topology: route_corr.reject_empty_topology,
        route_last_reject_reason: route_corr.last_reject_reason,
        route_fallback_direct_used,
        route_fallback_direct_blocked,
        untrusted_parser_mode: parser_boundary.mode,
        untrusted_parser_class_allowlist: parser_boundary.parser_class_allowlist,
        untrusted_parser_worker_launches: parser_boundary.worker_launches,
        untrusted_parser_worker_launch_failures: parser_boundary.worker_launch_failures,
        untrusted_parser_worker_restarts: parser_boundary.worker_restarts,
        untrusted_parser_worker_timeouts: parser_boundary.worker_timeouts,
        untrusted_parser_requests_total: parser_boundary.requests_total,
        untrusted_parser_parse_denials: parser_boundary.parse_denials,
        untrusted_parser_io_failures: parser_boundary.io_failures,
        untrusted_parser_protocol_mismatches: parser_boundary.protocol_mismatches,
        untrusted_parser_last_error: parser_boundary.last_error,
        rekey_active_sessions: rekey_health.active_sessions,
        rekey_pending_sessions: rekey_health.pending_sessions,
        forced_rekeys_total: rekey_health.forced_rekeys_total,
        forced_rekey_last_reason: rekey_health.last_forced_reason,
        protocol_version_current: rekey_health.protocol_version_current,
        protocol_min_accepted_version: rekey_health.protocol_min_accepted_version,
        forced_rekey_after_messages: rekey_health.forced_rekey_after_messages,
        forced_rekey_after_secs: rekey_health.forced_rekey_after_secs,
        pq_ratchet_interval_messages: rekey_health.pq_ratchet_interval_messages,
        background_mode: guard.background_config.mode,
        theme: guard.theme.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ClientEngine;

    #[test]
    fn test_crypto_benchmark() {
        let result = run_crypto_benchmark();
        assert!(result.x25519_keygen_us > 0);
        assert!(result.x25519_dh_us > 0);
        assert!(result.ratchet_step_us > 0);
    }

    #[test]
    fn test_health_check() {
        let engine = ClientEngine::new();
        let report = run_health_check(&engine);
        assert!(report.crypto_ok);
        assert!(report.memory_hardening_ok);
        assert_eq!(report.one_time_prekeys, 0);
        assert!(report.prekey_depleted);
        assert_eq!(report.route_last_correlation_score, 0);
    }

    #[test]
    fn test_health_check_reports_prekey_hygiene_state() {
        let engine = ClientEngine::new();
        engine.initialize_keys();

        let report = run_health_check(&engine);
        assert!(report.one_time_prekeys >= 1);
        assert!(report.signed_prekey_last_rotated_at.is_some());
        assert!(report.signed_prekey_rotate_interval_secs > 0);
    }

    #[test]
    fn test_storage_usage_snapshot_increases_with_fixture() {
        let engine = ClientEngine::new();
        let baseline = snapshot_storage_usage(&engine);

        seed_memory_budget_fixture(&engine);
        let populated = snapshot_storage_usage(&engine);

        assert!(populated.message_store > baseline.message_store);
        assert!(populated.attachment_cache > baseline.attachment_cache);
        assert!(populated.logs > baseline.logs);
        assert!(populated.total > baseline.total);
    }

    #[test]
    fn test_memory_budget_benchmark_regression_checks_pass() {
        let result = run_memory_budget_benchmark();
        assert!(
            result.checks_passed,
            "memory budget benchmark violations: {:?}",
            result.violations
        );
        assert!(result.populated.total > result.post_wipe.total);
        assert!(result.reclaim_ratio >= result.min_reclaim_ratio);
    }

    #[test]
    fn test_traffic_analysis_simulator_is_deterministic() {
        let report_a = run_traffic_analysis_simulator(42);
        let report_b = run_traffic_analysis_simulator(42);
        let encoded_a = serde_json::to_string(&report_a).expect("encode simulator report a");
        let encoded_b = serde_json::to_string(&report_b).expect("encode simulator report b");
        assert_eq!(encoded_a, encoded_b);
    }

    #[test]
    fn test_traffic_analysis_simulator_covers_required_scenarios() {
        let report = run_traffic_analysis_simulator_default();
        assert_eq!(report.scenarios.len(), 4);
        assert!(report.checks_passed, "violations: {:?}", report.violations);

        let mut seen = std::collections::HashSet::new();
        for scenario in &report.scenarios {
            seen.insert(scenario.scenario);
            assert_eq!(scenario.metric_version, TRAFFIC_ANALYSIS_REPORT_VERSION);
            assert!(!scenario.fixture_hash.is_empty());
            assert!(
                scenario
                    .comparable_id
                    .contains(scenario_label(scenario.scenario)),
                "comparable id should include scenario label"
            );
        }

        assert!(seen.contains(&TrafficScenario::Idle));
        assert!(seen.contains(&TrafficScenario::Burst));
        assert!(seen.contains(&TrafficScenario::MixedRealChaff));
        assert!(seen.contains(&TrafficScenario::RelayChurn));
    }

    #[test]
    fn test_traffic_analysis_simulator_regression_expectations_hold() {
        let report = run_traffic_analysis_simulator_default();

        let idle = report
            .scenarios
            .iter()
            .find(|scenario| scenario.scenario == TrafficScenario::Idle)
            .expect("idle scenario present");
        let burst = report
            .scenarios
            .iter()
            .find(|scenario| scenario.scenario == TrafficScenario::Burst)
            .expect("burst scenario present");
        let mixed = report
            .scenarios
            .iter()
            .find(|scenario| scenario.scenario == TrafficScenario::MixedRealChaff)
            .expect("mixed scenario present");
        let churn = report
            .scenarios
            .iter()
            .find(|scenario| scenario.scenario == TrafficScenario::RelayChurn)
            .expect("churn scenario present");

        assert!(mixed.top1_linkability < burst.top1_linkability);
        assert!(mixed.mean_candidate_set_size > idle.mean_candidate_set_size);
        assert!(churn.dropped_real_messages > idle.dropped_real_messages);
        assert!(churn.relay_churn_events > 0);
        assert!(
            report.phase_synchronization.hardened_pair_sync_ratio
                < report.phase_synchronization.baseline_pair_sync_ratio
        );
        assert!(
            report.phase_synchronization.improvement_ratio >= MIN_PHASE_SYNC_IMPROVEMENT,
            "phase improvement too small: {:.4}",
            report.phase_synchronization.improvement_ratio
        );
    }

    #[test]
    fn test_phase_synchronization_simulator_reduces_alignment() {
        let phase = simulate_phase_synchronization(TRAFFIC_ANALYSIS_DEFAULT_SEED);
        assert!(phase.baseline_pair_sync_ratio > 0.99);
        assert!(phase.hardened_pair_sync_ratio < phase.baseline_pair_sync_ratio);
        assert!(phase.improvement_ratio >= MIN_PHASE_SYNC_IMPROVEMENT);
    }

    #[test]
    fn test_traffic_analysis_regression_passes_against_suggested_baseline() {
        let seed = TRAFFIC_ANALYSIS_DEFAULT_SEED;
        let baseline = suggest_traffic_anonymity_baseline(seed);
        let report = run_traffic_analysis_simulator(seed);
        let evaluation = evaluate_traffic_analysis_regression(&report, &baseline);
        assert!(evaluation.checks_passed, "{:?}", evaluation.violations);
        assert!(evaluation.weighted_top1_regression_delta.abs() < 0.000_001);
    }

    #[test]
    fn test_traffic_analysis_regression_detects_top1_degradation() {
        let seed = TRAFFIC_ANALYSIS_DEFAULT_SEED;
        let baseline = suggest_traffic_anonymity_baseline(seed);
        let mut report = run_traffic_analysis_simulator(seed);

        let burst = report
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.scenario == TrafficScenario::Burst)
            .expect("burst scenario present");
        burst.top1_linkability = (burst.top1_linkability + 0.35).min(1.0);

        let evaluation = evaluate_traffic_analysis_regression(&report, &baseline);
        assert!(!evaluation.checks_passed);
        assert!(
            evaluation
                .violations
                .iter()
                .any(|violation| violation.contains("top1 linkability")),
            "expected top1 threshold violation"
        );
    }
}
