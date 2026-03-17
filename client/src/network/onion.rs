use crate::crypto::chacha20poly1305;
use crate::crypto::x25519;
use anyhow::{anyhow, Context, Result};
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use x25519_dalek::PublicKey;

const MIX_PACKET_MAGIC: &[u8; 4] = b"MXP1";
const MIX_PACKET_TAG_LEN: usize = 16;
const MIX_PACKET_HEADER_LEN: usize = 4 + MIX_PACKET_TAG_LEN + 32 + 12;
const ROUTE_CORRELATION_MEMORY_LIMIT: usize = 16;
const CORRELATION_OPERATOR_WEIGHT: u32 = 12;
const CORRELATION_JURISDICTION_WEIGHT: u32 = 12;
const CORRELATION_ASN_WEIGHT: u32 = 18;
const CORRELATION_NODE_WEIGHT: u32 = 6;
const CORRELATION_EXACT_ROUTE_WEIGHT: u32 = 42;
const CORRELATION_TEMPORAL_REUSE_WEIGHT: u32 = 8;
const CORRELATION_CONCENTRATION_WEIGHT: u32 = 3;

const MIXNET_CLASSIFICATION_ENV: &str = "REDOOR_MIXNET_CLASSIFICATION_JSON";

#[derive(Clone, Copy, Debug)]
pub struct MixnetConfig {
    pub min_hops: usize,
    pub max_hops: usize,
    pub min_unique_operators: usize,
    pub min_unique_jurisdictions: usize,
    pub min_unique_asns: usize,
    pub route_attempts: usize,
}

impl Default for MixnetConfig {
    fn default() -> Self {
        Self {
            min_hops: 0,
            max_hops: 0,
            min_unique_operators: 1,
            min_unique_jurisdictions: 1,
            min_unique_asns: 1,
            route_attempts: 16,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
struct SphinxHopPayload {
    v: u8,
    mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_hop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_hop_pub_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    final_receiver: Option<String>,
    payload: Vec<u8>,
}

#[derive(Clone)]
pub struct MixNode {
    pub url: String,
    pub pub_key: PublicKey,
    pub operator_tag: String,
    pub jurisdiction_tag: String,
    pub asn_tag: String,
}

impl MixNode {
    pub fn new(url: String, pub_key: PublicKey) -> Self {
        let fallback = default_node_tag_from_url(&url);
        Self {
            url,
            pub_key,
            operator_tag: fallback.clone(),
            jurisdiction_tag: "unknown".to_string(),
            asn_tag: "unknown".to_string(),
        }
    }

    pub fn with_tags(
        url: String,
        pub_key: PublicKey,
        operator_tag: Option<String>,
        jurisdiction_tag: Option<String>,
    ) -> Self {
        Self::with_extended_tags(url, pub_key, operator_tag, jurisdiction_tag, None)
    }

    pub fn with_extended_tags(
        url: String,
        pub_key: PublicKey,
        operator_tag: Option<String>,
        jurisdiction_tag: Option<String>,
        asn_tag: Option<String>,
    ) -> Self {
        let fallback = default_node_tag_from_url(&url);
        Self {
            url,
            pub_key,
            operator_tag: sanitize_tag(operator_tag.as_deref(), &fallback),
            jurisdiction_tag: sanitize_tag(jurisdiction_tag.as_deref(), "unknown"),
            asn_tag: sanitize_tag(asn_tag.as_deref(), "unknown"),
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct OnionRouter {
    // List of available relays with diversity metadata.
    nodes: Vec<MixNode>,
    correlation_memory: Arc<Mutex<RouteCorrelationMemory>>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RouteCorrelationTelemetry {
    pub score: u32,
    pub concentration_risk_score: u32,
    pub concentration_operator_dominance_pct: u8,
    pub concentration_jurisdiction_dominance_pct: u8,
    pub concentration_asn_dominance_pct: u8,
    pub operator_overlap: usize,
    pub jurisdiction_overlap: usize,
    pub asn_overlap: usize,
    pub node_overlap: usize,
    pub exact_route_reuse: usize,
    pub temporal_reuse_penalty: usize,
    pub live_classification_active: bool,
    pub live_classification_entries: usize,
    pub reject_diversity_policy: u64,
    pub reject_correlation_threshold: u64,
    pub reject_concentration_threshold: u64,
    pub reject_empty_topology: u64,
    pub last_reject_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct RouteCorrelationMemory {
    recent: VecDeque<RouteFingerprint>,
    last: RouteCorrelationTelemetry,
    reject_diversity_policy: u64,
    reject_correlation_threshold: u64,
    reject_concentration_threshold: u64,
    reject_empty_topology: u64,
    last_reject_reason: Option<String>,
}

#[derive(Clone, Debug)]
struct RouteFingerprint {
    node_sequence: Vec<String>,
    node_set: HashSet<String>,
    operators: HashSet<String>,
    jurisdictions: HashSet<String>,
    asns: HashSet<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct RouteCorrelationScore {
    score: u32,
    concentration_risk_score: u32,
    concentration_operator_dominance_pct: u8,
    concentration_jurisdiction_dominance_pct: u8,
    concentration_asn_dominance_pct: u8,
    operator_overlap: usize,
    jurisdiction_overlap: usize,
    asn_overlap: usize,
    node_overlap: usize,
    exact_route_reuse: usize,
    temporal_reuse_penalty: usize,
}

#[derive(Clone, Copy, Debug)]
enum RouteRejectReason {
    DiversityPolicy,
    CorrelationThreshold,
    ConcentrationThreshold,
    EmptyTopology,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LiveNodeClassification {
    #[serde(default)]
    operator_tag: Option<String>,
    #[serde(default)]
    jurisdiction_tag: Option<String>,
    #[serde(default)]
    asn_tag: Option<String>,
}

type LiveClassificationMap = HashMap<String, LiveNodeClassification>;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct RouteAdversarySimulationReport {
    pub report_version: &'static str,
    pub seed: u64,
    pub rounds: u32,
    pub selected_avg_score: f64,
    pub random_avg_score: f64,
    pub selected_partial_collusion_rate: f64,
    pub random_partial_collusion_rate: f64,
    pub selected_exact_reuse_rate: f64,
    pub random_exact_reuse_rate: f64,
}

impl OnionRouter {
    #[allow(dead_code)]
    pub fn new(nodes: Vec<(String, PublicKey)>) -> Self {
        let tagged = nodes
            .into_iter()
            .map(|(url, pub_key)| MixNode::new(url, pub_key))
            .collect();
        Self {
            nodes: tagged,
            correlation_memory: Arc::new(Mutex::new(RouteCorrelationMemory::default())),
        }
    }

    pub fn new_tagged(nodes: Vec<MixNode>) -> Self {
        Self {
            nodes,
            correlation_memory: Arc::new(Mutex::new(RouteCorrelationMemory::default())),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn route_correlation_telemetry(&self) -> RouteCorrelationTelemetry {
        self.correlation_memory
            .lock()
            .map(|state| {
                let mut telemetry = state.last.clone();
                telemetry.reject_diversity_policy = state.reject_diversity_policy;
                telemetry.reject_correlation_threshold = state.reject_correlation_threshold;
                telemetry.reject_concentration_threshold = state.reject_concentration_threshold;
                telemetry.reject_empty_topology = state.reject_empty_topology;
                telemetry.last_reject_reason = state.last_reject_reason.clone();
                telemetry
            })
            .unwrap_or_default()
    }

    fn diversity_satisfied_with_overrides(
        &self,
        selected_indices: &[usize],
        config: MixnetConfig,
        overrides: Option<&LiveClassificationMap>,
    ) -> bool {
        let min_ops = config.min_unique_operators.max(1);
        let min_jur = config.min_unique_jurisdictions.max(1);
        let min_asn = config.min_unique_asns.max(1);
        if min_ops <= 1 && min_jur <= 1 && min_asn <= 1 {
            return true;
        }

        let mut ops = HashSet::new();
        let mut jur = HashSet::new();
        let mut asns = HashSet::new();
        for idx in selected_indices {
            if let Some(node) = self.nodes.get(*idx) {
                let tags = effective_tags(node, overrides);
                ops.insert(tags.operator_tag);
                jur.insert(tags.jurisdiction_tag);
                asns.insert(tags.asn_tag);
            }
        }

        ops.len() >= min_ops && jur.len() >= min_jur && asns.len() >= min_asn
    }

    fn diversity_satisfied(&self, selected_indices: &[usize], config: MixnetConfig) -> bool {
        self.diversity_satisfied_with_overrides(selected_indices, config, None)
    }

    fn build_route_fingerprint(
        &self,
        selected_indices: &[usize],
        overrides: Option<&LiveClassificationMap>,
    ) -> Option<RouteFingerprint> {
        let mut node_sequence = Vec::with_capacity(selected_indices.len());
        let mut node_set = HashSet::new();
        let mut operators = HashSet::new();
        let mut jurisdictions = HashSet::new();
        let mut asns = HashSet::new();

        for idx in selected_indices {
            let node = self.nodes.get(*idx)?;
            let tags = effective_tags(node, overrides);
            node_sequence.push(node.url.clone());
            node_set.insert(node.url.clone());
            operators.insert(tags.operator_tag);
            jurisdictions.insert(tags.jurisdiction_tag);
            asns.insert(tags.asn_tag);
        }

        Some(RouteFingerprint {
            node_sequence,
            node_set,
            operators,
            jurisdictions,
            asns,
        })
    }

    fn overlap_size(left: &HashSet<String>, right: &HashSet<String>) -> usize {
        if left.len() <= right.len() {
            left.iter().filter(|item| right.contains(*item)).count()
        } else {
            right.iter().filter(|item| left.contains(*item)).count()
        }
    }

    fn concentration_metrics_for_indices(
        &self,
        selected_indices: &[usize],
        overrides: Option<&LiveClassificationMap>,
    ) -> ConcentrationMetrics {
        if selected_indices.is_empty() {
            return ConcentrationMetrics::default();
        }

        let mut operator_counts: HashMap<String, usize> = HashMap::new();
        let mut jurisdiction_counts: HashMap<String, usize> = HashMap::new();
        let mut asn_counts: HashMap<String, usize> = HashMap::new();

        for idx in selected_indices {
            if let Some(node) = self.nodes.get(*idx) {
                let tags = effective_tags(node, overrides);
                *operator_counts.entry(tags.operator_tag).or_insert(0) += 1;
                *jurisdiction_counts.entry(tags.jurisdiction_tag).or_insert(0) += 1;
                *asn_counts.entry(tags.asn_tag).or_insert(0) += 1;
            }
        }

        let hop_count = selected_indices.len();
        let max_operator_bucket = operator_counts.values().copied().max().unwrap_or(0);
        let max_jurisdiction_bucket = jurisdiction_counts.values().copied().max().unwrap_or(0);
        let max_asn_bucket = asn_counts.values().copied().max().unwrap_or(0);

        let operator_dominance_pct = max_share_pct(hop_count, max_operator_bucket);
        let jurisdiction_dominance_pct = max_share_pct(hop_count, max_jurisdiction_bucket);
        let asn_dominance_pct = max_share_pct(hop_count, max_asn_bucket);

        let risk_score = (operator_dominance_pct as u32)
            .saturating_add(jurisdiction_dominance_pct as u32)
            .saturating_add((asn_dominance_pct as u32).saturating_mul(2));

        ConcentrationMetrics {
            risk_score,
            operator_dominance_pct,
            jurisdiction_dominance_pct,
            asn_dominance_pct,
        }
    }

    fn score_candidate_against_recent(
        &self,
        selected_indices: &[usize],
        recent: &VecDeque<RouteFingerprint>,
        overrides: Option<&LiveClassificationMap>,
    ) -> RouteCorrelationScore {
        let Some(candidate) = self.build_route_fingerprint(selected_indices, overrides) else {
            return RouteCorrelationScore::default();
        };

        let mut operator_overlap = 0usize;
        let mut jurisdiction_overlap = 0usize;
        let mut asn_overlap = 0usize;
        let mut node_overlap = 0usize;
        let mut exact_route_reuse = 0usize;
        let mut temporal_reuse_penalty = 0usize;

        for (rev_idx, prior) in recent.iter().rev().enumerate() {
            let recency_weight = recent.len().saturating_sub(rev_idx);
            operator_overlap += Self::overlap_size(&candidate.operators, &prior.operators);
            jurisdiction_overlap +=
                Self::overlap_size(&candidate.jurisdictions, &prior.jurisdictions);
            asn_overlap += Self::overlap_size(&candidate.asns, &prior.asns);
            node_overlap += Self::overlap_size(&candidate.node_set, &prior.node_set);
            temporal_reuse_penalty = temporal_reuse_penalty.saturating_add(
                Self::overlap_size(&candidate.node_set, &prior.node_set)
                    .saturating_mul(recency_weight),
            );
            if candidate.node_sequence == prior.node_sequence {
                exact_route_reuse = exact_route_reuse.saturating_add(1);
                temporal_reuse_penalty =
                    temporal_reuse_penalty.saturating_add(recency_weight.saturating_mul(2));
            }
        }

        let concentration = self.concentration_metrics_for_indices(selected_indices, overrides);
        let mut score = 0u32;
        score = score.saturating_add((operator_overlap as u32) * CORRELATION_OPERATOR_WEIGHT);
        score =
            score.saturating_add((jurisdiction_overlap as u32) * CORRELATION_JURISDICTION_WEIGHT);
        score = score.saturating_add((asn_overlap as u32) * CORRELATION_ASN_WEIGHT);
        score = score.saturating_add((node_overlap as u32) * CORRELATION_NODE_WEIGHT);
        score = score.saturating_add((exact_route_reuse as u32) * CORRELATION_EXACT_ROUTE_WEIGHT);
        score = score
            .saturating_add((temporal_reuse_penalty as u32) * CORRELATION_TEMPORAL_REUSE_WEIGHT);
        score = score.saturating_add(
            concentration
                .risk_score
                .saturating_mul(CORRELATION_CONCENTRATION_WEIGHT),
        );

        RouteCorrelationScore {
            score,
            concentration_risk_score: concentration.risk_score,
            concentration_operator_dominance_pct: concentration.operator_dominance_pct,
            concentration_jurisdiction_dominance_pct: concentration.jurisdiction_dominance_pct,
            concentration_asn_dominance_pct: concentration.asn_dominance_pct,
            operator_overlap,
            jurisdiction_overlap,
            asn_overlap,
            node_overlap,
            exact_route_reuse,
            temporal_reuse_penalty,
        }
    }

    fn record_selected_route(
        &self,
        selected_indices: &[usize],
        score: RouteCorrelationScore,
        overrides: Option<&LiveClassificationMap>,
    ) {
        let Some(fingerprint) = self.build_route_fingerprint(selected_indices, overrides) else {
            return;
        };
        let live_entries = overrides.map(|m| m.len()).unwrap_or(0);
        if let Ok(mut memory) = self.correlation_memory.lock() {
            memory.recent.push_back(fingerprint);
            while memory.recent.len() > ROUTE_CORRELATION_MEMORY_LIMIT {
                memory.recent.pop_front();
            }
            memory.last = RouteCorrelationTelemetry {
                score: score.score,
                concentration_risk_score: score.concentration_risk_score,
                concentration_operator_dominance_pct: score.concentration_operator_dominance_pct,
                concentration_jurisdiction_dominance_pct: score
                    .concentration_jurisdiction_dominance_pct,
                concentration_asn_dominance_pct: score.concentration_asn_dominance_pct,
                operator_overlap: score.operator_overlap,
                jurisdiction_overlap: score.jurisdiction_overlap,
                asn_overlap: score.asn_overlap,
                node_overlap: score.node_overlap,
                exact_route_reuse: score.exact_route_reuse,
                temporal_reuse_penalty: score.temporal_reuse_penalty,
                live_classification_active: live_entries > 0,
                live_classification_entries: live_entries,
                reject_diversity_policy: memory.reject_diversity_policy,
                reject_correlation_threshold: memory.reject_correlation_threshold,
                reject_concentration_threshold: memory.reject_concentration_threshold,
                reject_empty_topology: memory.reject_empty_topology,
                last_reject_reason: memory.last_reject_reason.clone(),
            };
        }
    }

    fn record_route_reject(&self, reason: RouteRejectReason, details: &str) {
        if let Ok(mut memory) = self.correlation_memory.lock() {
            match reason {
                RouteRejectReason::DiversityPolicy => {
                    memory.reject_diversity_policy =
                        memory.reject_diversity_policy.saturating_add(1);
                }
                RouteRejectReason::CorrelationThreshold => {
                    memory.reject_correlation_threshold =
                        memory.reject_correlation_threshold.saturating_add(1);
                }
                RouteRejectReason::ConcentrationThreshold => {
                    memory.reject_concentration_threshold =
                        memory.reject_concentration_threshold.saturating_add(1);
                }
                RouteRejectReason::EmptyTopology => {
                    memory.reject_empty_topology = memory.reject_empty_topology.saturating_add(1);
                }
            }
            memory.last_reject_reason = Some(details.to_string());
            memory.last.reject_diversity_policy = memory.reject_diversity_policy;
            memory.last.reject_correlation_threshold = memory.reject_correlation_threshold;
            memory.last.reject_concentration_threshold = memory.reject_concentration_threshold;
            memory.last.reject_empty_topology = memory.reject_empty_topology;
            memory.last.last_reject_reason = memory.last_reject_reason.clone();
        }
    }

    fn collect_policy_compliant_combinations(
        &self,
        num_hops: usize,
        config: MixnetConfig,
    ) -> Vec<Vec<usize>> {
        let mut current = Vec::new();
        let mut out = Vec::new();
        self.collect_policy_compliant_recursive(0, num_hops, &mut current, config, &mut out);
        out
    }

    fn collect_policy_compliant_recursive(
        &self,
        start: usize,
        remaining: usize,
        current: &mut Vec<usize>,
        config: MixnetConfig,
        out: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            if self.diversity_satisfied(current, config) {
                out.push(current.clone());
            }
            return;
        }

        let n = self.nodes.len();
        for idx in start..n {
            if n.saturating_sub(idx) < remaining {
                break;
            }
            current.push(idx);
            self.collect_policy_compliant_recursive(idx + 1, remaining - 1, current, config, out);
            current.pop();
        }
    }

    fn select_hop_indices(&self, num_hops: usize, config: MixnetConfig) -> Result<Vec<usize>> {
        if num_hops == 0 {
            return Err(anyhow!("Mix circuit must include at least one hop"));
        }
        if self.nodes.len() < num_hops {
            self.record_route_reject(
                RouteRejectReason::EmptyTopology,
                "Not enough relays available for requested hop count",
            );
            return Err(anyhow!("Not enough relays for a {}-hop circuit", num_hops));
        }

        let live_overrides = load_live_classification_overrides();
        let mut candidates = self.collect_policy_compliant_combinations(num_hops, config);
        if let Some(overrides) = live_overrides.as_ref() {
            candidates.retain(|candidate| {
                self.diversity_satisfied_with_overrides(candidate, config, Some(overrides))
            });
        }
        if candidates.is_empty() {
            let min_ops = config.min_unique_operators.max(1);
            let min_jur = config.min_unique_jurisdictions.max(1);
            let min_asn = config.min_unique_asns.max(1);
            self.record_route_reject(
                RouteRejectReason::DiversityPolicy,
                &format!(
                    "No route satisfies diversity policy (operators >= {}, jurisdictions >= {}, asns >= {})",
                    min_ops, min_jur, min_asn
                ),
            );
            return Err(anyhow!(
                "No route satisfies diversity policy (required operators >= {}, jurisdictions >= {}, asns >= {})",
                min_ops,
                min_jur,
                min_asn
            ));
        }

        let max_attempts = config.route_attempts.max(1);
        if candidates.len() > max_attempts {
            candidates.shuffle(&mut rand::thread_rng());
            candidates.truncate(max_attempts);
        }

        let recent = self
            .correlation_memory
            .lock()
            .map(|memory| memory.recent.clone())
            .unwrap_or_default();
        let max_allowed_score = max_route_correlation_score();
        let max_allowed_concentration_risk = max_route_concentration_risk();

        let mut best_candidate: Option<(Vec<usize>, RouteCorrelationScore)> = None;
        for candidate in candidates {
            let score =
                self.score_candidate_against_recent(&candidate, &recent, live_overrides.as_ref());
            let is_better = match &best_candidate {
                None => true,
                Some((best_indices, best_score)) => {
                    score.score < best_score.score
                        || (score.score == best_score.score && candidate < *best_indices)
                }
            };
            if is_better {
                best_candidate = Some((candidate, score));
            }
        }

        if let Some((selected, score)) = best_candidate {
            if let Some(max_score) = max_allowed_score {
                if score.score > max_score {
                    self.record_route_reject(
                        RouteRejectReason::CorrelationThreshold,
                        &format!(
                            "Route rejected by anti-correlation threshold (score={}, max={})",
                            score.score, max_score
                        ),
                    );
                    return Err(anyhow!(
                        "Route rejected by anti-correlation threshold (score={}, max={})",
                        score.score,
                        max_score
                    ));
                }
            }
            if let Some(max_concentration) = max_allowed_concentration_risk {
                if score.concentration_risk_score > max_concentration {
                    self.record_route_reject(
                        RouteRejectReason::ConcentrationThreshold,
                        &format!(
                            "Route rejected by concentration threshold (risk={}, max={})",
                            score.concentration_risk_score, max_concentration
                        ),
                    );
                    return Err(anyhow!(
                        "Route rejected by concentration threshold (risk={}, max={})",
                        score.concentration_risk_score,
                        max_concentration
                    ));
                }
            }
            self.record_selected_route(&selected, score, live_overrides.as_ref());
            return Ok(selected);
        }

        Err(anyhow!(
            "No route satisfies anti-correlation selection policy"
        ))
    }

    /// Builds a Sphinx-like packet chain.
    /// Returns (Entry Node URL, Encrypted Mix Packet).
    #[allow(dead_code)]
    pub fn build_circuit(
        &self,
        final_receiver: &str,
        payload: &[u8],
        num_hops: usize,
    ) -> Result<(String, Vec<u8>)> {
        let default_policy = MixnetConfig::default();
        let selected_indices = self.select_hop_indices(num_hops, default_policy)?;
        self.build_circuit_with_indices(final_receiver, payload, &selected_indices)
    }

    pub fn build_circuit_from_config(
        &self,
        final_receiver: &str,
        payload: &[u8],
        config: MixnetConfig,
    ) -> Result<(String, Vec<u8>)> {
        if self.nodes.is_empty() {
            return Err(anyhow!("No mix nodes configured"));
        }

        let mut rng = rand::thread_rng();
        let mut min = if config.min_hops > 0 {
            config.min_hops
        } else {
            1
        };
        min = min.min(self.nodes.len());

        let mut max = if config.max_hops >= min {
            config.max_hops
        } else {
            min
        };
        max = max.min(self.nodes.len());

        let num_hops = rng.gen_range(min..=max);
        let selected_indices = self.select_hop_indices(num_hops, config)?;
        self.build_circuit_with_indices(final_receiver, payload, &selected_indices)
    }

    fn build_circuit_with_indices(
        &self,
        final_receiver: &str,
        payload: &[u8],
        selected_indices: &[usize],
    ) -> Result<(String, Vec<u8>)> {
        if selected_indices.is_empty() {
            return Err(anyhow!("Empty selected hop set"));
        }

        let exit_idx = *selected_indices
            .last()
            .ok_or_else(|| anyhow!("Empty selected hop set"))?;
        let exit_node = &self.nodes[exit_idx];

        let final_layer = SphinxHopPayload {
            v: 1,
            mode: "final".to_string(),
            next_hop: None,
            next_hop_pub_key: None,
            final_receiver: Some(final_receiver.to_string()),
            payload: payload.to_vec(),
        };

        let final_layer_bytes =
            serde_json::to_vec(&final_layer).context("serialize final sphinx hop payload")?;
        let mut current_packet = encrypt_mix_packet(&exit_node.pub_key, &final_layer_bytes)?;

        for pos in (0..selected_indices.len().saturating_sub(1)).rev() {
            let current_idx = selected_indices[pos];
            let next_idx = selected_indices[pos + 1];
            let current_node = &self.nodes[current_idx];
            let next_node = &self.nodes[next_idx];

            let route_layer = SphinxHopPayload {
                v: 1,
                mode: "route".to_string(),
                next_hop: Some(next_node.url.clone()),
                next_hop_pub_key: Some(hex::encode(next_node.pub_key.as_bytes())),
                final_receiver: None,
                payload: current_packet,
            };
            let route_layer_bytes =
                serde_json::to_vec(&route_layer).context("serialize route sphinx hop payload")?;
            current_packet = encrypt_mix_packet(&current_node.pub_key, &route_layer_bytes)?;
        }

        let entry_node = &self.nodes[selected_indices[0]];
        Ok((entry_node.url.clone(), current_packet))
    }

    pub fn simulate_adversary_resistance(
        &self,
        seed: u64,
        rounds: u32,
        num_hops: usize,
        config: MixnetConfig,
    ) -> RouteAdversarySimulationReport {
        const REPORT_VERSION: &str = "route_anti_correlation.v3";
        if rounds == 0 || num_hops == 0 {
            return RouteAdversarySimulationReport {
                report_version: REPORT_VERSION,
                seed,
                rounds,
                ..RouteAdversarySimulationReport::default()
            };
        }

        let live_overrides = load_live_classification_overrides();
        let mut candidates = self.collect_policy_compliant_combinations(num_hops, config);
        if let Some(overrides) = live_overrides.as_ref() {
            candidates.retain(|candidate| {
                self.diversity_satisfied_with_overrides(candidate, config, Some(overrides))
            });
        }
        if candidates.is_empty() {
            return RouteAdversarySimulationReport {
                report_version: REPORT_VERSION,
                seed,
                rounds,
                ..RouteAdversarySimulationReport::default()
            };
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let compromised_nodes: HashSet<String> = self
            .nodes
            .iter()
            .take(2)
            .map(|node| node.url.clone())
            .collect();

        let mut recent_selected = VecDeque::new();
        let mut recent_random = VecDeque::new();
        let mut selected_score_sum = 0f64;
        let mut random_score_sum = 0f64;
        let mut selected_collusion_hits = 0u32;
        let mut random_collusion_hits = 0u32;
        let mut selected_exact_reuse = 0u32;
        let mut random_exact_reuse = 0u32;

        for _round in 0..rounds {
            let mut selected_pick: Option<(Vec<usize>, RouteCorrelationScore)> = None;
            for candidate in &candidates {
                let score = self.score_candidate_against_recent(
                    candidate,
                    &recent_selected,
                    live_overrides.as_ref(),
                );
                let is_better = match &selected_pick {
                    None => true,
                    Some((best_indices, best_score)) => {
                        score.score < best_score.score
                            || (score.score == best_score.score && candidate < best_indices)
                    }
                };
                if is_better {
                    selected_pick = Some((candidate.clone(), score));
                }
            }
            if let Some((selected_indices, score)) = selected_pick {
                selected_score_sum += score.score as f64;
                if let Some(fingerprint) =
                    self.build_route_fingerprint(&selected_indices, live_overrides.as_ref())
                {
                    if recent_selected
                        .back()
                        .map(|prior: &RouteFingerprint| prior.node_sequence == fingerprint.node_sequence)
                        .unwrap_or(false)
                    {
                        selected_exact_reuse = selected_exact_reuse.saturating_add(1);
                    }
                    if partial_collusion_observed(&fingerprint, &compromised_nodes) {
                        selected_collusion_hits = selected_collusion_hits.saturating_add(1);
                    }
                    recent_selected.push_back(fingerprint);
                    while recent_selected.len() > ROUTE_CORRELATION_MEMORY_LIMIT {
                        recent_selected.pop_front();
                    }
                }
            }

            let random_indices = candidates[rng.gen_range(0..candidates.len())].clone();
            let random_score = self.score_candidate_against_recent(
                &random_indices,
                &recent_random,
                live_overrides.as_ref(),
            );
            random_score_sum += random_score.score as f64;
            if let Some(fingerprint) =
                self.build_route_fingerprint(&random_indices, live_overrides.as_ref())
            {
                if recent_random
                    .back()
                    .map(|prior: &RouteFingerprint| prior.node_sequence == fingerprint.node_sequence)
                    .unwrap_or(false)
                {
                    random_exact_reuse = random_exact_reuse.saturating_add(1);
                }
                if partial_collusion_observed(&fingerprint, &compromised_nodes) {
                    random_collusion_hits = random_collusion_hits.saturating_add(1);
                }
                recent_random.push_back(fingerprint);
                while recent_random.len() > ROUTE_CORRELATION_MEMORY_LIMIT {
                    recent_random.pop_front();
                }
            }
        }

        let denom = rounds as f64;
        RouteAdversarySimulationReport {
            report_version: REPORT_VERSION,
            seed,
            rounds,
            selected_avg_score: selected_score_sum / denom,
            random_avg_score: random_score_sum / denom,
            selected_partial_collusion_rate: selected_collusion_hits as f64 / denom,
            random_partial_collusion_rate: random_collusion_hits as f64 / denom,
            selected_exact_reuse_rate: selected_exact_reuse as f64 / denom,
            random_exact_reuse_rate: random_exact_reuse as f64 / denom,
        }
    }
}

fn partial_collusion_observed(
    fingerprint: &RouteFingerprint,
    compromised_nodes: &HashSet<String>,
) -> bool {
    let compromised_hops = fingerprint
        .node_sequence
        .iter()
        .filter(|url| compromised_nodes.contains(*url))
        .count();
    compromised_hops >= 2
}

fn max_route_correlation_score() -> Option<u32> {
    #[cfg(test)]
    {
        TEST_MAX_ROUTE_CORRELATION_SCORE_OVERRIDE
            .with(|state| *state.borrow())
            .unwrap_or(None)
    }

    #[cfg(not(test))]
    {
        std::env::var("REDOOR_MIXNET_MAX_CORRELATION_SCORE")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|value| *value > 0)
    }
}

fn max_route_concentration_risk() -> Option<u32> {
    #[cfg(test)]
    {
        TEST_MAX_ROUTE_CONCENTRATION_RISK_OVERRIDE
            .with(|state| *state.borrow())
            .unwrap_or(None)
    }

    #[cfg(not(test))]
    {
        std::env::var("REDOOR_MIXNET_MAX_CONCENTRATION_RISK")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|value| *value > 0)
    }
}

#[derive(Clone)]
struct EffectiveTags {
    operator_tag: String,
    jurisdiction_tag: String,
    asn_tag: String,
}

fn effective_tags(node: &MixNode, overrides: Option<&LiveClassificationMap>) -> EffectiveTags {
    let entry = overrides.and_then(|map| map.get(node.url.as_str()));
    let operator_tag = entry
        .and_then(|item| item.operator_tag.as_deref())
        .map(|value| sanitize_tag(Some(value), &node.operator_tag))
        .unwrap_or_else(|| node.operator_tag.clone());
    let jurisdiction_tag = entry
        .and_then(|item| item.jurisdiction_tag.as_deref())
        .map(|value| sanitize_tag(Some(value), &node.jurisdiction_tag))
        .unwrap_or_else(|| node.jurisdiction_tag.clone());
    let asn_tag = entry
        .and_then(|item| item.asn_tag.as_deref())
        .map(|value| sanitize_tag(Some(value), &node.asn_tag))
        .unwrap_or_else(|| node.asn_tag.clone());
    EffectiveTags {
        operator_tag,
        jurisdiction_tag,
        asn_tag,
    }
}

fn load_live_classification_overrides() -> Option<LiveClassificationMap> {
    let raw = std::env::var(MIXNET_CLASSIFICATION_ENV).ok()?;
    let parsed = serde_json::from_str::<LiveClassificationMap>(&raw).ok()?;
    if parsed.is_empty() {
        return None;
    }

    let normalized = parsed
        .into_iter()
        .map(|(url, mut entry)| {
            entry.operator_tag = entry
                .operator_tag
                .as_deref()
                .map(|value| sanitize_tag(Some(value), "unknown"))
                .and_then(|value| if value.is_empty() { None } else { Some(value) });
            entry.jurisdiction_tag = entry
                .jurisdiction_tag
                .as_deref()
                .map(|value| sanitize_tag(Some(value), "unknown"))
                .and_then(|value| if value.is_empty() { None } else { Some(value) });
            entry.asn_tag = entry
                .asn_tag
                .as_deref()
                .map(|value| sanitize_tag(Some(value), "unknown"))
                .and_then(|value| if value.is_empty() { None } else { Some(value) });
            (url, entry)
        })
        .collect::<LiveClassificationMap>();

    Some(normalized)
}

#[derive(Clone, Copy, Debug, Default)]
struct ConcentrationMetrics {
    risk_score: u32,
    operator_dominance_pct: u8,
    jurisdiction_dominance_pct: u8,
    asn_dominance_pct: u8,
}

fn max_share_pct(set_size: usize, max_bucket_size: usize) -> u8 {
    if set_size == 0 {
        return 0;
    }
    (((max_bucket_size.saturating_mul(100)) + (set_size / 2)) / set_size) as u8
}

#[cfg(test)]
thread_local! {
    static TEST_MAX_ROUTE_CORRELATION_SCORE_OVERRIDE: std::cell::RefCell<Option<Option<u32>>> =
        const { std::cell::RefCell::new(None) };
    static TEST_MAX_ROUTE_CONCENTRATION_RISK_OVERRIDE: std::cell::RefCell<Option<Option<u32>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct TestMaxCorrelationOverrideGuard;

#[cfg(test)]
impl Drop for TestMaxCorrelationOverrideGuard {
    fn drop(&mut self) {
        TEST_MAX_ROUTE_CORRELATION_SCORE_OVERRIDE.with(|state| {
            *state.borrow_mut() = None;
        });
        TEST_MAX_ROUTE_CONCENTRATION_RISK_OVERRIDE.with(|state| {
            *state.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
fn test_override_max_route_correlation_score(
    value: Option<u32>,
) -> TestMaxCorrelationOverrideGuard {
    TEST_MAX_ROUTE_CORRELATION_SCORE_OVERRIDE.with(|state| {
        *state.borrow_mut() = Some(value);
    });
    TestMaxCorrelationOverrideGuard
}

#[cfg(test)]
fn test_override_max_route_concentration_risk(
    value: Option<u32>,
) -> TestMaxCorrelationOverrideGuard {
    TEST_MAX_ROUTE_CONCENTRATION_RISK_OVERRIDE.with(|state| {
        *state.borrow_mut() = Some(value);
    });
    TestMaxCorrelationOverrideGuard
}

fn sanitize_tag(candidate: Option<&str>, fallback: &str) -> String {
    let normalized = candidate
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace(
            |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
            "-",
        );
    let trimmed = normalized.trim_matches('-').trim_matches('_').to_string();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed
    }
}

fn default_node_tag_from_url(url: &str) -> String {
    let stripped = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url);
    let host = stripped.split('@').next_back().unwrap_or(stripped);
    let host_only = host.split(':').next().unwrap_or(host);
    sanitize_tag(Some(host_only), "unknown")
}

fn encrypt_mix_packet(node_public_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let (ephemeral_priv, ephemeral_pub) = x25519::generate_keypair();
    let shared_secret = x25519::diffie_hellman(&ephemeral_priv, node_public_key);
    let (ciphertext, nonce) = chacha20poly1305::encrypt(&shared_secret, plaintext)?;

    let mut tag = [0u8; MIX_PACKET_TAG_LEN];
    rand::thread_rng().fill_bytes(&mut tag);

    let mut packet = Vec::with_capacity(MIX_PACKET_HEADER_LEN + ciphertext.len());
    packet.extend_from_slice(MIX_PACKET_MAGIC);
    packet.extend_from_slice(&tag);
    packet.extend_from_slice(ephemeral_pub.as_bytes());
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

#[cfg(test)]
fn decrypt_mix_packet(private_key: &x25519::StaticSecret, packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < MIX_PACKET_HEADER_LEN + 16 {
        return Err(anyhow!("mix packet too short"));
    }

    if &packet[..4] != MIX_PACKET_MAGIC {
        return Err(anyhow!("invalid mix packet magic"));
    }

    let ephemeral_offset = 4 + MIX_PACKET_TAG_LEN;
    let ephemeral_pub = PublicKey::from(
        <[u8; 32]>::try_from(&packet[ephemeral_offset..ephemeral_offset + 32])
            .map_err(|_| anyhow!("invalid ephemeral public key"))?,
    );
    let nonce_offset = ephemeral_offset + 32;
    let nonce: [u8; 12] = packet[nonce_offset..nonce_offset + 12]
        .try_into()
        .map_err(|_| anyhow!("invalid nonce"))?;
    let ciphertext = &packet[nonce_offset + 12..];

    let shared_secret = x25519::diffie_hellman(private_key, &ephemeral_pub);
    chacha20poly1305::decrypt(&shared_secret, ciphertext, &nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_build_circuit_sphinx_layers_hide_final_receiver() {
        let (n1_priv, n1_pub) = x25519::generate_keypair();
        let (n2_priv, n2_pub) = x25519::generate_keypair();
        let (n3_priv, n3_pub) = x25519::generate_keypair();

        let router = OnionRouter::new(vec![
            ("https://relay-a.example".to_string(), n1_pub),
            ("https://relay-b.example".to_string(), n2_pub),
            ("https://relay-c.example".to_string(), n3_pub),
        ]);

        let mut private_keys = HashMap::new();
        private_keys.insert("https://relay-a.example".to_string(), n1_priv);
        private_keys.insert("https://relay-b.example".to_string(), n2_priv);
        private_keys.insert("https://relay-c.example".to_string(), n3_priv);

        let final_receiver = "receiver-mailbox";
        let message = b"top secret payload";

        let (entry, mut packet) = router
            .build_circuit(final_receiver, message, 3)
            .expect("build sphinx circuit");

        let mut current_hop = entry;
        for hop_index in 0..3 {
            let private_key = private_keys
                .get(&current_hop)
                .expect("private key for hop URL exists");
            let plaintext = decrypt_mix_packet(private_key, &packet).expect("decrypt hop layer");
            let layer: SphinxHopPayload =
                serde_json::from_slice(&plaintext).expect("decode hop payload");

            if hop_index < 2 {
                assert_eq!(layer.mode, "route");
                assert!(layer.final_receiver.is_none());

                let next_hop = layer.next_hop.expect("route layer next hop");
                assert_ne!(next_hop, final_receiver);
                assert!(layer.next_hop_pub_key.is_some());

                current_hop = next_hop;
                packet = layer.payload;
            } else {
                assert_eq!(layer.mode, "final");
                assert_eq!(
                    layer.final_receiver.expect("final receiver present"),
                    final_receiver
                );
                assert_eq!(layer.payload, message);
            }
        }
    }

    #[test]
    fn test_build_circuit_from_config_clamps_hops_to_node_count() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let router = OnionRouter::new(vec![
            ("https://relay-a.example".to_string(), n1_pub),
            ("https://relay-b.example".to_string(), n2_pub),
            ("https://relay-c.example".to_string(), n3_pub),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 8,
            ..MixnetConfig::default()
        };
        let (_entry, packet) = router
            .build_circuit_from_config("receiver", b"payload", cfg)
            .expect("build from config");

        assert!(packet.len() > MIX_PACKET_HEADER_LEN);
    }

    #[test]
    fn test_route_selection_enforces_operator_and_jurisdiction_diversity() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let (_, n4_pub) = x25519::generate_keypair();

        let router = OnionRouter::new_tagged(vec![
            MixNode::with_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-a".to_string()),
                Some("jur-ca".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-b".to_string()),
                Some("jur-us".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-d.example".to_string(),
                n4_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 2,
            min_unique_jurisdictions: 2,
            min_unique_asns: 1,
            route_attempts: 4,
        };
        let selected = router
            .select_hop_indices(3, cfg)
            .expect("select diverse path");
        assert!(router.diversity_satisfied(&selected, cfg));
    }

    #[test]
    fn test_route_selection_reports_policy_failure_when_diversity_is_impossible() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let router = OnionRouter::new_tagged(vec![
            MixNode::with_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 2,
            min_unique_jurisdictions: 2,
            min_unique_asns: 1,
            route_attempts: 2,
        };
        let err = router
            .build_circuit_from_config("receiver", b"payload", cfg)
            .expect_err("diversity policy should fail");
        assert!(err
            .to_string()
            .contains("No route satisfies diversity policy"));
    }

    #[test]
    fn test_route_selection_enforces_asn_diversity() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let (_, n4_pub) = x25519::generate_keypair();

        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-b".to_string()),
                Some("jur-ca".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
                Some("as64501".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-d.example".to_string(),
                n4_pub,
                Some("operator-d".to_string()),
                Some("jur-fr".to_string()),
                Some("as64502".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 2,
            min_unique_jurisdictions: 2,
            min_unique_asns: 2,
            route_attempts: 4,
        };
        let selected = router
            .select_hop_indices(3, cfg)
            .expect("select asn-diverse path");
        assert!(router.diversity_satisfied(&selected, cfg));
    }

    #[test]
    fn test_route_selection_prefers_lower_correlation_over_reuse() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let (_, n4_pub) = x25519::generate_keypair();
        let (_, n5_pub) = x25519::generate_keypair();

        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-b".to_string()),
                Some("jur-ca".to_string()),
                Some("as64501".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
                Some("as64502".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-d.example".to_string(),
                n4_pub,
                Some("operator-d".to_string()),
                Some("jur-fr".to_string()),
                Some("as64503".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-e.example".to_string(),
                n5_pub,
                Some("operator-e".to_string()),
                Some("jur-it".to_string()),
                Some("as64504".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 1,
            min_unique_jurisdictions: 1,
            min_unique_asns: 1,
            route_attempts: 16,
        };

        let first = router
            .select_hop_indices(3, cfg)
            .expect("first route selection");
        assert_eq!(first, vec![0, 1, 2]);

        let recent = router
            .correlation_memory
            .lock()
            .expect("route memory lock")
            .recent
            .clone();

        let higher_reuse = router.score_candidate_against_recent(&[0, 1, 3], &recent, None);
        let lower_reuse = router.score_candidate_against_recent(&[0, 3, 4], &recent, None);
        assert!(
            lower_reuse.score < higher_reuse.score,
            "candidate with less infrastructure overlap should score lower"
        );

        let second = router
            .select_hop_indices(3, cfg)
            .expect("second route selection");
        assert_eq!(second, vec![0, 3, 4]);
    }

    #[test]
    fn test_route_correlation_telemetry_reports_last_selected_score() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let (_, n4_pub) = x25519::generate_keypair();
        let (_, n5_pub) = x25519::generate_keypair();

        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-b".to_string()),
                Some("jur-ca".to_string()),
                Some("as64501".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
                Some("as64502".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-d.example".to_string(),
                n4_pub,
                Some("operator-d".to_string()),
                Some("jur-fr".to_string()),
                Some("as64503".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-e.example".to_string(),
                n5_pub,
                Some("operator-e".to_string()),
                Some("jur-it".to_string()),
                Some("as64504".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 1,
            min_unique_jurisdictions: 1,
            min_unique_asns: 1,
            route_attempts: 16,
        };

        let _ = router.select_hop_indices(3, cfg).expect("first selection");
        let _ = router.select_hop_indices(3, cfg).expect("second selection");

        let telemetry = router.route_correlation_telemetry();
        assert!(telemetry.score >= 48);
        assert_eq!(telemetry.operator_overlap, 1);
        assert_eq!(telemetry.jurisdiction_overlap, 1);
        assert_eq!(telemetry.asn_overlap, 1);
        assert_eq!(telemetry.node_overlap, 1);
        assert_eq!(telemetry.exact_route_reuse, 0);
        assert!(telemetry.temporal_reuse_penalty > 0);
    }

    #[test]
    fn test_route_reject_counter_tracks_diversity_failures() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let router = OnionRouter::new_tagged(vec![
            MixNode::with_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
            MixNode::with_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 2,
            min_unique_jurisdictions: 2,
            min_unique_asns: 1,
            route_attempts: 2,
        };
        let _ = router.build_circuit_from_config("receiver", b"payload", cfg);
        let telemetry = router.route_correlation_telemetry();
        assert!(telemetry.reject_diversity_policy >= 1);
        assert!(telemetry
            .last_reject_reason
            .as_deref()
            .unwrap_or_default()
            .contains("diversity"));
    }

    #[test]
    fn test_route_reject_counter_tracks_correlation_threshold() {
        let _override_guard = test_override_max_route_correlation_score(Some(20));

        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-b".to_string()),
                Some("jur-ca".to_string()),
                Some("as64501".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
                Some("as64502".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 1,
            min_unique_jurisdictions: 1,
            min_unique_asns: 1,
            route_attempts: 8,
        };

        let _ = router
            .select_hop_indices(3, cfg)
            .expect("first route should pass");
        let err = router
            .select_hop_indices(3, cfg)
            .expect_err("second route should fail low threshold");
        assert!(err.to_string().contains("anti-correlation threshold"));

        let telemetry = router.route_correlation_telemetry();
        assert!(telemetry.reject_correlation_threshold >= 1);
        assert!(telemetry
            .last_reject_reason
            .as_deref()
            .unwrap_or_default()
            .contains("threshold"));
    }

    #[test]
    fn test_live_classification_overrides_drive_diversity_policy() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-b".to_string()),
                Some("jur-ca".to_string()),
                Some("as64501".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
                Some("as64502".to_string()),
            ),
        ]);

        let overrides = serde_json::json!({
            "https://relay-a.example": { "operator_tag": "operator-z", "jurisdiction_tag": "jur-z", "asn_tag": "as65000" },
            "https://relay-b.example": { "operator_tag": "operator-z", "jurisdiction_tag": "jur-z", "asn_tag": "as65000" },
            "https://relay-c.example": { "operator_tag": "operator-z", "jurisdiction_tag": "jur-z", "asn_tag": "as65000" }
        });
        std::env::set_var(MIXNET_CLASSIFICATION_ENV, overrides.to_string());

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 2,
            min_unique_jurisdictions: 2,
            min_unique_asns: 2,
            route_attempts: 8,
        };

        let err = router
            .build_circuit_from_config("receiver", b"payload", cfg)
            .expect_err("live classifications should collapse diversity");
        assert!(err
            .to_string()
            .contains("No route satisfies diversity policy"));
        std::env::remove_var(MIXNET_CLASSIFICATION_ENV);
    }

    #[test]
    fn test_route_reject_counter_tracks_concentration_threshold() {
        let _override_guard = test_override_max_route_concentration_risk(Some(150));

        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 1,
            min_unique_jurisdictions: 1,
            min_unique_asns: 1,
            route_attempts: 8,
        };

        let err = router
            .select_hop_indices(3, cfg)
            .expect_err("concentrated path should fail threshold");
        assert!(err.to_string().contains("concentration threshold"));

        let telemetry = router.route_correlation_telemetry();
        assert!(telemetry.reject_concentration_threshold >= 1);
        assert!(telemetry
            .last_reject_reason
            .as_deref()
            .unwrap_or_default()
            .contains("concentration"));
    }

    #[test]
    fn test_adversary_simulation_prefers_lower_correlation_than_random_baseline() {
        let (_, n1_pub) = x25519::generate_keypair();
        let (_, n2_pub) = x25519::generate_keypair();
        let (_, n3_pub) = x25519::generate_keypair();
        let (_, n4_pub) = x25519::generate_keypair();
        let (_, n5_pub) = x25519::generate_keypair();
        let (_, n6_pub) = x25519::generate_keypair();

        let router = OnionRouter::new_tagged(vec![
            MixNode::with_extended_tags(
                "https://relay-a.example".to_string(),
                n1_pub,
                Some("operator-a".to_string()),
                Some("jur-us".to_string()),
                Some("as64500".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-b.example".to_string(),
                n2_pub,
                Some("operator-b".to_string()),
                Some("jur-ca".to_string()),
                Some("as64501".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-c.example".to_string(),
                n3_pub,
                Some("operator-c".to_string()),
                Some("jur-de".to_string()),
                Some("as64502".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-d.example".to_string(),
                n4_pub,
                Some("operator-d".to_string()),
                Some("jur-fr".to_string()),
                Some("as64503".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-e.example".to_string(),
                n5_pub,
                Some("operator-e".to_string()),
                Some("jur-it".to_string()),
                Some("as64504".to_string()),
            ),
            MixNode::with_extended_tags(
                "https://relay-f.example".to_string(),
                n6_pub,
                Some("operator-f".to_string()),
                Some("jur-es".to_string()),
                Some("as64505".to_string()),
            ),
        ]);

        let cfg = MixnetConfig {
            min_hops: 3,
            max_hops: 3,
            min_unique_operators: 2,
            min_unique_jurisdictions: 2,
            min_unique_asns: 2,
            route_attempts: 32,
        };

        let report_a = router.simulate_adversary_resistance(42, 128, 3, cfg);
        let report_b = router.simulate_adversary_resistance(42, 128, 3, cfg);
        assert_eq!(report_a.seed, report_b.seed);
        assert_eq!(report_a.rounds, report_b.rounds);
        assert_eq!(report_a.selected_avg_score, report_b.selected_avg_score);
        assert_eq!(
            report_a.selected_partial_collusion_rate,
            report_b.selected_partial_collusion_rate
        );
        assert!(
            report_a.selected_avg_score <= report_a.random_avg_score,
            "selector should not be worse than random baseline"
        );
        assert!(
            report_a.selected_partial_collusion_rate <= report_a.random_partial_collusion_rate,
            "selector should reduce partial-collusion exposure"
        );
    }
}
