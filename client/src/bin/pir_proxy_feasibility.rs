use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use std::cmp::Ordering;
use std::env;
use std::fs;

const DEFAULT_SEED: u64 = 0x50A7_5EED_2026;
const DEFAULT_SAMPLES: usize = 10_000;

#[derive(Clone, Copy)]
enum StrategyKind {
    BaselineSplitRetrieval,
    ProxyFanout,
    TwoServerPirProxy,
}

impl StrategyKind {
    fn all() -> [StrategyKind; 3] {
        [
            StrategyKind::BaselineSplitRetrieval,
            StrategyKind::ProxyFanout,
            StrategyKind::TwoServerPirProxy,
        ]
    }

    fn id(self) -> &'static str {
        match self {
            StrategyKind::BaselineSplitRetrieval => "baseline_split_retrieval",
            StrategyKind::ProxyFanout => "proxy_fanout_retrieval",
            StrategyKind::TwoServerPirProxy => "two_server_pir_proxy",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            StrategyKind::BaselineSplitRetrieval => {
                "Current production path: direct client fanout to mirrored relays with quorum merge"
            }
            StrategyKind::ProxyFanout => {
                "Client queries a privacy proxy, proxy fans out to relay mirrors and returns merged result"
            }
            StrategyKind::TwoServerPirProxy => {
                "Research candidate: two-server PIR-style retrieval mediated by proxy"
            }
        }
    }
}

#[derive(Clone, Copy)]
struct SimConfig {
    relay_count: usize,
    relay_quorum: usize,
    relay_up_probability: f64,
    proxy_up_probability: f64,
    relay_timeout_ms: f64,
    relay_base_ms: f64,
    relay_jitter_ms: f64,
    proxy_base_ms: f64,
    proxy_jitter_ms: f64,
    client_relay_request_bytes: f64,
    client_relay_response_bytes: f64,
    client_proxy_request_bytes: f64,
    client_proxy_response_bytes: f64,
    proxy_relay_request_bytes: f64,
    proxy_relay_response_bytes: f64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            relay_count: 3,
            relay_quorum: 1,
            relay_up_probability: 0.972,
            proxy_up_probability: 0.985,
            relay_timeout_ms: 1300.0,
            relay_base_ms: 360.0,
            relay_jitter_ms: 240.0,
            proxy_base_ms: 170.0,
            proxy_jitter_ms: 110.0,
            client_relay_request_bytes: 420.0,
            client_relay_response_bytes: 740.0,
            client_proxy_request_bytes: 470.0,
            client_proxy_response_bytes: 790.0,
            proxy_relay_request_bytes: 430.0,
            proxy_relay_response_bytes: 740.0,
        }
    }
}

#[derive(Default)]
struct Aggregate {
    sample_count: usize,
    success_count: usize,
    latency_ms: Vec<f64>,
    client_up_bytes: f64,
    client_down_bytes: f64,
    infra_bytes: f64,
    client_cpu_ms: f64,
    infra_cpu_ms: f64,
    endpoint_exposure_score: f64,
    receiver_interest_exposure_score: f64,
}

#[derive(Serialize)]
struct Report {
    report_version: String,
    seed: u64,
    samples: usize,
    scenario: Scenario,
    strategies: Vec<StrategyReport>,
    recommendation: Recommendation,
}

#[derive(Serialize)]
struct Scenario {
    relay_count: usize,
    relay_quorum: usize,
    relay_up_probability: f64,
    proxy_up_probability: f64,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct StrategyReport {
    strategy: String,
    summary: String,
    metrics: Metrics,
    privacy: Privacy,
    operational_notes: Vec<String>,
}

#[derive(Serialize)]
struct Metrics {
    availability_success_rate: f64,
    mean_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    client_uplink_kib_per_fetch: f64,
    client_downlink_kib_per_fetch: f64,
    infra_total_kib_per_fetch: f64,
    client_cpu_ms_per_fetch: f64,
    infra_cpu_ms_per_fetch: f64,
}

#[derive(Serialize)]
struct Privacy {
    endpoint_exposure_score: f64,
    receiver_interest_exposure_score: f64,
    interpretation: String,
}

#[derive(Serialize)]
struct Recommendation {
    decision: String,
    rationale: Vec<String>,
    next_steps: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output_path = String::from("../docs/security/pir-proxy-feasibility-report.v1.json");
    let mut seed = DEFAULT_SEED;
    let mut samples = DEFAULT_SAMPLES;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                output_path = args
                    .next()
                    .ok_or("missing value for --output")?
                    .trim()
                    .to_string();
            }
            "--seed" => {
                let value = args.next().ok_or("missing value for --seed")?;
                seed = value.parse::<u64>()?;
            }
            "--samples" => {
                let value = args.next().ok_or("missing value for --samples")?;
                samples = value.parse::<usize>()?;
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                return Err(format!("unknown argument: {}", other).into());
            }
        }
    }

    let config = SimConfig::default();
    let mut reports = Vec::new();

    for strategy in StrategyKind::all() {
        let aggregate = run_strategy(strategy, config, seed, samples);
        reports.push(materialize_strategy_report(strategy, aggregate));
    }

    let recommendation = build_recommendation(&reports);

    let report = Report {
        report_version: "pir_proxy_mailbox_feasibility.v1".to_string(),
        seed,
        samples,
        scenario: Scenario {
            relay_count: config.relay_count,
            relay_quorum: config.relay_quorum,
            relay_up_probability: config.relay_up_probability,
            proxy_up_probability: config.proxy_up_probability,
            notes: vec![
                "Model uses deterministic synthetic latency and availability draws; values are comparative, not SLA guarantees.".to_string(),
                "Current baseline reflects existing mirrored relay fanout with quorum merge and wait-for-all completion.".to_string(),
                "PIR candidate models a two-server non-colluding design with heavy CPU/bandwidth overhead.".to_string(),
            ],
        },
        strategies: reports,
        recommendation,
    };

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&output_path, json)?;
    println!("wrote {}", output_path);

    Ok(())
}

fn print_help() {
    println!("usage: pir_proxy_feasibility [--output <path>] [--seed <u64>] [--samples <usize>]");
}

fn run_strategy(strategy: StrategyKind, config: SimConfig, seed: u64, samples: usize) -> Aggregate {
    let mut rng = StdRng::seed_from_u64(seed_for_strategy(seed, strategy));
    let mut agg = Aggregate {
        sample_count: samples,
        ..Aggregate::default()
    };

    for _ in 0..samples {
        match strategy {
            StrategyKind::BaselineSplitRetrieval => simulate_baseline(&mut rng, &config, &mut agg),
            StrategyKind::ProxyFanout => simulate_proxy_fanout(&mut rng, &config, &mut agg),
            StrategyKind::TwoServerPirProxy => simulate_pir_proxy(&mut rng, &config, &mut agg),
        }
    }

    agg
}

fn seed_for_strategy(seed: u64, strategy: StrategyKind) -> u64 {
    let salt = match strategy {
        StrategyKind::BaselineSplitRetrieval => 0xBACE,
        StrategyKind::ProxyFanout => 0xA7C2,
        StrategyKind::TwoServerPirProxy => 0xD1F2,
    };
    seed ^ salt
}

fn sample_latency_ms(rng: &mut StdRng, base: f64, jitter: f64) -> f64 {
    base + rng.gen_range(0.0..=jitter)
}

fn simulate_baseline(rng: &mut StdRng, cfg: &SimConfig, agg: &mut Aggregate) {
    let mut relay_latencies = Vec::with_capacity(cfg.relay_count);
    let mut healthy = 0usize;
    for _ in 0..cfg.relay_count {
        let up = rng.gen_bool(cfg.relay_up_probability);
        if up {
            healthy += 1;
            relay_latencies.push(sample_latency_ms(
                rng,
                cfg.relay_base_ms,
                cfg.relay_jitter_ms,
            ));
        } else {
            relay_latencies.push(cfg.relay_timeout_ms);
        }
    }

    let success = healthy >= cfg.relay_quorum;
    let latency = relay_latencies
        .into_iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
        .unwrap_or(cfg.relay_timeout_ms);

    agg.latency_ms.push(latency);
    if success {
        agg.success_count += 1;
    }

    agg.client_up_bytes += cfg.client_relay_request_bytes * cfg.relay_count as f64;
    agg.client_down_bytes += cfg.client_relay_response_bytes * cfg.relay_count as f64;
    agg.infra_bytes +=
        (cfg.client_relay_request_bytes + cfg.client_relay_response_bytes) * cfg.relay_count as f64;
    agg.client_cpu_ms += 1.8;
    agg.infra_cpu_ms += 2.9 * cfg.relay_count as f64;

    // Direct fanout exposes endpoint identity to each contacted relay.
    agg.endpoint_exposure_score += 1.0;
    // Receiver mailbox interest is directly visible to each relay queried.
    agg.receiver_interest_exposure_score += 1.0;
}

fn simulate_proxy_fanout(rng: &mut StdRng, cfg: &SimConfig, agg: &mut Aggregate) {
    let proxy_up = rng.gen_bool(cfg.proxy_up_probability);
    let mut relay_latencies = Vec::with_capacity(cfg.relay_count);
    let mut healthy_relays = 0usize;

    for _ in 0..cfg.relay_count {
        let up = rng.gen_bool(cfg.relay_up_probability);
        if up {
            healthy_relays += 1;
            let client_proxy = sample_latency_ms(rng, cfg.proxy_base_ms, cfg.proxy_jitter_ms);
            let proxy_relay = sample_latency_ms(rng, cfg.relay_base_ms, cfg.relay_jitter_ms);
            relay_latencies.push(client_proxy + proxy_relay + 28.0);
        } else {
            relay_latencies.push(cfg.relay_timeout_ms + 45.0);
        }
    }

    let success = proxy_up && healthy_relays >= cfg.relay_quorum;
    let latency = if proxy_up {
        relay_latencies
            .into_iter()
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
            .unwrap_or(cfg.relay_timeout_ms)
    } else {
        cfg.relay_timeout_ms + 110.0
    };

    agg.latency_ms.push(latency);
    if success {
        agg.success_count += 1;
    }

    agg.client_up_bytes += cfg.client_proxy_request_bytes;
    agg.client_down_bytes += cfg.client_proxy_response_bytes;
    agg.infra_bytes += cfg.client_proxy_request_bytes
        + cfg.client_proxy_response_bytes
        + (cfg.proxy_relay_request_bytes + cfg.proxy_relay_response_bytes) * cfg.relay_count as f64;
    agg.client_cpu_ms += 1.2;
    agg.infra_cpu_ms += 4.6 * cfg.relay_count as f64 + 2.2;

    // Relays lose direct endpoint observability; proxy becomes concentration point.
    agg.endpoint_exposure_score += 0.52;
    // Receiver interest is hidden from relays but fully visible to proxy.
    agg.receiver_interest_exposure_score += 0.64;
}

fn simulate_pir_proxy(rng: &mut StdRng, cfg: &SimConfig, agg: &mut Aggregate) {
    let proxy_up = rng.gen_bool(cfg.proxy_up_probability);
    // Two-server PIR needs both sides reachable for correctness.
    let relay_a_up = rng.gen_bool(cfg.relay_up_probability);
    let relay_b_up = rng.gen_bool(cfg.relay_up_probability);

    let relay_a = if relay_a_up {
        sample_latency_ms(rng, cfg.relay_base_ms * 1.8, cfg.relay_jitter_ms * 1.4)
    } else {
        cfg.relay_timeout_ms + 210.0
    };
    let relay_b = if relay_b_up {
        sample_latency_ms(rng, cfg.relay_base_ms * 1.8, cfg.relay_jitter_ms * 1.4)
    } else {
        cfg.relay_timeout_ms + 210.0
    };
    let client_proxy = sample_latency_ms(rng, cfg.proxy_base_ms, cfg.proxy_jitter_ms);

    let success = proxy_up && relay_a_up && relay_b_up;
    let latency = if success {
        client_proxy + relay_a.max(relay_b) + 95.0
    } else {
        cfg.relay_timeout_ms + 220.0
    };

    agg.latency_ms.push(latency);
    if success {
        agg.success_count += 1;
    }

    // PIR query expansion increases transfer size substantially.
    let expansion = 14.0;
    agg.client_up_bytes += cfg.client_proxy_request_bytes * expansion;
    agg.client_down_bytes += cfg.client_proxy_response_bytes * expansion;
    agg.infra_bytes += (cfg.client_proxy_request_bytes + cfg.client_proxy_response_bytes)
        * expansion
        + (cfg.proxy_relay_request_bytes + cfg.proxy_relay_response_bytes) * expansion * 2.0;

    // CPU is dominated by PIR compute on both proxy and relays.
    agg.client_cpu_ms += 7.6;
    agg.infra_cpu_ms += 58.0;

    // If non-collusion assumption holds, receiver-interest leakage is low.
    agg.endpoint_exposure_score += 0.44;
    agg.receiver_interest_exposure_score += 0.27;
}

fn materialize_strategy_report(strategy: StrategyKind, agg: Aggregate) -> StrategyReport {
    let sample_count = agg.sample_count.max(1) as f64;
    let mut latencies = agg.latency_ms;
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

    let mean_latency = latencies.iter().sum::<f64>() / sample_count;

    let p50 = percentile(&latencies, 50.0);
    let p95 = percentile(&latencies, 95.0);
    let p99 = percentile(&latencies, 99.0);

    let endpoint_exposure = agg.endpoint_exposure_score / sample_count;
    let receiver_interest_exposure = agg.receiver_interest_exposure_score / sample_count;

    StrategyReport {
        strategy: strategy.id().to_string(),
        summary: strategy.summary().to_string(),
        metrics: Metrics {
            availability_success_rate: agg.success_count as f64 / sample_count,
            mean_latency_ms: round3(mean_latency),
            p50_latency_ms: round3(p50),
            p95_latency_ms: round3(p95),
            p99_latency_ms: round3(p99),
            client_uplink_kib_per_fetch: round3(agg.client_up_bytes / sample_count / 1024.0),
            client_downlink_kib_per_fetch: round3(agg.client_down_bytes / sample_count / 1024.0),
            infra_total_kib_per_fetch: round3(agg.infra_bytes / sample_count / 1024.0),
            client_cpu_ms_per_fetch: round3(agg.client_cpu_ms / sample_count),
            infra_cpu_ms_per_fetch: round3(agg.infra_cpu_ms / sample_count),
        },
        privacy: Privacy {
            endpoint_exposure_score: round3(endpoint_exposure),
            receiver_interest_exposure_score: round3(receiver_interest_exposure),
            interpretation: privacy_interpretation(strategy).to_string(),
        },
        operational_notes: strategy_notes(strategy),
    }
}

fn strategy_notes(strategy: StrategyKind) -> Vec<String> {
    match strategy {
        StrategyKind::BaselineSplitRetrieval => vec![
            "No extra trust domain; relies on independent relay operators and quorum policy.".to_string(),
            "Client endpoint metadata is still directly exposed to every queried relay.".to_string(),
        ],
        StrategyKind::ProxyFanout => vec![
            "Adds one trusted privacy proxy blast-radius; proxy compromise can re-link clients to receivers.".to_string(),
            "Improves relay-side unlinkability but increases infrastructure complexity and abuse-governance load.".to_string(),
        ],
        StrategyKind::TwoServerPirProxy => vec![
            "Strongest receiver-interest privacy under non-collusion assumption.".to_string(),
            "Current performance/cost envelope is not suitable for always-on mobile polling path.".to_string(),
        ],
    }
}

fn privacy_interpretation(strategy: StrategyKind) -> &'static str {
    match strategy {
        StrategyKind::BaselineSplitRetrieval => {
            "Direct endpoint-to-relay fetch; strongest simplicity, weakest endpoint metadata shielding."
        }
        StrategyKind::ProxyFanout => {
            "Moderate metadata improvement by hiding endpoint from relays, with central proxy trust trade-off."
        }
        StrategyKind::TwoServerPirProxy => {
            "Best theoretical receiver-interest protection, but only if non-colluding servers and high compute budget hold."
        }
    }
}

fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let rank = (p / 100.0) * (values.len().saturating_sub(1) as f64);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        return values[lower];
    }

    let weight = rank - lower as f64;
    values[lower] * (1.0 - weight) + values[upper] * weight
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn build_recommendation(reports: &[StrategyReport]) -> Recommendation {
    let baseline = reports
        .iter()
        .find(|r| r.strategy == "baseline_split_retrieval")
        .expect("baseline strategy missing");
    let proxy = reports
        .iter()
        .find(|r| r.strategy == "proxy_fanout_retrieval")
        .expect("proxy strategy missing");
    let pir = reports
        .iter()
        .find(|r| r.strategy == "two_server_pir_proxy")
        .expect("pir strategy missing");

    Recommendation {
        decision: "NO-GO for mandatory PIR/proxy production rollout now; GO for optional research profile behind explicit operator flag".to_string(),
        rationale: vec![
            format!(
                "Proxy fanout improves endpoint exposure score from {:.3} to {:.3}, but introduces a concentration trust domain.",
                baseline.privacy.endpoint_exposure_score, proxy.privacy.endpoint_exposure_score
            ),
            format!(
                "Two-server PIR candidate reduces receiver-interest exposure to {:.3}, but adds {:.1}x infra CPU and {:.1}x client downlink versus baseline.",
                pir.privacy.receiver_interest_exposure_score,
                pir.metrics.infra_cpu_ms_per_fetch / baseline.metrics.infra_cpu_ms_per_fetch,
                pir.metrics.client_downlink_kib_per_fetch
                    / baseline.metrics.client_downlink_kib_per_fetch
            ),
            format!(
                "PIR availability ({:.3}) materially underperforms baseline ({:.3}) under realistic relay/proxy outage assumptions.",
                pir.metrics.availability_success_rate, baseline.metrics.availability_success_rate
            ),
        ],
        next_steps: vec![
            "Keep current multi-relay split retrieval as default with stronger relay diversity and anti-correlation controls.".to_string(),
            "Prototype proxy fanout only in high-risk mode with strict no-log attestations, jurisdiction split, and external audit before rollout.".to_string(),
            "Revisit PIR if practical latency can stay within +35% p95 and infra CPU within 3x baseline under mobile polling constraints.".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_for_strategy() {
        let a = seed_for_strategy(DEFAULT_SEED, StrategyKind::ProxyFanout);
        let b = seed_for_strategy(DEFAULT_SEED, StrategyKind::ProxyFanout);
        assert_eq!(a, b);
    }

    #[test]
    fn percentile_handles_empty() {
        assert_eq!(percentile(&[], 95.0), 0.0);
    }

    #[test]
    fn report_contains_three_strategies() {
        let cfg = SimConfig::default();
        let mut reports = Vec::new();
        for strategy in StrategyKind::all() {
            let aggregate = run_strategy(strategy, cfg, DEFAULT_SEED, 2000);
            reports.push(materialize_strategy_report(strategy, aggregate));
        }
        assert_eq!(reports.len(), 3);
    }
}
