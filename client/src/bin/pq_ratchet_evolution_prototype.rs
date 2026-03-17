use anyhow::Result;
use redoor_client::ratchet::pq_evolution::simulate_post_compromise_recovery;
use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
struct IntervalBenchmark {
    pq_interval: u32,
    compromise_samples: usize,
    average_recovery_steps: f64,
    p95_recovery_steps: u32,
    max_recovery_steps: u32,
    total_pq_mixes: u32,
    state_size_bytes: usize,
    state_overhead_bytes: usize,
    elapsed_ms: u128,
    ns_per_simulated_step: f64,
}

#[derive(Debug, Serialize)]
struct PqRatchetEvolutionReport {
    report_id: &'static str,
    generated_at_unix: u64,
    seed: u64,
    total_steps: u32,
    compromise_schedule: Vec<u32>,
    intervals: Vec<IntervalBenchmark>,
    recommended_interval: u32,
    recommendation: String,
}

fn parse_output_path(args: &[String]) -> PathBuf {
    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--output" && idx + 1 < args.len() {
            return PathBuf::from(args[idx + 1].clone());
        }
        idx += 1;
    }
    PathBuf::from("docs/security/pq-ratchet-evolution-report.v1.json")
}

fn default_compromise_schedule(total_steps: u32) -> Vec<u32> {
    vec![
        total_steps / 16,
        total_steps / 8,
        total_steps / 6,
        total_steps / 4,
        total_steps / 3,
        total_steps / 2,
        (total_steps * 2) / 3,
        (total_steps * 3) / 4,
    ]
}

fn choose_recommended_interval(results: &[IntervalBenchmark]) -> u32 {
    if let Some(candidate) = results
        .iter()
        .filter(|row| row.p95_recovery_steps <= 16)
        .max_by_key(|row| row.pq_interval)
    {
        return candidate.pq_interval;
    }

    results
        .iter()
        .min_by_key(|row| (row.p95_recovery_steps, row.pq_interval))
        .map(|row| row.pq_interval)
        .unwrap_or(16)
}

fn build_recommendation(interval: u32) -> String {
    format!(
        "Prototype recommendation: start with pq_interval={interval} for staged rollout. \
Require explicit telemetry in pre-production and promote to default only after external \
crypto review confirms acceptable overhead and recovery guarantees."
    )
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let output = parse_output_path(&args);

    let seed: u64 = 0xA11C_E11D_1630_0001;
    let total_steps: u32 = 4096;
    let compromise_schedule = default_compromise_schedule(total_steps);
    let intervals = [4u32, 8, 16, 24, 32, 48, 64];

    let mut results = Vec::new();
    for pq_interval in intervals {
        let start = Instant::now();
        let summary = simulate_post_compromise_recovery(
            seed,
            total_steps,
            pq_interval,
            &compromise_schedule,
        )?;
        let elapsed = start.elapsed();
        let simulated_steps = (summary.total_steps as u128) * (summary.compromise_samples as u128);
        let ns_per_step = if simulated_steps == 0 {
            0.0
        } else {
            elapsed.as_nanos() as f64 / simulated_steps as f64
        };

        results.push(IntervalBenchmark {
            pq_interval,
            compromise_samples: summary.compromise_samples,
            average_recovery_steps: summary.average_recovery_steps,
            p95_recovery_steps: summary.p95_recovery_steps,
            max_recovery_steps: summary.max_recovery_steps,
            total_pq_mixes: summary.total_pq_mixes,
            state_size_bytes: summary.state_size_bytes,
            state_overhead_bytes: summary.state_overhead_bytes,
            elapsed_ms: elapsed.as_millis(),
            ns_per_simulated_step: ns_per_step,
        });
    }

    let recommended_interval = choose_recommended_interval(&results);
    let generated_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = PqRatchetEvolutionReport {
        report_id: "pq_ratchet_evolution_prototype.v1",
        generated_at_unix,
        seed,
        total_steps,
        compromise_schedule: compromise_schedule.clone(),
        intervals: results,
        recommended_interval,
        recommendation: build_recommendation(recommended_interval),
    };

    let body = serde_json::to_string_pretty(&report)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, body)?;

    println!("{}", output.display());
    Ok(())
}
