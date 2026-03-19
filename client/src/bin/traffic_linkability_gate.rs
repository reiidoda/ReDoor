use anyhow::{anyhow, Context, Result};
use redoor_client::diagnostics::{
    evaluate_traffic_analysis_regression, run_traffic_analysis_simulator, TrafficAnonymityBaseline,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
struct CliOptions {
    baseline_path: PathBuf,
    report_path: PathBuf,
    evaluation_path: PathBuf,
    seed_override: Option<u64>,
}

fn usage() -> &'static str {
    "usage: traffic_linkability_gate --baseline <path> --report <path> --evaluation <path> [--seed <u64>]"
}

fn parse_args() -> Result<CliOptions> {
    let mut args = std::env::args().skip(1);
    let mut baseline_path = None;
    let mut report_path = None;
    let mut evaluation_path = None;
    let mut seed_override = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--baseline" => baseline_path = args.next().map(PathBuf::from),
            "--report" => report_path = args.next().map(PathBuf::from),
            "--evaluation" => evaluation_path = args.next().map(PathBuf::from),
            "--seed" => {
                seed_override = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing value for --seed"))?
                        .parse::<u64>()
                        .context("invalid value for --seed")?,
                )
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => return Err(anyhow!("unknown argument: {arg}\n{}", usage())),
        }
    }

    Ok(CliOptions {
        baseline_path: baseline_path.ok_or_else(|| anyhow!("--baseline is required"))?,
        report_path: report_path.ok_or_else(|| anyhow!("--report is required"))?,
        evaluation_path: evaluation_path.ok_or_else(|| anyhow!("--evaluation is required"))?,
        seed_override,
    })
}

fn write_json_file(path: &Path, json: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create artifact directory {}", parent.display()))?;
    }
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn main() -> Result<()> {
    let opts = parse_args()?;
    let baseline_json = fs::read_to_string(&opts.baseline_path)
        .with_context(|| format!("read baseline {}", opts.baseline_path.display()))?;
    let baseline: TrafficAnonymityBaseline =
        serde_json::from_str(&baseline_json).context("parse baseline JSON")?;

    let seed = opts.seed_override.unwrap_or(baseline.seed);
    let report = run_traffic_analysis_simulator(seed);
    let report_json = serde_json::to_string_pretty(&report).context("encode report JSON")?;
    write_json_file(&opts.report_path, &report_json)?;

    let mut evaluation = evaluate_traffic_analysis_regression(&report, &baseline);
    let allow_override = env_truthy("REDOOR_ALLOW_ANONYMITY_REGRESSION");
    let override_reason = std::env::var("REDOOR_ANONYMITY_OVERRIDE_REASON")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if !evaluation.checks_passed && allow_override {
        evaluation.override_applied = true;
        evaluation.override_reason = override_reason.clone();
        evaluation
            .violations
            .push("Regression override applied by REDOOR_ALLOW_ANONYMITY_REGRESSION.".to_string());
    } else {
        evaluation.override_reason = override_reason;
    }

    let evaluation_json =
        serde_json::to_string_pretty(&evaluation).context("encode evaluation JSON")?;
    write_json_file(&opts.evaluation_path, &evaluation_json)?;

    println!(
        "traffic-linkability report: {}",
        opts.report_path.as_path().display()
    );
    println!(
        "traffic-linkability evaluation: {}",
        opts.evaluation_path.as_path().display()
    );
    println!(
        "weighted_top1_linkability={:.6}, regression_delta={:.6}, unresolved_rate={:.6}, sample={}",
        evaluation.weighted_top1_linkability,
        evaluation.weighted_top1_regression_delta,
        evaluation.total_unresolved_rate,
        evaluation.total_delivered_real_messages
    );

    if evaluation.checks_passed || evaluation.override_applied {
        if evaluation.override_applied {
            eprintln!(
                "WARNING: anonymity regression override applied (reason: {}).",
                evaluation
                    .override_reason
                    .as_deref()
                    .unwrap_or("unspecified")
            );
        }
        return Ok(());
    }

    for violation in &evaluation.violations {
        eprintln!("violation: {violation}");
    }
    Err(anyhow!(
        "traffic linkability regression gate failed ({} violation(s))",
        evaluation.violations.len()
    ))
}
