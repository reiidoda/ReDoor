use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::cmp;

type HmacSha256 = Hmac<Sha256>;

const CLASSICAL_STEP_INFO: &[u8] = b"pq-ratchet-classical-step-v1";
const PQ_MIX_INFO: &[u8] = b"pq-ratchet-pq-mix-v1";
const MESSAGE_KEY_INFO: &[u8] = b"pq-ratchet-message-key-v1";
const BASELINE_STATE_BYTES: usize = 64; // root key + chain key

fn hmac32(key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| anyhow!("invalid hmac key"))?;
    for chunk in chunks {
        mac.update(chunk);
    }
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(result.as_slice());
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct PqRatchetState {
    root_key: [u8; 32],
    chain_key: [u8; 32],
    pub step: u32,
    pub pq_mix_count: u32,
}

impl PqRatchetState {
    pub fn new(initial_secret: [u8; 32]) -> Self {
        Self {
            root_key: initial_secret,
            chain_key: initial_secret,
            step: 0,
            pq_mix_count: 0,
        }
    }

    pub fn apply_pq_mix(&mut self, pq_secret: &[u8]) -> Result<()> {
        if pq_secret.is_empty() {
            return Err(anyhow!("pq secret cannot be empty"));
        }

        let step_bytes = self.step.to_le_bytes();
        let next_root = hmac32(&self.root_key, &[PQ_MIX_INFO, &step_bytes, pq_secret])?;
        let next_chain = hmac32(&self.chain_key, &[PQ_MIX_INFO, &step_bytes, &next_root])?;
        self.root_key = next_root;
        self.chain_key = next_chain;
        self.pq_mix_count = self.pq_mix_count.saturating_add(1);
        Ok(())
    }

    pub fn step_classical(&mut self) -> Result<[u8; 32]> {
        let step_bytes = self.step.to_le_bytes();
        let next_chain = hmac32(&self.chain_key, &[CLASSICAL_STEP_INFO, &step_bytes])?;
        let next_root = hmac32(&self.root_key, &[CLASSICAL_STEP_INFO, &next_chain])?;
        let message_key = hmac32(&next_chain, &[MESSAGE_KEY_INFO, &step_bytes])?;
        self.chain_key = next_chain;
        self.root_key = next_root;
        self.step = self.step.saturating_add(1);
        Ok(message_key)
    }

    pub fn state_size_bytes(&self) -> usize {
        32 + 32 + 4 + 4
    }

    pub fn state_overhead_bytes(&self) -> usize {
        self.state_size_bytes().saturating_sub(BASELINE_STATE_BYTES)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverySample {
    pub compromise_step: u32,
    pub recovery_after_steps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverySimulationSummary {
    pub total_steps: u32,
    pub pq_interval: u32,
    pub compromise_samples: usize,
    pub average_recovery_steps: f64,
    pub p95_recovery_steps: u32,
    pub max_recovery_steps: u32,
    pub total_pq_mixes: u32,
    pub state_size_bytes: usize,
    pub state_overhead_bytes: usize,
    pub samples: Vec<RecoverySample>,
}

fn percentile_95(values: &[u32]) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = cmp::min(
        sorted.len().saturating_sub(1),
        ((sorted.len() as f64) * 0.95).floor() as usize,
    );
    sorted[idx]
}

fn deterministic_pq_secret(seed: u64, step: u32) -> [u8; 32] {
    let mut rng = StdRng::seed_from_u64(seed ^ ((step as u64) << 32) ^ 0xA11C_E11D_u64);
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    out
}

pub fn simulate_post_compromise_recovery(
    seed: u64,
    total_steps: u32,
    pq_interval: u32,
    compromise_steps: &[u32],
) -> Result<RecoverySimulationSummary> {
    if total_steps == 0 {
        return Err(anyhow!("total_steps must be > 0"));
    }
    if pq_interval == 0 {
        return Err(anyhow!("pq_interval must be > 0"));
    }

    let mut base_seed = [0u8; 32];
    base_seed[..8].copy_from_slice(&seed.to_le_bytes());

    let mut samples = Vec::new();
    let mut all_recovery_steps = Vec::new();
    let mut total_pq_mixes: u32 = 0;
    let mut state_size_bytes = 0usize;
    let mut state_overhead_bytes = 0usize;

    for compromise_step in compromise_steps {
        if *compromise_step >= total_steps.saturating_sub(1) {
            continue;
        }

        let mut victim = PqRatchetState::new(base_seed);
        let mut attacker = PqRatchetState::new(base_seed);

        // Run until compromise point with identical knowledge.
        for step in 0..=*compromise_step {
            if step % pq_interval == 0 {
                let secret = deterministic_pq_secret(seed, step);
                victim.apply_pq_mix(&secret)?;
                attacker.apply_pq_mix(&secret)?;
            }
            let _ = victim.step_classical()?;
            let _ = attacker.step_classical()?;
        }

        // After compromise, attacker loses access to future PQ secrets.
        let mut recovery_after = total_steps.saturating_sub(*compromise_step);
        for step in (*compromise_step + 1)..total_steps {
            if step % pq_interval == 0 {
                let victim_secret = deterministic_pq_secret(seed, step);
                victim.apply_pq_mix(&victim_secret)?;
                let attacker_guess = [0u8; 32];
                attacker.apply_pq_mix(&attacker_guess)?;
            }

            let victim_key = victim.step_classical()?;
            let attacker_key = attacker.step_classical()?;
            if victim_key != attacker_key {
                recovery_after = step.saturating_sub(*compromise_step);
                break;
            }
        }

        total_pq_mixes = total_pq_mixes.saturating_add(victim.pq_mix_count);
        state_size_bytes = victim.state_size_bytes();
        state_overhead_bytes = victim.state_overhead_bytes();
        all_recovery_steps.push(recovery_after);
        samples.push(RecoverySample {
            compromise_step: *compromise_step,
            recovery_after_steps: recovery_after,
        });
    }

    if samples.is_empty() {
        return Err(anyhow!("no valid compromise samples"));
    }

    let average_recovery_steps =
        all_recovery_steps.iter().map(|v| *v as f64).sum::<f64>() / all_recovery_steps.len() as f64;
    let p95_recovery_steps = percentile_95(&all_recovery_steps);
    let max_recovery_steps = *all_recovery_steps.iter().max().unwrap_or(&0);

    Ok(RecoverySimulationSummary {
        total_steps,
        pq_interval,
        compromise_samples: samples.len(),
        average_recovery_steps,
        p95_recovery_steps,
        max_recovery_steps,
        total_pq_mixes,
        state_size_bytes,
        state_overhead_bytes,
        samples,
    })
}

#[cfg(test)]
mod tests {
    use super::{simulate_post_compromise_recovery, PqRatchetState};

    #[test]
    fn state_size_has_bounded_overhead() {
        let state = PqRatchetState::new([3u8; 32]);
        assert_eq!(state.state_size_bytes(), 72);
        assert_eq!(state.state_overhead_bytes(), 8);
    }

    #[test]
    fn recovery_happens_within_interval_bound() {
        let summary =
            simulate_post_compromise_recovery(0xA11C_E11D, 512, 16, &[32, 64, 80, 120, 255, 300])
                .expect("simulate");

        assert!(summary.max_recovery_steps <= 16);
        assert!(summary.average_recovery_steps > 0.0);
    }

    #[test]
    fn simulation_is_deterministic_for_same_seed() {
        let first =
            simulate_post_compromise_recovery(4242, 512, 32, &[32, 128, 256]).expect("first");
        let second =
            simulate_post_compromise_recovery(4242, 512, 32, &[32, 128, 256]).expect("second");
        assert_eq!(first.p95_recovery_steps, second.p95_recovery_steps);
        assert_eq!(first.max_recovery_steps, second.max_recovery_steps);
        assert_eq!(first.samples, second.samples);
    }
}
