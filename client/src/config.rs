use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};

// --- PQ Config ---
static PQ_ENABLED: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqHandshakePolicy {
    Prefer,
    Required,
    Disabled,
}

static PQ_HANDSHAKE_POLICY_OVERRIDE: OnceLock<RwLock<Option<PqHandshakePolicy>>> = OnceLock::new();
static PROTOCOL_VERSION_OVERRIDE: OnceLock<RwLock<Option<u16>>> = OnceLock::new();
static PROTOCOL_MIN_ACCEPTED_VERSION_OVERRIDE: OnceLock<RwLock<Option<u16>>> = OnceLock::new();

// --- Proxy Config ---
static PROXY_URL: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static PROXY_AUTH: OnceLock<RwLock<Option<(String, String)>>> = OnceLock::new();

// --- Relay TLS Pinning Config ---
static RELAY_CA_B64: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static RELAY_SPKI_PIN_B64: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static DIRECTORY_SIGNING_PUBKEY_HEX: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static MEMORY_HARDENING_ACTIVE: AtomicBool = AtomicBool::new(false);
static MEMORY_HARDENING_REQUIRED: AtomicBool = AtomicBool::new(false);
static MEMORY_HARDENING_LAST_ERROR: OnceLock<RwLock<Option<String>>> = OnceLock::new();

pub const DEFAULT_RELAY_URL: &str = "https://localhost:8443";
pub const DEFAULT_BLOCKCHAIN_URL: &str = "http://127.0.0.1:9444";
pub const DEFAULT_DIRECTORY_URL: &str = "http://localhost:7070";
const DEFAULT_SECURE_BLOCKCHAIN_BATCH_MS: u64 = 5000;
const DEFAULT_SECURE_BLOCKCHAIN_BATCH_JITTER_PCT: u64 = 35;
const DEFAULT_SECURE_BLOCKCHAIN_DECOY_COUNT: usize = 0;
const DEFAULT_COMMITMENT_AUTH_THRESHOLD: u8 = 1;
const DEFAULT_PROTOCOL_VERSION_CURRENT: u16 = 2;
const DEFAULT_PROTOCOL_MIN_ACCEPTED_VERSION: u16 = 1;
const DEFAULT_FORCED_REKEY_AFTER_MESSAGES: u64 = 512;
const DEFAULT_FORCED_REKEY_AFTER_SECS: u64 = 6 * 60 * 60;
const DEFAULT_PQ_RATCHET_INTERVAL_MESSAGES: u64 = 32;

// --- Traffic Shaping Config ---
#[derive(Clone, Copy, Debug)]
pub struct TrafficShapingConfig {
    pub pad_to: usize,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for TrafficShapingConfig {
    fn default() -> Self {
        Self {
            pad_to: 0, // No padding by default
            min_delay_ms: 0,
            max_delay_ms: 0,
        }
    }
}

static TRAFFIC_SHAPING_CONFIG: OnceLock<RwLock<TrafficShapingConfig>> = OnceLock::new();

static INIT: OnceLock<()> = OnceLock::new();

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let normalized = v.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(default)
}

fn env_u16(name: &str, default: u16, min: u16, max: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

pub fn init_from_env() {
    INIT.get_or_init(|| {
        if let Ok(val) = std::env::var("REDOOR_PQ") {
            let enabled = val != "0" && val.to_lowercase() != "false";
            PQ_ENABLED.store(enabled, Ordering::Relaxed);
        }
    });
}

#[allow(dead_code)]
pub fn set_pq_enabled(enabled: bool) {
    PQ_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn pq_enabled() -> bool {
    init_from_env();
    PQ_ENABLED.load(Ordering::Relaxed)
}

pub fn pq_handshake_policy() -> PqHandshakePolicy {
    let lock = PQ_HANDSHAKE_POLICY_OVERRIDE.get_or_init(|| RwLock::new(None));
    if let Some(policy) = *lock.read().unwrap() {
        return policy;
    }

    std::env::var("REDOOR_PQ_HANDSHAKE_POLICY")
        .ok()
        .as_deref()
        .and_then(parse_pq_handshake_policy)
        .unwrap_or(PqHandshakePolicy::Prefer)
}

pub fn parse_pq_handshake_policy(raw: &str) -> Option<PqHandshakePolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "prefer" | "preferred" | "default" | "auto" => Some(PqHandshakePolicy::Prefer),
        "required" | "require" | "strict" => Some(PqHandshakePolicy::Required),
        "disabled" | "disable" | "off" | "false" | "0" => Some(PqHandshakePolicy::Disabled),
        _ => None,
    }
}

pub fn pq_handshake_policy_as_str(policy: PqHandshakePolicy) -> &'static str {
    match policy {
        PqHandshakePolicy::Prefer => "prefer",
        PqHandshakePolicy::Required => "required",
        PqHandshakePolicy::Disabled => "disabled",
    }
}

pub fn set_pq_handshake_policy_override(policy: Option<PqHandshakePolicy>) {
    let lock = PQ_HANDSHAKE_POLICY_OVERRIDE.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = policy;
}

#[allow(dead_code)]
pub fn set_proxy(url: Option<String>) {
    let lock = PROXY_URL.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = url;
}

pub fn get_proxy() -> Option<String> {
    let lock = PROXY_URL.get_or_init(|| RwLock::new(None));
    let r = lock.read().unwrap();
    r.clone()
}

#[allow(dead_code)]
pub fn set_proxy_auth(auth: Option<(String, String)>) {
    let lock = PROXY_AUTH.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = auth;
}

pub fn get_proxy_auth() -> Option<(String, String)> {
    let lock = PROXY_AUTH.get_or_init(|| RwLock::new(None));
    let r = lock.read().unwrap();
    r.clone()
}

pub fn default_relay_url() -> String {
    std::env::var("REDOOR_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string())
}

pub fn default_blockchain_url() -> String {
    std::env::var("REDOOR_BLOCKCHAIN_URL").unwrap_or_else(|_| DEFAULT_BLOCKCHAIN_URL.to_string())
}

pub fn blockchain_commitment_delegate_url() -> Option<String> {
    std::env::var("REDOOR_COMMITMENT_DELEGATE_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
}

pub fn blockchain_commitment_delegate_required() -> bool {
    env_bool("REDOOR_COMMITMENT_DELEGATE_REQUIRED", false)
}

pub fn blockchain_commitment_auth_threshold() -> u8 {
    std::env::var("REDOOR_COMMITMENT_AUTH_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.clamp(1, 32))
        .unwrap_or(DEFAULT_COMMITMENT_AUTH_THRESHOLD)
}

pub fn blockchain_commitment_cosigner_secrets_hex() -> Option<String> {
    std::env::var("REDOOR_COMMITMENT_COSIGNER_SECRETS_HEX")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn secure_mode_enabled() -> bool {
    env_bool("REDOOR_SECURE_MODE", false)
}

pub fn set_memory_hardening_required(required: bool) {
    MEMORY_HARDENING_REQUIRED.store(required, Ordering::Relaxed);
}

pub fn memory_hardening_required() -> bool {
    MEMORY_HARDENING_REQUIRED.load(Ordering::Relaxed)
}

pub fn set_memory_hardening_status(active: bool, last_error: Option<String>) {
    MEMORY_HARDENING_ACTIVE.store(active, Ordering::Relaxed);
    let lock = MEMORY_HARDENING_LAST_ERROR.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = last_error;
}

pub fn memory_hardening_active() -> bool {
    MEMORY_HARDENING_ACTIVE.load(Ordering::Relaxed)
}

pub fn memory_hardening_last_error() -> Option<String> {
    let lock = MEMORY_HARDENING_LAST_ERROR.get_or_init(|| RwLock::new(None));
    let r = lock.read().unwrap();
    r.clone()
}

pub fn blockchain_batch_interval_ms() -> u64 {
    std::env::var("REDOOR_SECURE_BLOCKCHAIN_BATCH_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_SECURE_BLOCKCHAIN_BATCH_MS)
}

pub fn blockchain_batch_jitter_pct() -> u64 {
    std::env::var("REDOOR_SECURE_BLOCKCHAIN_BATCH_JITTER_PCT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.min(200))
        .unwrap_or(DEFAULT_SECURE_BLOCKCHAIN_BATCH_JITTER_PCT)
}

pub fn blockchain_batch_decoy_count() -> usize {
    std::env::var("REDOOR_SECURE_BLOCKCHAIN_BATCH_DECOY_COUNT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.min(32))
        .unwrap_or(DEFAULT_SECURE_BLOCKCHAIN_DECOY_COUNT)
}

pub fn blockchain_batch_scheduler_seed() -> Option<u64> {
    std::env::var("REDOOR_SECURE_BLOCKCHAIN_BATCH_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
}

pub fn blockchain_batch_per_message_fallback() -> bool {
    std::env::var("REDOOR_BLOCKCHAIN_PER_MESSAGE_FALLBACK")
        .ok()
        .map(|v| {
            let normalized = v.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

pub fn default_directory_url() -> String {
    std::env::var("REDOOR_DIRECTORY_URL").unwrap_or_else(|_| DEFAULT_DIRECTORY_URL.to_string())
}

pub fn prekey_low_watermark() -> usize {
    std::env::var("REDOOR_PREKEY_LOW_WATERMARK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5)
}

pub fn prekey_target_count() -> usize {
    std::env::var("REDOOR_PREKEY_TARGET_COUNT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20)
}

pub fn signed_prekey_rotate_interval_secs() -> u64 {
    std::env::var("REDOOR_SIGNED_PREKEY_ROTATE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(7 * 24 * 60 * 60)
}

pub fn protocol_version_current() -> u16 {
    let lock = PROTOCOL_VERSION_OVERRIDE.get_or_init(|| RwLock::new(None));
    if let Some(version) = *lock.read().unwrap() {
        return version;
    }
    env_u16(
        "REDOOR_PROTOCOL_VERSION",
        DEFAULT_PROTOCOL_VERSION_CURRENT,
        1,
        u16::MAX,
    )
}

pub fn protocol_min_accepted_version() -> u16 {
    let lock = PROTOCOL_MIN_ACCEPTED_VERSION_OVERRIDE.get_or_init(|| RwLock::new(None));
    if let Some(version) = *lock.read().unwrap() {
        return version;
    }
    let current = protocol_version_current();
    env_u16(
        "REDOOR_PROTOCOL_MIN_ACCEPTED_VERSION",
        DEFAULT_PROTOCOL_MIN_ACCEPTED_VERSION,
        1,
        current,
    )
}

pub fn set_protocol_version_override(version: Option<u16>) {
    let lock = PROTOCOL_VERSION_OVERRIDE.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = version;
}

pub fn set_protocol_min_accepted_version_override(version: Option<u16>) {
    let lock = PROTOCOL_MIN_ACCEPTED_VERSION_OVERRIDE.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = version;
}

pub fn forced_rekey_after_messages() -> u64 {
    std::env::var("REDOOR_FORCE_REKEY_AFTER_MESSAGES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_FORCED_REKEY_AFTER_MESSAGES)
}

pub fn forced_rekey_after_secs() -> u64 {
    std::env::var("REDOOR_FORCE_REKEY_AFTER_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_FORCED_REKEY_AFTER_SECS)
}

pub fn pq_ratchet_interval_messages() -> u64 {
    std::env::var("REDOOR_PQ_RATCHET_INTERVAL_MESSAGES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_PQ_RATCHET_INTERVAL_MESSAGES)
}

pub fn mixnet_allow_direct_fallback() -> bool {
    env_bool("REDOOR_MIXNET_ALLOW_DIRECT_FALLBACK", false)
}

#[allow(dead_code)]
pub fn set_relay_ca_b64(ca_b64: Option<String>) {
    let lock = RELAY_CA_B64.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = ca_b64;
}

pub fn get_relay_ca_b64() -> Option<String> {
    let lock = RELAY_CA_B64.get_or_init(|| RwLock::new(None));
    let r = lock.read().unwrap();
    if r.is_some() {
        return r.clone();
    }
    std::env::var("RELAY_CA_B64").ok()
}

#[allow(dead_code)]
pub fn set_relay_spki_pin_b64(pin_b64: Option<String>) {
    let lock = RELAY_SPKI_PIN_B64.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = pin_b64;
}

pub fn get_relay_spki_pin_b64() -> Option<String> {
    let lock = RELAY_SPKI_PIN_B64.get_or_init(|| RwLock::new(None));
    let r = lock.read().unwrap();
    if r.is_some() {
        return r.clone();
    }
    std::env::var("RELAY_PINNED_CERT_HASH").ok()
}

#[allow(dead_code)]
pub fn set_directory_signing_pubkey_hex(pubkey_hex: Option<String>) {
    let lock = DIRECTORY_SIGNING_PUBKEY_HEX.get_or_init(|| RwLock::new(None));
    let mut w = lock.write().unwrap();
    *w = pubkey_hex;
}

pub fn get_directory_signing_pubkey_hex() -> Option<String> {
    let lock = DIRECTORY_SIGNING_PUBKEY_HEX.get_or_init(|| RwLock::new(None));
    let r = lock.read().unwrap();
    if r.is_some() {
        return r.clone();
    }
    std::env::var("DIRECTORY_SIGNING_PUBKEY_HEX").ok()
}

pub fn set_traffic_shaping(config: TrafficShapingConfig) {
    let lock = TRAFFIC_SHAPING_CONFIG.get_or_init(|| RwLock::new(TrafficShapingConfig::default()));
    let mut w = lock.write().unwrap();
    *w = config;
}

pub fn get_traffic_shaping() -> TrafficShapingConfig {
    let lock = TRAFFIC_SHAPING_CONFIG.get_or_init(|| RwLock::new(TrafficShapingConfig::default()));
    let r = lock.read().unwrap();
    *r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_handshake_policy_parser_supports_aliases() {
        assert_eq!(
            parse_pq_handshake_policy("required"),
            Some(PqHandshakePolicy::Required)
        );
        assert_eq!(
            parse_pq_handshake_policy("strict"),
            Some(PqHandshakePolicy::Required)
        );
        assert_eq!(
            parse_pq_handshake_policy("disabled"),
            Some(PqHandshakePolicy::Disabled)
        );
        assert_eq!(
            parse_pq_handshake_policy("off"),
            Some(PqHandshakePolicy::Disabled)
        );
        assert_eq!(
            parse_pq_handshake_policy("prefer"),
            Some(PqHandshakePolicy::Prefer)
        );
        assert_eq!(parse_pq_handshake_policy("unknown"), None);
    }

    #[test]
    fn pq_handshake_policy_override_takes_precedence() {
        let prev = std::env::var("REDOOR_PQ_HANDSHAKE_POLICY").ok();
        std::env::set_var("REDOOR_PQ_HANDSHAKE_POLICY", "disabled");
        set_pq_handshake_policy_override(Some(PqHandshakePolicy::Required));
        assert_eq!(pq_handshake_policy(), PqHandshakePolicy::Required);

        set_pq_handshake_policy_override(None);
        assert_eq!(pq_handshake_policy(), PqHandshakePolicy::Disabled);

        if let Some(value) = prev {
            std::env::set_var("REDOOR_PQ_HANDSHAKE_POLICY", value);
        } else {
            std::env::remove_var("REDOOR_PQ_HANDSHAKE_POLICY");
        }
    }

    #[test]
    fn protocol_version_policy_bounds_values() {
        set_protocol_version_override(None);
        set_protocol_min_accepted_version_override(None);
        let prev_current = std::env::var("REDOOR_PROTOCOL_VERSION").ok();
        let prev_min = std::env::var("REDOOR_PROTOCOL_MIN_ACCEPTED_VERSION").ok();

        std::env::set_var("REDOOR_PROTOCOL_VERSION", "3");
        std::env::set_var("REDOOR_PROTOCOL_MIN_ACCEPTED_VERSION", "9");
        assert_eq!(protocol_version_current(), 3);
        assert_eq!(
            protocol_min_accepted_version(),
            3,
            "min accepted version must clamp to current version"
        );

        if let Some(value) = prev_current {
            std::env::set_var("REDOOR_PROTOCOL_VERSION", value);
        } else {
            std::env::remove_var("REDOOR_PROTOCOL_VERSION");
        }
        if let Some(value) = prev_min {
            std::env::set_var("REDOOR_PROTOCOL_MIN_ACCEPTED_VERSION", value);
        } else {
            std::env::remove_var("REDOOR_PROTOCOL_MIN_ACCEPTED_VERSION");
        }
        set_protocol_version_override(None);
        set_protocol_min_accepted_version_override(None);
    }

    #[test]
    fn forced_rekey_policy_uses_positive_values() {
        let prev_msg = std::env::var("REDOOR_FORCE_REKEY_AFTER_MESSAGES").ok();
        let prev_secs = std::env::var("REDOOR_FORCE_REKEY_AFTER_SECS").ok();
        let prev_interval = std::env::var("REDOOR_PQ_RATCHET_INTERVAL_MESSAGES").ok();

        std::env::set_var("REDOOR_FORCE_REKEY_AFTER_MESSAGES", "0");
        std::env::set_var("REDOOR_FORCE_REKEY_AFTER_SECS", "0");
        std::env::set_var("REDOOR_PQ_RATCHET_INTERVAL_MESSAGES", "0");
        assert!(forced_rekey_after_messages() > 0);
        assert!(forced_rekey_after_secs() > 0);
        assert!(pq_ratchet_interval_messages() > 0);

        std::env::set_var("REDOOR_FORCE_REKEY_AFTER_MESSAGES", "2048");
        std::env::set_var("REDOOR_FORCE_REKEY_AFTER_SECS", "7200");
        std::env::set_var("REDOOR_PQ_RATCHET_INTERVAL_MESSAGES", "64");
        assert_eq!(forced_rekey_after_messages(), 2048);
        assert_eq!(forced_rekey_after_secs(), 7200);
        assert_eq!(pq_ratchet_interval_messages(), 64);

        if let Some(value) = prev_msg {
            std::env::set_var("REDOOR_FORCE_REKEY_AFTER_MESSAGES", value);
        } else {
            std::env::remove_var("REDOOR_FORCE_REKEY_AFTER_MESSAGES");
        }
        if let Some(value) = prev_secs {
            std::env::set_var("REDOOR_FORCE_REKEY_AFTER_SECS", value);
        } else {
            std::env::remove_var("REDOOR_FORCE_REKEY_AFTER_SECS");
        }
        if let Some(value) = prev_interval {
            std::env::set_var("REDOOR_PQ_RATCHET_INTERVAL_MESSAGES", value);
        } else {
            std::env::remove_var("REDOOR_PQ_RATCHET_INTERVAL_MESSAGES");
        }
    }

    #[test]
    fn mixnet_direct_fallback_defaults_to_disabled() {
        let previous = std::env::var("REDOOR_MIXNET_ALLOW_DIRECT_FALLBACK").ok();

        std::env::remove_var("REDOOR_MIXNET_ALLOW_DIRECT_FALLBACK");
        assert!(!mixnet_allow_direct_fallback());

        std::env::set_var("REDOOR_MIXNET_ALLOW_DIRECT_FALLBACK", "true");
        assert!(mixnet_allow_direct_fallback());

        if let Some(value) = previous {
            std::env::set_var("REDOOR_MIXNET_ALLOW_DIRECT_FALLBACK", value);
        } else {
            std::env::remove_var("REDOOR_MIXNET_ALLOW_DIRECT_FALLBACK");
        }
    }
}
