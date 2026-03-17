use crate::blockchain_client::verify_blockchain::BlockchainClient;
use crate::config;
use crate::crypto::ed25519::IdentityKey;
use crate::crypto::x3dh::{InitialMessage, PrekeySecrets};
use crate::network::directory::DirectoryClient;
use crate::network::onion::{MixnetConfig, OnionRouter};
use crate::network::p2p::P2PClient;
use crate::network::relay::RelayClient;
use crate::orchestrator;
use crate::ratchet::double_ratchet::RatchetSession;
use base64::Engine as _;
#[cfg(feature = "pq")]
use pqcrypto_kyber::kyber1024;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_log_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

fn redact_for_log(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::with_capacity(message.len());
    let mut i = 0;

    while i < chars.len() {
        if is_log_token_char(chars[i]) {
            let start = i;
            let mut has_alpha = false;
            let mut has_digit = false;
            while i < chars.len() && is_log_token_char(chars[i]) {
                has_alpha |= chars[i].is_ascii_alphabetic();
                has_digit |= chars[i].is_ascii_digit();
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            if token.len() >= 16 && has_alpha && has_digit {
                let hash = crate::crypto::blake3::hash(token.as_bytes());
                let digest = hex::encode(hash);
                out.push_str("<redacted:");
                out.push_str(&digest[..12]);
                out.push('>');
            } else {
                out.push_str(&token);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }

    out
}

const MAX_UNTRUSTED_ENVELOPE_BLOB_BYTES: usize = 256 * 1024;
const MAX_UNTRUSTED_ENVELOPE_CIPHERTEXT_BYTES: usize = 192 * 1024;
const MAX_UNTRUSTED_INNER_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_UNTRUSTED_MESSAGE_CONTENT_BYTES: usize = 16 * 1024;
const MAX_UNTRUSTED_SIGNATURE_BYTES: usize = 512;
const MAX_UNTRUSTED_SENDER_ID_BYTES: usize = 128;
const MAX_UNTRUSTED_MAILBOX_ID_BYTES: usize = 192;
const MAX_UNTRUSTED_GROUP_ID_BYTES: usize = 128;
const MAX_UNTRUSTED_MSG_TYPE_BYTES: usize = 32;
const MAX_UNTRUSTED_INITIAL_BLOB_BYTES: usize = 64 * 1024;
const MAX_UNTRUSTED_INITIAL_CIPHERTEXT_BYTES: usize = 8 * 1024;
const MAX_UNTRUSTED_PQ_CIPHERTEXT_BYTES: usize = 8 * 1024;
const ALLOWED_UNTRUSTED_MSG_TYPES: [&str; 3] = ["text", "system", "cover"];
const MAX_UNTRUSTED_JSON_NUMBER_DIGITS: usize = 20;
const MAX_UNTRUSTED_JSON_DEPTH_ENVELOPE: usize = 12;
const MAX_UNTRUSTED_JSON_TOKENS_ENVELOPE: usize = 90_000;
const MAX_UNTRUSTED_JSON_DEPTH_INNER: usize = 8;
const MAX_UNTRUSTED_JSON_TOKENS_INNER: usize = 16_000;
const MAX_UNTRUSTED_JSON_DEPTH_INITIAL: usize = 10;
const MAX_UNTRUSTED_JSON_TOKENS_INITIAL: usize = 40_000;
const PARSER_CLASS_ALLOWLIST_ENV: &str = "REDOOR_UNTRUSTED_PARSER_CLASS_ALLOWLIST";
const DEFAULT_PARSER_CLASS_ALLOWLIST: &str =
    "envelope_json,inner_payload_json,initial_message_json";
const UNTRUSTED_PARSER_WORKER_ARG: &str = "untrusted-parser-worker";
const DEFAULT_UNTRUSTED_PARSER_WORKER_TIMEOUT_MS: u64 = 750;
const DEFAULT_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES: usize = MAX_UNTRUSTED_ENVELOPE_BLOB_BYTES;

pub const FUZZ_CLASS_DROPPED_BLOB_SIZE: u8 = 0;
pub const FUZZ_CLASS_DROPPED_ENVELOPE_PARSE: u8 = 1;
pub const FUZZ_CLASS_DROPPED_ENVELOPE_VALIDATION: u8 = 2;
pub const FUZZ_CLASS_ACCEPTED_ENVELOPE: u8 = 3;
pub const FUZZ_CLASS_ACCEPTED_HANDSHAKE: u8 = 4;

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UntrustedParserClass {
    EnvelopeJson,
    InnerPayloadJson,
    InitialMessageJson,
}

fn parser_class_bit(class: UntrustedParserClass) -> u8 {
    match class {
        UntrustedParserClass::EnvelopeJson => 1 << 0,
        UntrustedParserClass::InnerPayloadJson => 1 << 1,
        UntrustedParserClass::InitialMessageJson => 1 << 2,
    }
}

fn parser_class_name(class: UntrustedParserClass) -> &'static str {
    match class {
        UntrustedParserClass::EnvelopeJson => "envelope_json",
        UntrustedParserClass::InnerPayloadJson => "inner_payload_json",
        UntrustedParserClass::InitialMessageJson => "initial_message_json",
    }
}

fn parse_parser_class_allowlist(raw: Option<String>) -> u8 {
    let source = raw.unwrap_or_else(|| DEFAULT_PARSER_CLASS_ALLOWLIST.to_string());
    source
        .split(',')
        .map(|entry| entry.trim().to_ascii_lowercase())
        .fold(0u8, |mut acc, token| {
            match token.as_str() {
                "envelope_json" => acc |= parser_class_bit(UntrustedParserClass::EnvelopeJson),
                "inner_payload_json" => {
                    acc |= parser_class_bit(UntrustedParserClass::InnerPayloadJson)
                }
                "initial_message_json" => {
                    acc |= parser_class_bit(UntrustedParserClass::InitialMessageJson)
                }
                _ => {}
            }
            acc
        })
}

fn format_parser_class_allowlist(mask: u8) -> String {
    let mut classes = Vec::new();
    for class in [
        UntrustedParserClass::EnvelopeJson,
        UntrustedParserClass::InnerPayloadJson,
        UntrustedParserClass::InitialMessageJson,
    ] {
        if (mask & parser_class_bit(class)) != 0 {
            classes.push(parser_class_name(class));
        }
    }
    classes.join(",")
}

fn looks_like_compressed_payload(raw: &[u8]) -> bool {
    raw.starts_with(&[0x1f, 0x8b]) // gzip
        || raw.starts_with(&[0x50, 0x4b, 0x03, 0x04]) // zip
        || raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) // zstd
        || raw.starts_with(&[0x04, 0x22, 0x4d, 0x18]) // lz4 frame
        || raw.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) // xz
}

fn validate_untrusted_json_structure(
    payload: &[u8],
    max_depth: usize,
    max_tokens: usize,
) -> Result<(), &'static str> {
    if looks_like_compressed_payload(payload) {
        return Err("compressed payloads are not supported in parser boundary");
    }

    let text = std::str::from_utf8(payload).map_err(|_| "json payload must be utf-8")?;
    let first_non_ws = text
        .bytes()
        .find(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        .ok_or("empty json payload")?;
    if first_non_ws != b'{' && first_non_ws != b'[' {
        return Err("json payload must start with object or array");
    }

    let mut depth = 0usize;
    let mut tokens = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut numeric_digits = 0usize;

    for b in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match b {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match b {
            b'"' => {
                in_string = true;
                numeric_digits = 0;
            }
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                tokens = tokens.saturating_add(1);
                numeric_digits = 0;
                if depth > max_depth {
                    return Err("json nesting depth exceeded");
                }
            }
            b'}' | b']' => {
                if depth == 0 {
                    return Err("json payload contains unmatched closing token");
                }
                depth -= 1;
                tokens = tokens.saturating_add(1);
                numeric_digits = 0;
            }
            b',' | b':' => {
                tokens = tokens.saturating_add(1);
                numeric_digits = 0;
            }
            b'-' | b'0'..=b'9' => {
                numeric_digits = numeric_digits.saturating_add(1);
                if numeric_digits > MAX_UNTRUSTED_JSON_NUMBER_DIGITS {
                    return Err("json numeric token exceeds digit budget");
                }
            }
            b' ' | b'\n' | b'\r' | b'\t' => {
                numeric_digits = 0;
            }
            _ => {
                numeric_digits = 0;
            }
        }

        if tokens > max_tokens {
            return Err("json structural token budget exceeded");
        }
    }

    if in_string {
        return Err("unterminated string literal");
    }
    if depth != 0 {
        return Err("json payload has unmatched opening token");
    }
    Ok(())
}

fn is_untrusted_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | ':' | '.')
}

fn is_untrusted_token(value: &str, max_len: usize) -> bool {
    let len = value.len();
    len > 0 && len <= max_len && value.chars().all(is_untrusted_token_char)
}

fn is_untrusted_message_type(value: &str) -> bool {
    let len = value.len();
    len > 0
        && len <= MAX_UNTRUSTED_MSG_TYPE_BYTES
        && ALLOWED_UNTRUSTED_MSG_TYPES.contains(&value)
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

fn validate_untrusted_envelope_blob_size(blob_len: usize) -> Result<(), &'static str> {
    if blob_len > MAX_UNTRUSTED_ENVELOPE_BLOB_BYTES {
        return Err("envelope blob exceeds maximum size");
    }
    Ok(())
}

fn validate_untrusted_envelope(env: &Envelope) -> Result<(), &'static str> {
    if !is_untrusted_token(env.mailbox_id.as_str(), MAX_UNTRUSTED_MAILBOX_ID_BYTES) {
        return Err("invalid mailbox_id format");
    }
    if !is_untrusted_token(env.sender_id.as_str(), MAX_UNTRUSTED_SENDER_ID_BYTES) {
        return Err("invalid sender_id format");
    }
    if env.ciphertext.is_empty() {
        return Err("empty envelope ciphertext");
    }
    if env.ciphertext.len() > MAX_UNTRUSTED_ENVELOPE_CIPHERTEXT_BYTES {
        return Err("envelope ciphertext exceeds maximum size");
    }
    Ok(())
}

fn validate_untrusted_inner_payload(
    env: &Envelope,
    inner: &InnerPayload,
    plaintext_len: usize,
) -> Result<(), &'static str> {
    if plaintext_len > MAX_UNTRUSTED_INNER_PAYLOAD_BYTES {
        return Err("inner payload exceeds maximum size");
    }
    if inner.sender_id != env.sender_id {
        return Err("inner payload sender_id mismatch");
    }
    if !is_untrusted_token(inner.sender_id.as_str(), MAX_UNTRUSTED_SENDER_ID_BYTES) {
        return Err("invalid inner sender_id format");
    }
    if !is_untrusted_message_type(inner.msg_type.as_str()) {
        return Err("invalid msg_type format");
    }
    if inner.content.len() > MAX_UNTRUSTED_MESSAGE_CONTENT_BYTES {
        return Err("message content exceeds maximum size");
    }
    if inner.signature.len() > MAX_UNTRUSTED_SIGNATURE_BYTES {
        return Err("signature exceeds maximum size");
    }
    if let Some(group_id) = &inner.group_id {
        if !is_untrusted_token(group_id.as_str(), MAX_UNTRUSTED_GROUP_ID_BYTES) {
            return Err("invalid group_id format");
        }
    }
    Ok(())
}

fn validate_untrusted_initial_message(initial: &InitialMessage) -> Result<(), &'static str> {
    if initial.identity_key.len() != 32 {
        return Err("invalid initial identity_key length");
    }
    if initial.ephemeral_key.len() != 32 {
        return Err("invalid initial ephemeral_key length");
    }
    if let Some(opk) = &initial.one_time_prekey_id {
        if opk.len() != 32 {
            return Err("invalid one_time_prekey_id length");
        }
    }
    if initial.ciphertext.len() > MAX_UNTRUSTED_INITIAL_CIPHERTEXT_BYTES {
        return Err("initial ciphertext exceeds maximum size");
    }
    if let Some(mode) = &initial.handshake_mode {
        if mode != "classic" && mode != "hybrid_kyber1024" {
            return Err("invalid handshake_mode");
        }
    }
    if let Some(version) = initial.protocol_version {
        if version == 0 {
            return Err("invalid protocol_version");
        }
    }
    #[cfg(feature = "pq")]
    if let Some(pq_ct) = &initial.pq_ciphertext {
        if pq_ct.len() > MAX_UNTRUSTED_PQ_CIPHERTEXT_BYTES {
            return Err("pq ciphertext exceeds maximum size");
        }
    }
    Ok(())
}

fn parse_validated_untrusted_envelope(blob: &[u8]) -> Result<Envelope, &'static str> {
    validate_untrusted_envelope_blob_size(blob.len())?;
    validate_untrusted_json_structure(
        blob,
        MAX_UNTRUSTED_JSON_DEPTH_ENVELOPE,
        MAX_UNTRUSTED_JSON_TOKENS_ENVELOPE,
    )?;
    let env = serde_json::from_slice::<Envelope>(blob).map_err(|_| "invalid envelope json")?;
    validate_untrusted_envelope(&env)?;
    Ok(env)
}

fn parse_validated_untrusted_inner_payload(
    expected_sender_id: &str,
    plaintext: &[u8],
) -> Result<InnerPayload, &'static str> {
    if plaintext.len() > MAX_UNTRUSTED_INNER_PAYLOAD_BYTES {
        return Err("inner payload exceeds maximum size");
    }
    validate_untrusted_json_structure(
        plaintext,
        MAX_UNTRUSTED_JSON_DEPTH_INNER,
        MAX_UNTRUSTED_JSON_TOKENS_INNER,
    )?;
    let inner =
        serde_json::from_slice::<InnerPayload>(plaintext).map_err(|_| "invalid inner payload")?;
    let synthetic_env = Envelope {
        mailbox_id: "parser-worker".to_string(),
        sender_id: expected_sender_id.to_string(),
        timestamp: 0,
        ciphertext: vec![0u8],
        pow_nonce: 0,
    };
    validate_untrusted_inner_payload(&synthetic_env, &inner, plaintext.len())?;
    Ok(inner)
}

fn parse_validated_untrusted_initial_message(
    ciphertext: &[u8],
) -> Result<InitialMessage, &'static str> {
    if ciphertext.len() > MAX_UNTRUSTED_INITIAL_BLOB_BYTES {
        return Err("initial payload exceeds maximum size");
    }
    validate_untrusted_json_structure(
        ciphertext,
        MAX_UNTRUSTED_JSON_DEPTH_INITIAL,
        MAX_UNTRUSTED_JSON_TOKENS_INITIAL,
    )?;
    let initial =
        serde_json::from_slice::<InitialMessage>(ciphertext).map_err(|_| "invalid initial json")?;
    validate_untrusted_initial_message(&initial)?;
    Ok(initial)
}

/// Classification helper for parser-fuzz harnesses.
/// 0 = dropped by blob-size gate
/// 1 = dropped by envelope parse failure
/// 2 = dropped by envelope validation
/// 3 = accepted envelope (non-handshake candidate)
/// 4 = accepted envelope with valid handshake candidate
#[doc(hidden)]
pub fn fuzz_classify_untrusted_blob(blob: &[u8]) -> u8 {
    if validate_untrusted_envelope_blob_size(blob.len()).is_err() {
        return FUZZ_CLASS_DROPPED_BLOB_SIZE;
    }
    if validate_untrusted_json_structure(
        blob,
        MAX_UNTRUSTED_JSON_DEPTH_ENVELOPE,
        MAX_UNTRUSTED_JSON_TOKENS_ENVELOPE,
    )
    .is_err()
    {
        return FUZZ_CLASS_DROPPED_ENVELOPE_PARSE;
    }
    let env = match serde_json::from_slice::<Envelope>(blob) {
        Ok(v) => v,
        Err(_) => return FUZZ_CLASS_DROPPED_ENVELOPE_PARSE,
    };
    if validate_untrusted_envelope(&env).is_err() {
        return FUZZ_CLASS_DROPPED_ENVELOPE_VALIDATION;
    }

    if parse_validated_untrusted_initial_message(&env.ciphertext).is_ok() {
        return FUZZ_CLASS_ACCEPTED_HANDSHAKE;
    }
    FUZZ_CLASS_ACCEPTED_ENVELOPE
}

/// Inner-payload validation helper for parser-fuzz harnesses.
#[doc(hidden)]
pub fn fuzz_validate_untrusted_inner_payload(sender_id: &str, plaintext: &[u8]) -> bool {
    parse_validated_untrusted_inner_payload(sender_id, plaintext).is_ok()
}

/// Parser-worker IPC request decode helper for fuzz harnesses.
#[doc(hidden)]
pub fn fuzz_parse_untrusted_parser_worker_request_frame(frame: &[u8]) -> bool {
    serde_json::from_slice::<UntrustedParserWorkerRequest>(frame).is_ok()
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub timestamp: u64,
    pub sender: String,
    pub content: String, // Plaintext content - Zeroized on drop
    pub msg_type: String,
    pub group_id: Option<String>,
    pub read: bool,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionEntry {
    pub wrapped_state: Option<Vec<u8>>,
    #[zeroize(skip)] // RatchetSession implements Zeroize
    pub inner: Option<RatchetSession>,
    pub pending_handshake: Option<String>,
    pub peer_seal_key: Option<Vec<u8>>,
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

#[derive(Clone, Copy)]
pub struct RateLimitConfig {
    pub max_messages: u32,
    pub window_seconds: u64,
}

#[derive(Default, Clone)]
pub struct TrafficStats {
    pub real_messages_sent: u64,
    pub cover_messages_sent: u64,
    pub queued_real_messages: u64,
    pub send_ticks: u64,
    pub poll_ticks: u64,
    pub send_failures: u64,
    pub poll_failures: u64,
    pub route_policy_violations: u64,
    pub route_fallback_direct_used: u64,
    pub route_fallback_direct_blocked: u64,
    pub last_send_tick_unix_ms: u64,
    pub last_poll_tick_unix_ms: u64,
}

#[derive(Default, Clone, Debug)]
pub struct ZeroizationReport {
    pub message_entries: usize,
    pub message_bytes: usize,
    pub attachment_entries: usize,
    pub attachment_bytes: usize,
    pub session_entries: usize,
    pub log_entries: usize,
    pub log_bytes: usize,
    pub pending_blob_entries: usize,
    pub pending_blob_bytes: usize,
    pub outgoing_entries: usize,
    pub outgoing_blob_bytes: usize,
    pub proof_entries: usize,
    pub metadata_entries: usize,
    pub metadata_bytes: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerPayload {
    pub sender_id: String,
    pub content: String,
    pub msg_type: String,
    pub signature: Vec<u8>,
    pub group_id: Option<String>,
    pub counter: u32,
    pub commitment_nonce: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub mailbox_id: String,
    pub sender_id: String,
    pub timestamp: u64,
    pub ciphertext: Vec<u8>,
    pub pow_nonce: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum UntrustedParserWorkerRequest {
    Envelope {
        blob_base64: String,
    },
    InnerPayload {
        expected_sender_id: String,
        plaintext_base64: String,
    },
    InitialMessage {
        ciphertext_base64: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum UntrustedParserWorkerResponse {
    Envelope { envelope: Envelope },
    InnerPayload { inner: InnerPayload },
    InitialMessage { initial: InitialMessage },
    Error { err_kind: String, err_msg: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UntrustedParserMode {
    Worker,
    InlineUnsafe,
    Disabled,
}

#[derive(Clone, Default, serde::Serialize)]
pub struct UntrustedParserBoundaryTelemetry {
    pub mode: String,
    pub parser_class_allowlist: String,
    pub worker_launches: u64,
    pub worker_launch_failures: u64,
    pub worker_restarts: u64,
    pub worker_timeouts: u64,
    pub requests_total: u64,
    pub parse_denials: u64,
    pub io_failures: u64,
    pub protocol_mismatches: u64,
    pub last_error: Option<String>,
}

struct UntrustedParserWorkerClient {
    timeout: Duration,
    max_input_bytes: usize,
    parser_class_mask: u8,
    mode: UntrustedParserMode,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
    worker_launches: u64,
    worker_launch_failures: u64,
    worker_restarts: u64,
    worker_timeouts: u64,
    requests_total: u64,
    parse_denials: u64,
    io_failures: u64,
    protocol_mismatches: u64,
    last_error: Option<String>,
}

impl UntrustedParserWorkerClient {
    fn new_from_env() -> Self {
        let integration_inline = cfg!(debug_assertions)
            && std::env::var("INTEGRATION_RUN")
                .ok()
                .map(|v| {
                    let normalized = v.trim().to_ascii_lowercase();
                    normalized == "1" || normalized == "true" || normalized == "yes"
                })
                .unwrap_or(false);
        let mode = if cfg!(test) || integration_inline {
            UntrustedParserMode::InlineUnsafe
        } else if std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_ENABLED")
            .ok()
            .map(|v| v.trim() == "0")
            .unwrap_or(false)
        {
            UntrustedParserMode::Disabled
        } else {
            UntrustedParserMode::Worker
        };

        let timeout_ms = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_UNTRUSTED_PARSER_WORKER_TIMEOUT_MS);
        let max_input_bytes = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES);
        let parser_class_mask =
            parse_parser_class_allowlist(std::env::var(PARSER_CLASS_ALLOWLIST_ENV).ok());

        Self {
            timeout: Duration::from_millis(timeout_ms),
            max_input_bytes,
            parser_class_mask,
            mode,
            child: None,
            stdin: None,
            stdout: None,
            worker_launches: 0,
            worker_launch_failures: 0,
            worker_restarts: 0,
            worker_timeouts: 0,
            requests_total: 0,
            parse_denials: 0,
            io_failures: 0,
            protocol_mismatches: 0,
            last_error: None,
        }
    }

    fn mode_name(&self) -> &'static str {
        match self.mode {
            UntrustedParserMode::Worker => "worker",
            UntrustedParserMode::InlineUnsafe => "inline_unsafe",
            UntrustedParserMode::Disabled => "disabled",
        }
    }

    fn snapshot_telemetry(&self) -> UntrustedParserBoundaryTelemetry {
        UntrustedParserBoundaryTelemetry {
            mode: self.mode_name().to_string(),
            parser_class_allowlist: format_parser_class_allowlist(self.parser_class_mask),
            worker_launches: self.worker_launches,
            worker_launch_failures: self.worker_launch_failures,
            worker_restarts: self.worker_restarts,
            worker_timeouts: self.worker_timeouts,
            requests_total: self.requests_total,
            parse_denials: self.parse_denials,
            io_failures: self.io_failures,
            protocol_mismatches: self.protocol_mismatches,
            last_error: self.last_error.clone(),
        }
    }

    fn set_last_error(&mut self, err: impl Into<String>) {
        self.last_error = Some(err.into());
    }

    fn parser_class_enabled(&self, class: UntrustedParserClass) -> bool {
        (self.parser_class_mask & parser_class_bit(class)) != 0
    }

    fn deny_parser_class(&mut self, class: UntrustedParserClass) -> Result<(), String> {
        if self.parser_class_enabled(class) {
            return Ok(());
        }
        self.parse_denials = self.parse_denials.saturating_add(1);
        let err = format!(
            "parser class {} disabled by allowlist",
            parser_class_name(class)
        );
        self.set_last_error(err.clone());
        Err(err)
    }

    fn restart_worker(&mut self, reason: &str) {
        self.worker_restarts = self.worker_restarts.saturating_add(1);
        self.set_last_error(reason.to_string());
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.flush();
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.stdin = None;
        self.stdout = None;
        self.child = None;
    }

    fn shutdown_worker(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.flush();
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.stdin = None;
        self.stdout = None;
        self.child = None;
    }

    fn parse_envelope(&mut self, blob: &[u8]) -> Result<Envelope, String> {
        self.requests_total = self.requests_total.saturating_add(1);
        self.deny_parser_class(UntrustedParserClass::EnvelopeJson)?;
        if blob.len() > self.max_input_bytes {
            self.parse_denials = self.parse_denials.saturating_add(1);
            let err = "parser worker input exceeds configured max bytes".to_string();
            self.set_last_error(err.clone());
            return Err(err);
        }
        match self.mode {
            UntrustedParserMode::InlineUnsafe => {
                parse_validated_untrusted_envelope(blob).map_err(|v| {
                    self.parse_denials = self.parse_denials.saturating_add(1);
                    self.set_last_error(v.to_string());
                    v.to_string()
                })
            }
            UntrustedParserMode::Disabled => {
                self.parse_denials = self.parse_denials.saturating_add(1);
                let err = "untrusted parser worker disabled".to_string();
                self.set_last_error(err.clone());
                Err(err)
            }
            UntrustedParserMode::Worker => {
                let req = UntrustedParserWorkerRequest::Envelope {
                    blob_base64: base64::engine::general_purpose::STANDARD.encode(blob),
                };
                match self.send_request_once(req) {
                    Ok(UntrustedParserWorkerResponse::Envelope { envelope }) => Ok(envelope),
                    Ok(UntrustedParserWorkerResponse::Error { err_msg, .. }) => {
                        self.parse_denials = self.parse_denials.saturating_add(1);
                        self.set_last_error(err_msg.clone());
                        Err(err_msg)
                    }
                    Ok(_) => {
                        self.protocol_mismatches = self.protocol_mismatches.saturating_add(1);
                        let err = "unexpected parser worker response kind".to_string();
                        self.set_last_error(err.clone());
                        Err(err)
                    }
                    Err(err) => {
                        self.restart_worker("parser worker request failed; restarting");
                        let retry_req = UntrustedParserWorkerRequest::Envelope {
                            blob_base64: base64::engine::general_purpose::STANDARD.encode(blob),
                        };
                        match self.send_request_once(retry_req) {
                            Ok(UntrustedParserWorkerResponse::Envelope { envelope }) => {
                                Ok(envelope)
                            }
                            Ok(UntrustedParserWorkerResponse::Error { err_msg, .. }) => {
                                self.parse_denials = self.parse_denials.saturating_add(1);
                                self.set_last_error(err_msg.clone());
                                Err(err_msg)
                            }
                            Ok(_) => {
                                self.protocol_mismatches =
                                    self.protocol_mismatches.saturating_add(1);
                                let retry_err =
                                    "unexpected parser worker response kind on restart".to_string();
                                self.set_last_error(retry_err.clone());
                                Err(retry_err)
                            }
                            Err(second_err) => {
                                self.io_failures = self.io_failures.saturating_add(1);
                                let retry_err = format!(
                                    "parser worker unavailable after restart: {err}; {second_err}"
                                );
                                self.set_last_error(retry_err.clone());
                                Err(retry_err)
                            }
                        }
                    }
                }
            }
        }
    }

    fn parse_inner_payload(
        &mut self,
        expected_sender_id: &str,
        plaintext: &[u8],
    ) -> Result<InnerPayload, String> {
        self.requests_total = self.requests_total.saturating_add(1);
        self.deny_parser_class(UntrustedParserClass::InnerPayloadJson)?;
        if plaintext.len() > self.max_input_bytes {
            self.parse_denials = self.parse_denials.saturating_add(1);
            let err = "inner payload exceeds configured parser worker max bytes".to_string();
            self.set_last_error(err.clone());
            return Err(err);
        }
        match self.mode {
            UntrustedParserMode::InlineUnsafe => {
                parse_validated_untrusted_inner_payload(expected_sender_id, plaintext).map_err(
                    |v| {
                        self.parse_denials = self.parse_denials.saturating_add(1);
                        self.set_last_error(v.to_string());
                        v.to_string()
                    },
                )
            }
            UntrustedParserMode::Disabled => {
                self.parse_denials = self.parse_denials.saturating_add(1);
                let err = "untrusted parser worker disabled".to_string();
                self.set_last_error(err.clone());
                Err(err)
            }
            UntrustedParserMode::Worker => {
                let req = UntrustedParserWorkerRequest::InnerPayload {
                    expected_sender_id: expected_sender_id.to_string(),
                    plaintext_base64: base64::engine::general_purpose::STANDARD.encode(plaintext),
                };
                match self.send_request_once(req) {
                    Ok(UntrustedParserWorkerResponse::InnerPayload { inner }) => Ok(inner),
                    Ok(UntrustedParserWorkerResponse::Error { err_msg, .. }) => {
                        self.parse_denials = self.parse_denials.saturating_add(1);
                        self.set_last_error(err_msg.clone());
                        Err(err_msg)
                    }
                    Ok(_) => {
                        self.protocol_mismatches = self.protocol_mismatches.saturating_add(1);
                        let err = "unexpected parser worker response kind".to_string();
                        self.set_last_error(err.clone());
                        Err(err)
                    }
                    Err(err) => {
                        self.restart_worker("parser worker request failed; restarting");
                        let retry_req = UntrustedParserWorkerRequest::InnerPayload {
                            expected_sender_id: expected_sender_id.to_string(),
                            plaintext_base64: base64::engine::general_purpose::STANDARD
                                .encode(plaintext),
                        };
                        match self.send_request_once(retry_req) {
                            Ok(UntrustedParserWorkerResponse::InnerPayload { inner }) => Ok(inner),
                            Ok(UntrustedParserWorkerResponse::Error { err_msg, .. }) => {
                                self.parse_denials = self.parse_denials.saturating_add(1);
                                self.set_last_error(err_msg.clone());
                                Err(err_msg)
                            }
                            Ok(_) => {
                                self.protocol_mismatches =
                                    self.protocol_mismatches.saturating_add(1);
                                let retry_err =
                                    "unexpected parser worker response kind on restart".to_string();
                                self.set_last_error(retry_err.clone());
                                Err(retry_err)
                            }
                            Err(second_err) => {
                                self.io_failures = self.io_failures.saturating_add(1);
                                let retry_err = format!(
                                    "parser worker unavailable after restart: {err}; {second_err}"
                                );
                                self.set_last_error(retry_err.clone());
                                Err(retry_err)
                            }
                        }
                    }
                }
            }
        }
    }

    fn parse_initial_message(&mut self, ciphertext: &[u8]) -> Result<InitialMessage, String> {
        self.requests_total = self.requests_total.saturating_add(1);
        self.deny_parser_class(UntrustedParserClass::InitialMessageJson)?;
        if ciphertext.len() > self.max_input_bytes {
            self.parse_denials = self.parse_denials.saturating_add(1);
            let err = "initial payload exceeds configured parser worker max bytes".to_string();
            self.set_last_error(err.clone());
            return Err(err);
        }
        match self.mode {
            UntrustedParserMode::InlineUnsafe => {
                parse_validated_untrusted_initial_message(ciphertext).map_err(|v| {
                    self.parse_denials = self.parse_denials.saturating_add(1);
                    self.set_last_error(v.to_string());
                    v.to_string()
                })
            }
            UntrustedParserMode::Disabled => {
                self.parse_denials = self.parse_denials.saturating_add(1);
                let err = "untrusted parser worker disabled".to_string();
                self.set_last_error(err.clone());
                Err(err)
            }
            UntrustedParserMode::Worker => {
                let req = UntrustedParserWorkerRequest::InitialMessage {
                    ciphertext_base64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
                };
                match self.send_request_once(req) {
                    Ok(UntrustedParserWorkerResponse::InitialMessage { initial }) => Ok(initial),
                    Ok(UntrustedParserWorkerResponse::Error { err_msg, .. }) => {
                        self.parse_denials = self.parse_denials.saturating_add(1);
                        self.set_last_error(err_msg.clone());
                        Err(err_msg)
                    }
                    Ok(_) => {
                        self.protocol_mismatches = self.protocol_mismatches.saturating_add(1);
                        let err = "unexpected parser worker response kind".to_string();
                        self.set_last_error(err.clone());
                        Err(err)
                    }
                    Err(err) => {
                        self.restart_worker("parser worker request failed; restarting");
                        let retry_req = UntrustedParserWorkerRequest::InitialMessage {
                            ciphertext_base64: base64::engine::general_purpose::STANDARD
                                .encode(ciphertext),
                        };
                        match self.send_request_once(retry_req) {
                            Ok(UntrustedParserWorkerResponse::InitialMessage { initial }) => {
                                Ok(initial)
                            }
                            Ok(UntrustedParserWorkerResponse::Error { err_msg, .. }) => {
                                self.parse_denials = self.parse_denials.saturating_add(1);
                                self.set_last_error(err_msg.clone());
                                Err(err_msg)
                            }
                            Ok(_) => {
                                self.protocol_mismatches =
                                    self.protocol_mismatches.saturating_add(1);
                                let retry_err =
                                    "unexpected parser worker response kind on restart".to_string();
                                self.set_last_error(retry_err.clone());
                                Err(retry_err)
                            }
                            Err(second_err) => {
                                self.io_failures = self.io_failures.saturating_add(1);
                                let retry_err = format!(
                                    "parser worker unavailable after restart: {err}; {second_err}"
                                );
                                self.set_last_error(retry_err.clone());
                                Err(retry_err)
                            }
                        }
                    }
                }
            }
        }
    }

    fn ensure_started(&mut self) -> Result<(), String> {
        if self.child.is_some() && self.stdin.is_some() && self.stdout.is_some() {
            return Ok(());
        }
        let exec_path = match std::env::current_exe() {
            Ok(v) => v,
            Err(e) => {
                self.worker_launch_failures = self.worker_launch_failures.saturating_add(1);
                let err = format!("resolve executable: {e}");
                self.set_last_error(err.clone());
                return Err(err);
            }
        };
        let mut cmd = Command::new(exec_path);
        cmd.arg(UNTRUSTED_PARSER_WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .env(
                "REDOOR_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES",
                self.max_input_bytes.to_string(),
            )
            .env(
                PARSER_CLASS_ALLOWLIST_ENV,
                format_parser_class_allowlist(self.parser_class_mask),
            );

        if let Ok(raw) = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_MEM_LIMIT_BYTES") {
            cmd.env("REDOOR_UNTRUSTED_PARSER_WORKER_MEM_LIMIT_BYTES", raw);
        }
        if let Ok(raw) = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_CPU_SECONDS") {
            cmd.env("REDOOR_UNTRUSTED_PARSER_WORKER_CPU_SECONDS", raw);
        }

        let mut child = match cmd.spawn() {
            Ok(v) => v,
            Err(e) => {
                self.worker_launch_failures = self.worker_launch_failures.saturating_add(1);
                let err = format!("start parser worker process: {e}");
                self.set_last_error(err.clone());
                return Err(err);
            }
        };
        let stdin = match child.stdin.take() {
            Some(v) => v,
            None => {
                self.worker_launch_failures = self.worker_launch_failures.saturating_add(1);
                self.set_last_error("parser worker missing stdin".to_string());
                let _ = child.kill();
                let _ = child.wait();
                return Err("parser worker missing stdin".to_string());
            }
        };
        let stdout = match child.stdout.take() {
            Some(v) => v,
            None => {
                self.worker_launch_failures = self.worker_launch_failures.saturating_add(1);
                self.set_last_error("parser worker missing stdout".to_string());
                let _ = child.kill();
                let _ = child.wait();
                return Err("parser worker missing stdout".to_string());
            }
        };
        self.stdin = Some(stdin);
        self.stdout = Some(BufReader::new(stdout));
        self.child = Some(child);
        self.worker_launches = self.worker_launches.saturating_add(1);
        self.last_error = None;
        Ok(())
    }

    fn send_request_once(
        &mut self,
        req: UntrustedParserWorkerRequest,
    ) -> Result<UntrustedParserWorkerResponse, String> {
        self.ensure_started()?;

        let encoded =
            serde_json::to_vec(&req).map_err(|e| format!("encode parser request: {e}"))?;
        if encoded.len() > self.max_input_bytes.saturating_mul(2).max(4096) {
            return Err("parser request exceeds IPC frame budget".to_string());
        }

        let write_err = {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| "parser worker stdin unavailable".to_string())?;
            if let Err(e) = stdin
                .write_all(&encoded)
                .and_then(|_| stdin.write_all(b"\n"))
            {
                Some(format!("write parser request: {e}"))
            } else if let Err(e) = stdin.flush() {
                Some(format!("flush parser request: {e}"))
            } else {
                None
            }
        };
        if let Some(err) = write_err {
            self.io_failures = self.io_failures.saturating_add(1);
            self.set_last_error(err.clone());
            return Err(err);
        }

        let stdout = self
            .stdout
            .take()
            .ok_or_else(|| "parser worker stdout unavailable".to_string())?;
        let timeout = self.timeout;
        let (tx, rx) = mpsc::channel::<(
            BufReader<ChildStdout>,
            Result<UntrustedParserWorkerResponse, String>,
        )>();
        std::thread::spawn(move || {
            let mut stdout = stdout;
            let mut response_line = Vec::new();
            let result = match stdout.read_until(b'\n', &mut response_line) {
                Ok(0) => Err("parser worker returned EOF".to_string()),
                Ok(_) => serde_json::from_slice::<UntrustedParserWorkerResponse>(&response_line)
                    .map_err(|e| format!("decode parser response: {e}")),
                Err(e) => Err(format!("read parser response: {e}")),
            };
            let _ = tx.send((stdout, result));
        });

        match rx.recv_timeout(timeout) {
            Ok((stdout, result)) => {
                self.stdout = Some(stdout);
                if let Err(ref err) = result {
                    self.io_failures = self.io_failures.saturating_add(1);
                    self.set_last_error(err.clone());
                }
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.worker_timeouts = self.worker_timeouts.saturating_add(1);
                let err = format!("parser worker timeout after {} ms", timeout.as_millis());
                self.restart_worker(err.as_str());
                Err(err)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.io_failures = self.io_failures.saturating_add(1);
                let err = "parser worker response channel disconnected".to_string();
                self.restart_worker(err.as_str());
                Err(err)
            }
        }
    }
}

impl Drop for UntrustedParserWorkerClient {
    fn drop(&mut self) {
        self.shutdown_worker();
    }
}

pub fn is_untrusted_parser_worker_command(args: &[String]) -> bool {
    args.len() > 1 && args[1].trim() == UNTRUSTED_PARSER_WORKER_ARG
}

pub fn run_untrusted_parser_worker_main() -> i32 {
    apply_untrusted_parser_worker_limits();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = std::io::BufWriter::new(stdout.lock());
    let max_input_bytes = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_UNTRUSTED_PARSER_WORKER_MAX_INPUT_BYTES);
    let parser_class_mask =
        parse_parser_class_allowlist(std::env::var(PARSER_CLASS_ALLOWLIST_ENV).ok());

    loop {
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return 0,
            Ok(_) => {}
            Err(_) => return 1,
        }
        if line.is_empty() {
            continue;
        }
        if line.len() > max_input_bytes.saturating_mul(2).max(4096) {
            let _ = serde_json::to_writer(
                &mut writer,
                &UntrustedParserWorkerResponse::Error {
                    err_kind: "invalid_request".to_string(),
                    err_msg: "parser request exceeds worker frame budget".to_string(),
                },
            );
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
            continue;
        }

        let req = match serde_json::from_slice::<UntrustedParserWorkerRequest>(&line) {
            Ok(v) => v,
            Err(_) => {
                let _ = serde_json::to_writer(
                    &mut writer,
                    &UntrustedParserWorkerResponse::Error {
                        err_kind: "invalid_request".to_string(),
                        err_msg: "invalid parser request payload".to_string(),
                    },
                );
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
                continue;
            }
        };

        let resp = match req {
            UntrustedParserWorkerRequest::Envelope { blob_base64 } => {
                if (parser_class_mask & parser_class_bit(UntrustedParserClass::EnvelopeJson)) == 0 {
                    UntrustedParserWorkerResponse::Error {
                        err_kind: "policy_denied".to_string(),
                        err_msg: "parser class envelope_json disabled by allowlist".to_string(),
                    }
                } else {
                    match base64::engine::general_purpose::STANDARD.decode(blob_base64) {
                        Ok(blob) => {
                            if blob.len() > max_input_bytes {
                                UntrustedParserWorkerResponse::Error {
                                    err_kind: "invalid_payload".to_string(),
                                    err_msg: "blob exceeds max input budget".to_string(),
                                }
                            } else {
                                match parse_validated_untrusted_envelope(&blob) {
                                    Ok(envelope) => {
                                        UntrustedParserWorkerResponse::Envelope { envelope }
                                    }
                                    Err(reason) => UntrustedParserWorkerResponse::Error {
                                        err_kind: "invalid_payload".to_string(),
                                        err_msg: reason.to_string(),
                                    },
                                }
                            }
                        }
                        Err(_) => UntrustedParserWorkerResponse::Error {
                            err_kind: "invalid_request".to_string(),
                            err_msg: "invalid base64 blob".to_string(),
                        },
                    }
                }
            }
            UntrustedParserWorkerRequest::InnerPayload {
                expected_sender_id,
                plaintext_base64,
            } => {
                if (parser_class_mask & parser_class_bit(UntrustedParserClass::InnerPayloadJson))
                    == 0
                {
                    UntrustedParserWorkerResponse::Error {
                        err_kind: "policy_denied".to_string(),
                        err_msg: "parser class inner_payload_json disabled by allowlist"
                            .to_string(),
                    }
                } else {
                    match base64::engine::general_purpose::STANDARD.decode(plaintext_base64) {
                        Ok(plaintext) => {
                            if plaintext.len() > max_input_bytes {
                                UntrustedParserWorkerResponse::Error {
                                    err_kind: "invalid_payload".to_string(),
                                    err_msg: "plaintext exceeds max input budget".to_string(),
                                }
                            } else {
                                match parse_validated_untrusted_inner_payload(
                                    expected_sender_id.as_str(),
                                    &plaintext,
                                ) {
                                    Ok(inner) => {
                                        UntrustedParserWorkerResponse::InnerPayload { inner }
                                    }
                                    Err(reason) => UntrustedParserWorkerResponse::Error {
                                        err_kind: "invalid_payload".to_string(),
                                        err_msg: reason.to_string(),
                                    },
                                }
                            }
                        }
                        Err(_) => UntrustedParserWorkerResponse::Error {
                            err_kind: "invalid_request".to_string(),
                            err_msg: "invalid base64 inner payload".to_string(),
                        },
                    }
                }
            }
            UntrustedParserWorkerRequest::InitialMessage { ciphertext_base64 } => {
                if (parser_class_mask & parser_class_bit(UntrustedParserClass::InitialMessageJson))
                    == 0
                {
                    UntrustedParserWorkerResponse::Error {
                        err_kind: "policy_denied".to_string(),
                        err_msg: "parser class initial_message_json disabled by allowlist"
                            .to_string(),
                    }
                } else {
                    match base64::engine::general_purpose::STANDARD.decode(ciphertext_base64) {
                        Ok(ciphertext) => {
                            if ciphertext.len() > max_input_bytes {
                                UntrustedParserWorkerResponse::Error {
                                    err_kind: "invalid_payload".to_string(),
                                    err_msg: "ciphertext exceeds max input budget".to_string(),
                                }
                            } else {
                                match parse_validated_untrusted_initial_message(&ciphertext) {
                                    Ok(initial) => {
                                        UntrustedParserWorkerResponse::InitialMessage { initial }
                                    }
                                    Err(reason) => UntrustedParserWorkerResponse::Error {
                                        err_kind: "invalid_payload".to_string(),
                                        err_msg: reason.to_string(),
                                    },
                                }
                            }
                        }
                        Err(_) => UntrustedParserWorkerResponse::Error {
                            err_kind: "invalid_request".to_string(),
                            err_msg: "invalid base64 initial payload".to_string(),
                        },
                    }
                }
            }
        };

        if serde_json::to_writer(&mut writer, &resp).is_err() {
            return 1;
        }
        if writer.write_all(b"\n").is_err() {
            return 1;
        }
        if writer.flush().is_err() {
            return 1;
        }
    }
}

#[cfg(unix)]
fn apply_untrusted_parser_worker_limits() {
    let memory_limit = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_MEM_LIMIT_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(64 * 1024 * 1024);
    let cpu_seconds = std::env::var("REDOOR_UNTRUSTED_PARSER_WORKER_CPU_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(2);

    unsafe {
        let limit = libc::rlimit {
            rlim_cur: memory_limit as libc::rlim_t,
            rlim_max: memory_limit as libc::rlim_t,
        };
        let _ = libc::setrlimit(libc::RLIMIT_AS, &limit);

        let cpu_limit = libc::rlimit {
            rlim_cur: cpu_seconds as libc::rlim_t,
            rlim_max: cpu_seconds as libc::rlim_t,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit);
    }
}

#[cfg(not(unix))]
fn apply_untrusted_parser_worker_limits() {}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OutgoingMessage {
    pub msg_id: String,
    pub peer_id: String,
    pub blob: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct QueuedBlockchainCommitment {
    pub receiver_id: String,
    pub message_hash: [u8; 32],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct CommitmentInclusionProof {
    pub message_hash: String,
    pub merkle_root: String,
    pub receiver_commitment: String,
    pub leaf_index: usize,
    pub siblings: Vec<String>,
    pub batch_size: usize,
    pub submitted_at: u64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct BlockchainBatchObservation {
    pub submitted_at: u64,
    pub real_batch_size: usize,
    pub real_root: String,
    pub decoy_roots: Vec<String>,
    pub scheduled_delay_ms: u64,
    pub observed_interval_ms: u64,
    pub drift_ms: i64,
    pub submissions_ok: usize,
    pub submissions_failed: usize,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct BlockchainBatchTelemetry {
    pub enabled: bool,
    pub configured_interval_ms: u64,
    pub scheduler_jitter_pct: u64,
    pub decoy_count: usize,
    pub scheduler_seed: Option<u64>,
    pub ticks_total: u64,
    pub empty_ticks: u64,
    pub flushes_total: u64,
    pub real_commits_submitted: u64,
    pub decoy_commits_submitted: u64,
    pub submit_failures: u64,
    pub last_scheduled_delay_ms: u64,
    pub last_tick_interval_ms: u64,
    pub max_positive_drift_ms: u64,
    pub max_negative_drift_ms: u64,
    pub last_submitted_at: u64,
    pub recent_batches: Vec<BlockchainBatchObservation>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SessionRekeyState {
    pub protocol_version: u16,
    pub protocol_epoch: u32,
    pub established_at: u64,
    pub last_rekey_at: u64,
    pub last_activity_at: u64,
    pub messages_since_rekey: u64,
    pub pq_mixes_applied: u64,
    pub pending_rekey: bool,
    pub pending_reason: Option<String>,
    pub rekey_events_total: u64,
}

impl SessionRekeyState {
    fn new(protocol_version: u16, now: u64) -> Self {
        Self {
            protocol_version,
            protocol_epoch: 1,
            established_at: now,
            last_rekey_at: now,
            last_activity_at: now,
            messages_since_rekey: 0,
            pq_mixes_applied: 0,
            pending_rekey: false,
            pending_reason: None,
            rekey_events_total: 0,
        }
    }

    fn mark_pending(&mut self, reason: &str) -> bool {
        if self.pending_rekey {
            return false;
        }
        self.pending_rekey = true;
        self.pending_reason = Some(reason.to_string());
        true
    }
}

#[derive(Clone, serde::Serialize, Default)]
pub struct RekeyHealthTelemetry {
    pub active_sessions: usize,
    pub pending_sessions: usize,
    pub forced_rekeys_total: u64,
    pub last_forced_reason: Option<String>,
    pub protocol_version_current: u16,
    pub protocol_min_accepted_version: u16,
    pub forced_rekey_after_messages: u64,
    pub forced_rekey_after_secs: u64,
    pub pq_ratchet_interval_messages: u64,
}

pub struct AppState {
    pub relay_client: Option<RelayClient>,
    pub blockchain_client: Option<BlockchainClient>,
    pub p2p_client: Option<P2PClient>,
    pub directory_client: Option<DirectoryClient>,
    pub identity: Option<IdentityKey>,
    pub prekey_secrets: Option<PrekeySecrets>,
    pub prekey_low_watermark: usize,
    pub prekey_target_count: usize,
    pub prekey_last_replenished_at: Option<u64>,
    pub signed_prekey_last_rotated_at: Option<u64>,
    pub signed_prekey_rotate_interval_secs: u64,
    pub protocol_version_current: u16,
    pub protocol_min_accepted_version: u16,
    pub forced_rekey_after_messages: u64,
    pub forced_rekey_after_secs: u64,
    pub pq_ratchet_interval_messages: u64,
    pub forced_rekey_events_total: u64,
    pub last_forced_rekey_reason: Option<String>,
    #[cfg(feature = "pq")]
    pub kyber_keys: Option<(kyber1024::PublicKey, kyber1024::SecretKey)>,
    pub sessions: HashMap<String, SessionEntry>,
    pub session_rekey_state: HashMap<String, SessionRekeyState>,
    pub onion_router: Option<OnionRouter>,
    pub background_config: BackgroundConfig,
    pub background_generation: AtomicUsize,
    pub log_buffer: VecDeque<String>,
    pub cover_traffic_config: CoverTrafficConfig,
    pub nicknames: HashMap<String, String>,
    pub groups: HashMap<String, Vec<String>>,
    pub blocked_peers: HashSet<String>,
    pub auto_delete_timers: HashMap<String, u64>,

    // Sensitive data that needs careful wiping
    pub message_store: HashMap<String, Vec<StoredMessage>>,
    pub attachment_cache: HashMap<String, Vec<u8>>,

    pub pending_blobs: Mutex<VecDeque<(String, Vec<u8>)>>,
    pub low_power_mode: AtomicBool,
    pub read_receipts_enabled: AtomicBool,
    pub pow_difficulty: u32,
    pub rate_limit_config: Option<RateLimitConfig>,
    pub batching_enabled: AtomicBool,
    pub blockchain_queue: Mutex<Vec<QueuedBlockchainCommitment>>,
    pub commitment_proofs: Mutex<HashMap<String, CommitmentInclusionProof>>,
    pub blockchain_batch_telemetry: Mutex<BlockchainBatchTelemetry>,
    pub last_zeroization_report: ZeroizationReport,
    pub outgoing_batching_enabled: AtomicBool,
    pub outgoing_batch_interval_ms: AtomicU64,
    pub outgoing_queue: Mutex<VecDeque<OutgoingMessage>>,
    pub fixed_polling_enabled: AtomicBool,
    pub anonymity_mode_enabled: AtomicBool,
    pub constant_rate_enabled: AtomicBool,
    pub mixnet_config: MixnetConfig,
    pub traffic_stats: Mutex<TrafficStats>,
    pub log_level: AtomicU8,
    pub theme: String,
    pub cover_traffic_enabled: AtomicBool,
}

fn append_log_locked(state: &mut AppState, msg: String) {
    if state.log_buffer.len() >= 1000 {
        state.log_buffer.pop_front();
    }
    state.log_buffer.push_back(redact_for_log(&msg));
}

impl AppState {
    pub fn new() -> Self {
        let prekey_low_watermark = config::prekey_low_watermark();
        let prekey_target_count = config::prekey_target_count();
        let signed_prekey_rotate_interval_secs = config::signed_prekey_rotate_interval_secs();
        let protocol_version_current = config::protocol_version_current();
        let protocol_min_accepted_version = config::protocol_min_accepted_version();
        let forced_rekey_after_messages = config::forced_rekey_after_messages();
        let forced_rekey_after_secs = config::forced_rekey_after_secs();
        let pq_ratchet_interval_messages = config::pq_ratchet_interval_messages();

        Self {
            relay_client: None,
            blockchain_client: None,
            p2p_client: None,
            directory_client: None,
            identity: None,
            prekey_secrets: None,
            prekey_low_watermark,
            prekey_target_count,
            prekey_last_replenished_at: None,
            signed_prekey_last_rotated_at: None,
            signed_prekey_rotate_interval_secs,
            protocol_version_current,
            protocol_min_accepted_version,
            forced_rekey_after_messages,
            forced_rekey_after_secs,
            pq_ratchet_interval_messages,
            forced_rekey_events_total: 0,
            last_forced_rekey_reason: None,
            #[cfg(feature = "pq")]
            kyber_keys: None,
            sessions: HashMap::new(),
            session_rekey_state: HashMap::new(),
            onion_router: None,
            background_config: BackgroundConfig {
                mode: 0,
                grace_period_ms: 0,
            },
            background_generation: AtomicUsize::new(0),
            log_buffer: VecDeque::new(),
            cover_traffic_config: CoverTrafficConfig {
                min_delay_ms: 1000,
                max_delay_ms: 5000,
            },
            nicknames: HashMap::new(),
            groups: HashMap::new(),
            blocked_peers: HashSet::new(),
            auto_delete_timers: HashMap::new(),
            message_store: HashMap::new(),
            attachment_cache: HashMap::new(),
            pending_blobs: Mutex::new(VecDeque::new()),
            low_power_mode: AtomicBool::new(false),
            read_receipts_enabled: AtomicBool::new(true),
            pow_difficulty: 0,
            rate_limit_config: None,
            batching_enabled: AtomicBool::new(false),
            blockchain_queue: Mutex::new(Vec::new()),
            commitment_proofs: Mutex::new(HashMap::new()),
            blockchain_batch_telemetry: Mutex::new(BlockchainBatchTelemetry::default()),
            last_zeroization_report: ZeroizationReport::default(),
            outgoing_batching_enabled: AtomicBool::new(false),
            outgoing_batch_interval_ms: AtomicU64::new(0),
            outgoing_queue: Mutex::new(VecDeque::new()),
            fixed_polling_enabled: AtomicBool::new(false),
            anonymity_mode_enabled: AtomicBool::new(true), // Strict anonymity always enabled by default
            constant_rate_enabled: AtomicBool::new(false),
            mixnet_config: MixnetConfig::default(),
            traffic_stats: Mutex::new(TrafficStats::default()),
            log_level: AtomicU8::new(2),
            theme: "system".to_string(),
            cover_traffic_enabled: AtomicBool::new(false),
        }
    }

    fn ensure_session_rekey_state(
        &mut self,
        peer_id: &str,
        protocol_version: u16,
    ) -> &mut SessionRekeyState {
        let now = unix_now_secs();
        self.session_rekey_state
            .entry(peer_id.to_string())
            .or_insert_with(|| SessionRekeyState::new(protocol_version, now))
    }

    pub fn mark_session_established(&mut self, peer_id: &str, protocol_version: u16, reason: &str) {
        let now = unix_now_secs();
        let state = self
            .session_rekey_state
            .entry(peer_id.to_string())
            .or_insert_with(|| SessionRekeyState::new(protocol_version, now));
        state.protocol_epoch = state.protocol_epoch.saturating_add(1);
        state.protocol_version = protocol_version;
        state.established_at = now;
        state.last_rekey_at = now;
        state.last_activity_at = now;
        state.messages_since_rekey = 0;
        state.pq_mixes_applied = 0;
        state.pending_rekey = false;
        state.pending_reason = None;
        state.rekey_events_total = state.rekey_events_total.saturating_add(1);

        self.forced_rekey_events_total = self.forced_rekey_events_total.saturating_add(1);
        self.last_forced_rekey_reason = Some(reason.to_string());
    }

    pub fn record_session_activity(&mut self, peer_id: &str) {
        let protocol_version = self.protocol_version_current;
        let pq_interval = self.pq_ratchet_interval_messages.max(1);
        let now = unix_now_secs();
        let state = self.ensure_session_rekey_state(peer_id, protocol_version);
        state.messages_since_rekey = state.messages_since_rekey.saturating_add(1);
        state.last_activity_at = now;
        if state.messages_since_rekey.is_multiple_of(pq_interval) {
            state.pq_mixes_applied = state.pq_mixes_applied.saturating_add(1);
        }
    }

    fn mark_session_rekey_pending_internal(&mut self, peer_id: &str, reason: &str) {
        if let Some(state) = self.session_rekey_state.get_mut(peer_id) {
            if state.mark_pending(reason) {
                self.forced_rekey_events_total = self.forced_rekey_events_total.saturating_add(1);
                self.last_forced_rekey_reason = Some(reason.to_string());
            }
        }
    }

    pub fn mark_session_rekey_pending(&mut self, peer_id: &str, reason: &str) {
        let protocol_version = self.protocol_version_current;
        let _ = self.ensure_session_rekey_state(peer_id, protocol_version);
        self.mark_session_rekey_pending_internal(peer_id, reason);
    }

    pub fn mark_all_sessions_rekey_pending(&mut self, reason: &str) {
        let peers: Vec<String> = self.sessions.keys().cloned().collect();
        for peer in peers {
            self.mark_session_rekey_pending(peer.as_str(), reason);
        }
    }

    pub fn evaluate_session_rekey_requirement(&mut self, peer_id: &str) -> Option<String> {
        let protocol_version = self.protocol_version_current;
        let _ = self.ensure_session_rekey_state(peer_id, protocol_version);
        let now = unix_now_secs();

        let mut reason = None;
        if let Some(state) = self.session_rekey_state.get(peer_id) {
            if state.pending_rekey {
                return state.pending_reason.clone();
            }
            if state.protocol_version < self.protocol_min_accepted_version {
                reason = Some("protocol_version_rejected".to_string());
            } else if state.protocol_version < self.protocol_version_current {
                reason = Some("protocol_version_transition".to_string());
            } else if now.saturating_sub(state.last_rekey_at) >= self.forced_rekey_after_secs {
                reason = Some("rekey_time_window_elapsed".to_string());
            } else if state.messages_since_rekey >= self.forced_rekey_after_messages {
                reason = Some("rekey_message_budget_exhausted".to_string());
            }
        }

        if let Some(reason_text) = reason {
            self.mark_session_rekey_pending_internal(peer_id, reason_text.as_str());
            return Some(reason_text);
        }
        None
    }

    pub fn rekey_health(&self) -> RekeyHealthTelemetry {
        let pending_sessions = self
            .session_rekey_state
            .values()
            .filter(|state| state.pending_rekey)
            .count();
        RekeyHealthTelemetry {
            active_sessions: self.sessions.len(),
            pending_sessions,
            forced_rekeys_total: self.forced_rekey_events_total,
            last_forced_reason: self.last_forced_rekey_reason.clone(),
            protocol_version_current: self.protocol_version_current,
            protocol_min_accepted_version: self.protocol_min_accepted_version,
            forced_rekey_after_messages: self.forced_rekey_after_messages,
            forced_rekey_after_secs: self.forced_rekey_after_secs,
            pq_ratchet_interval_messages: self.pq_ratchet_interval_messages,
        }
    }

    fn wipe_message_store(&mut self) {
        let mut message_entries = 0usize;
        let mut message_bytes = 0usize;
        let mut metadata_entries = 0usize;
        let mut metadata_bytes = 0usize;

        for (mut peer_id, mut messages) in self.message_store.drain() {
            metadata_entries += 1;
            metadata_bytes += peer_id.len();
            peer_id.zeroize();

            for msg in messages.iter_mut() {
                message_entries += 1;
                message_bytes += msg.id.len()
                    + msg.sender.len()
                    + msg.content.len()
                    + msg.msg_type.len()
                    + msg.group_id.as_ref().map(|g| g.len()).unwrap_or_default();
                msg.zeroize();
            }
        }

        self.last_zeroization_report.message_entries += message_entries;
        self.last_zeroization_report.message_bytes += message_bytes;
        self.last_zeroization_report.metadata_entries += metadata_entries;
        self.last_zeroization_report.metadata_bytes += metadata_bytes;
    }

    fn wipe_attachment_cache(&mut self) {
        let mut attachment_entries = 0usize;
        let mut attachment_bytes = 0usize;
        let mut metadata_entries = 0usize;
        let mut metadata_bytes = 0usize;

        for (mut key, mut data) in self.attachment_cache.drain() {
            attachment_entries += 1;
            attachment_bytes += data.len();
            metadata_entries += 1;
            metadata_bytes += key.len();
            data.zeroize();
            key.zeroize();
        }

        self.last_zeroization_report.attachment_entries += attachment_entries;
        self.last_zeroization_report.attachment_bytes += attachment_bytes;
        self.last_zeroization_report.metadata_entries += metadata_entries;
        self.last_zeroization_report.metadata_bytes += metadata_bytes;
    }

    fn wipe_sessions(&mut self) {
        let mut session_entries = 0usize;
        let mut metadata_entries = 0usize;
        let mut metadata_bytes = 0usize;

        for (mut peer_id, mut session) in self.sessions.drain() {
            session_entries += 1;
            metadata_entries += 1;
            metadata_bytes += peer_id.len();
            peer_id.zeroize();
            session.zeroize();
        }

        self.last_zeroization_report.session_entries += session_entries;
        self.last_zeroization_report.metadata_entries += metadata_entries;
        self.last_zeroization_report.metadata_bytes += metadata_bytes;

        let mut rekey_metadata_entries = 0usize;
        let mut rekey_metadata_bytes = 0usize;
        for (mut peer_id, mut state) in self.session_rekey_state.drain() {
            rekey_metadata_entries += 1;
            rekey_metadata_bytes += peer_id.len();
            peer_id.zeroize();
            if let Some(reason) = state.pending_reason.as_mut() {
                reason.zeroize();
            }
        }
        self.last_zeroization_report.metadata_entries += rekey_metadata_entries;
        self.last_zeroization_report.metadata_bytes += rekey_metadata_bytes;
        self.forced_rekey_events_total = 0;
        self.last_forced_rekey_reason = None;
    }

    fn wipe_log_buffer(&mut self) {
        let mut log_entries = 0usize;
        let mut log_bytes = 0usize;
        while let Some(mut line) = self.log_buffer.pop_front() {
            log_entries += 1;
            log_bytes += line.len();
            line.zeroize();
        }
        self.last_zeroization_report.log_entries += log_entries;
        self.last_zeroization_report.log_bytes += log_bytes;
    }

    fn wipe_volatile_metadata(&mut self) {
        let mut metadata_entries = 0usize;
        let mut metadata_bytes = 0usize;

        for (mut key, mut value) in self.nicknames.drain() {
            metadata_entries += 2;
            metadata_bytes += key.len() + value.len();
            key.zeroize();
            value.zeroize();
        }

        for (mut group_id, mut members) in self.groups.drain() {
            metadata_entries += 1 + members.len();
            metadata_bytes += group_id.len();
            group_id.zeroize();
            for member in &mut members {
                metadata_bytes += member.len();
                member.zeroize();
            }
        }

        for mut peer in self.blocked_peers.drain() {
            metadata_entries += 1;
            metadata_bytes += peer.len();
            peer.zeroize();
        }

        for (mut key, _) in self.auto_delete_timers.drain() {
            metadata_entries += 1;
            metadata_bytes += key.len();
            key.zeroize();
        }

        self.last_zeroization_report.metadata_entries += metadata_entries;
        self.last_zeroization_report.metadata_bytes += metadata_bytes;
    }

    fn wipe_pending_blobs(&mut self) {
        if let Ok(mut queue) = self.pending_blobs.lock() {
            let mut entries = 0usize;
            let mut bytes = 0usize;
            let mut metadata_entries = 0usize;
            let mut metadata_bytes = 0usize;
            for (mut msg_id, mut blob) in queue.drain(..) {
                entries += 1;
                bytes += blob.len();
                metadata_entries += 1;
                metadata_bytes += msg_id.len();
                msg_id.zeroize();
                blob.zeroize();
            }
            self.last_zeroization_report.pending_blob_entries += entries;
            self.last_zeroization_report.pending_blob_bytes += bytes;
            self.last_zeroization_report.metadata_entries += metadata_entries;
            self.last_zeroization_report.metadata_bytes += metadata_bytes;
        }
    }

    fn wipe_blockchain_queues(&mut self) {
        if let Ok(mut queue) = self.blockchain_queue.lock() {
            let mut metadata_entries = 0usize;
            let mut metadata_bytes = 0usize;
            for mut item in queue.drain(..) {
                metadata_entries += 1;
                metadata_bytes += item.receiver_id.len();
                item.zeroize();
            }
            self.last_zeroization_report.metadata_entries += metadata_entries;
            self.last_zeroization_report.metadata_bytes += metadata_bytes;
        }

        if let Ok(mut proofs) = self.commitment_proofs.lock() {
            let mut proof_entries = 0usize;
            let mut metadata_entries = 0usize;
            let mut metadata_bytes = 0usize;
            for (mut key, mut proof) in proofs.drain() {
                proof_entries += 1;
                metadata_entries += 1;
                metadata_bytes += key.len();
                key.zeroize();
                proof.zeroize();
            }
            self.last_zeroization_report.proof_entries += proof_entries;
            self.last_zeroization_report.metadata_entries += metadata_entries;
            self.last_zeroization_report.metadata_bytes += metadata_bytes;
        }
    }

    fn wipe_outgoing_queue(&mut self) {
        if let Ok(mut queue) = self.outgoing_queue.lock() {
            let mut entries = 0usize;
            let mut bytes = 0usize;
            let mut metadata_entries = 0usize;
            let mut metadata_bytes = 0usize;
            for mut msg in queue.drain(..) {
                entries += 1;
                bytes += msg.blob.len();
                metadata_entries += 2;
                metadata_bytes += msg.msg_id.len() + msg.peer_id.len();
                msg.zeroize();
            }
            self.last_zeroization_report.outgoing_entries += entries;
            self.last_zeroization_report.outgoing_blob_bytes += bytes;
            self.last_zeroization_report.metadata_entries += metadata_entries;
            self.last_zeroization_report.metadata_bytes += metadata_bytes;
        }
    }

    pub fn clear_message_history_securely(&mut self) {
        self.last_zeroization_report = ZeroizationReport::default();
        self.wipe_message_store();
        self.wipe_attachment_cache();
    }

    pub fn secure_wipe(&mut self) {
        self.last_zeroization_report = ZeroizationReport::default();

        self.wipe_message_store();
        self.wipe_attachment_cache();
        self.wipe_sessions();
        self.wipe_log_buffer();
        self.wipe_volatile_metadata();
        self.wipe_pending_blobs();
        self.wipe_blockchain_queues();
        self.wipe_outgoing_queue();

        self.identity = None;
        self.prekey_secrets = None;
        self.prekey_last_replenished_at = None;
        self.signed_prekey_last_rotated_at = None;
        self.relay_client = None;
        self.blockchain_client = None;
        self.p2p_client = None;
        self.directory_client = None;
        self.onion_router = None;
        #[cfg(feature = "pq")]
        {
            self.kyber_keys = None;
        }

        if let Ok(mut telemetry) = self.blockchain_batch_telemetry.lock() {
            *telemetry = BlockchainBatchTelemetry::default();
        }
    }

    pub fn apply_prekey_hygiene(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        let now = unix_now_secs();

        let identity = match self.identity.clone() {
            Some(id) => id,
            None => return notes,
        };

        let secrets = match self.prekey_secrets.as_mut() {
            Some(s) => s,
            None => return notes,
        };

        if self.signed_prekey_last_rotated_at.is_none() {
            self.signed_prekey_last_rotated_at = Some(now);
        }

        if let Some(last_rotated) = self.signed_prekey_last_rotated_at {
            if now.saturating_sub(last_rotated) >= self.signed_prekey_rotate_interval_secs {
                if let Ok((_spk_pub, _sig, spk_priv)) =
                    crate::crypto::x3dh::rotate_signed_prekey(&identity)
                {
                    secrets.signed_prekey = spk_priv;
                    self.signed_prekey_last_rotated_at = Some(now);
                    notes.push("Signed prekey rotated by hygiene cadence.".to_string());
                }
            }
        }

        let count = secrets.one_time_prekeys.len();
        if count < self.prekey_low_watermark {
            let target = self.prekey_target_count.max(self.prekey_low_watermark);
            let needed = target.saturating_sub(count);
            if needed > 0 {
                let (_pubs, mut new_secrets) =
                    crate::crypto::x3dh::generate_one_time_prekeys(needed);
                secrets.one_time_prekeys.append(&mut new_secrets);
                self.prekey_last_replenished_at = Some(now);
                notes.push(format!(
                    "Prekey inventory low ({}). Replenished {} one-time prekeys.",
                    count, needed
                ));
            }
        }

        notes
    }
}

pub struct ClientEngine {
    pub runtime: Runtime,
    pub state: Arc<Mutex<AppState>>,
    untrusted_parser: Arc<Mutex<UntrustedParserWorkerClient>>,
}

impl ClientEngine {
    pub fn new() -> Self {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        let untrusted_parser = Arc::new(Mutex::new(UntrustedParserWorkerClient::new_from_env()));
        Self {
            runtime,
            state: Arc::new(Mutex::new(AppState::new())),
            untrusted_parser,
        }
    }

    pub fn untrusted_parser_mode(&self) -> String {
        self.untrusted_parser
            .lock()
            .map(|parser| parser.mode_name().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    pub fn untrusted_parser_telemetry(&self) -> UntrustedParserBoundaryTelemetry {
        self.untrusted_parser
            .lock()
            .map(|parser| parser.snapshot_telemetry())
            .unwrap_or_else(|_| UntrustedParserBoundaryTelemetry {
                mode: "unknown".to_string(),
                last_error: Some("untrusted parser boundary lock poisoned".to_string()),
                ..UntrustedParserBoundaryTelemetry::default()
            })
    }

    pub fn rekey_health_telemetry(&self) -> RekeyHealthTelemetry {
        self.state
            .lock()
            .map(|guard| guard.rekey_health())
            .unwrap_or_default()
    }

    pub fn mark_all_sessions_for_rekey(&self, reason: &str) {
        if let Ok(mut guard) = self.state.lock() {
            guard.mark_all_sessions_rekey_pending(reason);
            append_log_locked(
                &mut guard,
                format!("Forced rekey marked for all sessions: {reason}"),
            );
        }
    }

    pub fn mark_peer_for_rekey(&self, peer_id: &str, reason: &str) {
        if let Ok(mut guard) = self.state.lock() {
            guard.mark_session_rekey_pending(peer_id, reason);
            append_log_locked(
                &mut guard,
                format!("Forced rekey marked for {}: {reason}", peer_id),
            );
        }
    }

    pub fn initialize_keys(&self) {
        let identity = IdentityKey::generate();
        let prekeys = PrekeySecrets::generate();
        let now = unix_now_secs();

        let mut guard = self.state.lock().unwrap();
        guard.identity = Some(identity);
        guard.prekey_secrets = Some(prekeys);
        guard.signed_prekey_last_rotated_at = Some(now);
        guard.prekey_last_replenished_at = Some(now);
        guard
            .log_buffer
            .push_back("Keys initialized with real X3DH handshake materials.".to_string());
    }

    pub fn wipe_memory(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.secure_wipe();
            guard
                .log_buffer
                .push_back("Memory wiped securely.".to_string());
        }
    }

    pub fn log_internal(&self, msg: String) {
        if let Ok(mut guard) = self.state.lock() {
            if guard.log_buffer.len() >= 1000 {
                guard.log_buffer.pop_front();
            }
            guard.log_buffer.push_back(redact_for_log(&msg));
        }
    }

    // Mock methods for FFI calls
    pub fn send_payload(
        &self,
        peer_id: &str,
        content: &str,
        msg_type: &str,
        group_id: Option<&str>,
        onion_routing: bool,
        p2p_mode: bool,
        peer_addr: Option<String>,
    ) -> i32 {
        let (
            relay,
            identity,
            session,
            rekey_block_reason,
            blockchain,
            p2p_client,
            onion_router,
            strict_anonymity,
            blockchain_batching_enabled,
            fixed_polling_enabled,
            constant_rate_enabled,
        ) = {
            let mut guard = self.state.lock().unwrap();
            for note in guard.apply_prekey_hygiene() {
                if guard.log_buffer.len() >= 1000 {
                    guard.log_buffer.pop_front();
                }
                guard.log_buffer.push_back(redact_for_log(&note));
            }
            let protocol_version_current = guard.protocol_version_current;
            let _ = guard.ensure_session_rekey_state(peer_id, protocol_version_current);
            let rekey_block_reason = guard.evaluate_session_rekey_requirement(peer_id);
            let relay = guard.relay_client.clone();
            let identity = guard.identity.clone();
            // Clone the inner session to use it, we will update it back later
            let session = guard
                .sessions
                .get_mut(peer_id)
                .and_then(|s| s.inner.clone());
            let blockchain = guard.blockchain_client.clone();
            let p2p_client = guard.p2p_client.clone();
            let onion_router = guard.onion_router.clone();
            let strict_anonymity = guard.anonymity_mode_enabled.load(Ordering::Relaxed);
            let blockchain_batching_enabled = guard.batching_enabled.load(Ordering::Relaxed);
            let fixed_polling_enabled = guard.fixed_polling_enabled.load(Ordering::Relaxed);
            let constant_rate_enabled = guard.constant_rate_enabled.load(Ordering::Relaxed);
            (
                relay,
                identity,
                session,
                rekey_block_reason,
                blockchain,
                p2p_client,
                onion_router,
                strict_anonymity,
                blockchain_batching_enabled,
                fixed_polling_enabled,
                constant_rate_enabled,
            )
        };

        if identity.is_none() || session.is_none() {
            self.log_internal(format!(
                "Send failed: Missing identity or session for {}",
                peer_id
            ));
            return -1;
        }
        if let Some(reason) = rekey_block_reason {
            self.log_internal(format!(
                "Send blocked for {}: forced rekey required ({})",
                peer_id, reason
            ));
            return -10;
        }

        // Strict anonymity policy: all user-originated traffic must use the onion path.
        if strict_anonymity {
            if p2p_mode || !onion_routing || onion_router.is_none() {
                self.log_internal(
                    "Strict anonymity mode blocked a non-onion send attempt.".to_string(),
                );
                return -9;
            }
        }

        let identity = identity.unwrap();
        let mut session = session.unwrap();

        // 1. Prepare Inner Payload
        let inner = InnerPayload {
            sender_id: hex::encode(identity.public_key_bytes()),
            content: content.to_string(),
            msg_type: msg_type.to_string(),
            signature: vec![], // In a full impl, sign content with identity key here
            group_id: group_id.map(|s| s.to_string()),
            counter: session.msg_count_send,
            commitment_nonce: rand::random(),
        };

        let inner_bytes = match serde_json::to_vec(&inner) {
            Ok(b) => b,
            Err(_) => return -2,
        };

        // 2. Encrypt with Double Ratchet
        let ciphertext = match session.ratchet_encrypt(&inner_bytes) {
            Ok(ct) => ct,
            Err(e) => {
                self.log_internal(format!("Ratchet encryption failed: {}", e));
                return -3;
            }
        };

        // 3. Update Session State (Ratchet advanced)
        {
            let mut guard = self.state.lock().unwrap();
            if let Some(entry) = guard.sessions.get_mut(peer_id) {
                entry.inner = Some(session);
            }
            guard.record_session_activity(peer_id);
            let _ = guard.evaluate_session_rekey_requirement(peer_id);
        }

        // 4. Wrap in Envelope
        // In a real anonymity network, mailbox_id would be a blinded token.
        // Here we use a hash of the receiver ID for simplicity.
        let mailbox_id = hex::encode(crate::crypto::blake3::hash(peer_id.as_bytes()));

        let envelope = Envelope {
            mailbox_id,
            sender_id: hex::encode(identity.public_key_bytes()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ciphertext,
            pow_nonce: 0, // PoW logic omitted for brevity
        };

        let mut blob = serde_json::to_vec(&envelope).unwrap();
        blob = pad_envelope(blob);

        let msg_hash = crate::crypto::blake3::hash(&blob);
        let msg_id = hex::encode(msg_hash);

        if strict_anonymity {
            if !fixed_polling_enabled || !constant_rate_enabled {
                let _ = crate::service::start_fixed_polling(self, 0);
                let _ = crate::service::start_constant_rate_traffic(self, 0);

                let guard = self.state.lock().unwrap();
                let fixed_ready = guard.fixed_polling_enabled.load(Ordering::Relaxed);
                let rate_ready = guard.constant_rate_enabled.load(Ordering::Relaxed);
                drop(guard);
                if !fixed_ready || !rate_ready {
                    self.log_internal(
                        "Strict anonymity mode blocked send: secure fixed-rate loops inactive."
                            .to_string(),
                    );
                    return -9;
                }
            }

            if let Ok(guard) = self.state.lock() {
                if let Ok(mut q) = guard.outgoing_queue.lock() {
                    q.push_back(OutgoingMessage {
                        msg_id: msg_id.clone(),
                        peer_id: peer_id.to_string(),
                        blob,
                    });
                }
                if let Ok(mut stats) = guard.traffic_stats.lock() {
                    stats.queued_real_messages += 1;
                }
            }
            return 0;
        }

        // 5. Send to Relay or P2P
        let send_result = self.runtime.block_on(async {
            if p2p_mode {
                if let (Some(p2p_client), Some(addr)) = (p2p_client, peer_addr) {
                    orchestrator::send_p2p_blob_with_retry(
                        &p2p_client,
                        &addr,
                        &blob,
                        3,
                        std::time::Duration::from_millis(100),
                        std::time::Duration::from_secs(5),
                    )
                    .await
                } else {
                    Err(anyhow::anyhow!(
                        "P2P mode enabled but no P2P client or peer address configured"
                    ))
                }
            } else if onion_routing {
                match (onion_router, relay) {
                    (Some(router), Some(relay)) => {
                        orchestrator::send_onion_blob_with_retry(
                            &router,
                            &relay,
                            &msg_id,
                            peer_id,
                            &blob,
                            3,
                            std::time::Duration::from_millis(100),
                            std::time::Duration::from_secs(5),
                        )
                        .await
                    }
                    (None, Some(_)) => Err(anyhow::anyhow!(
                        "Onion routing enabled but no onion router configured"
                    )),
                    (_, None) => Err(anyhow::anyhow!(
                        "Onion routing enabled but no relay client configured"
                    )),
                }
            } else {
                if let Some(relay) = relay {
                    orchestrator::send_blob_with_retry(
                        &relay,
                        &msg_id,
                        peer_id,
                        &blob,
                        3,
                        std::time::Duration::from_millis(100),
                        std::time::Duration::from_secs(5),
                    )
                    .await
                } else {
                    Err(anyhow::anyhow!("No relay client configured"))
                }
            }
        });

        if let Err(e) = send_result {
            self.log_internal(format!("Failed to send blob: {}", e));
            return -4;
        }

        // 6. Log to Blockchain (Best effort)
        if let Some(bc) = blockchain {
            let use_batching = blockchain_batching_enabled
                && !crate::config::blockchain_batch_per_message_fallback();
            if use_batching {
                let queued = if let Ok(guard) = self.state.lock() {
                    if let Ok(mut q) = guard.blockchain_queue.lock() {
                        q.push(QueuedBlockchainCommitment {
                            receiver_id: peer_id.to_string(),
                            message_hash: msg_hash,
                        });
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                // Fail-open to legacy behavior if queueing is temporarily unavailable.
                if !queued {
                    let pid = peer_id.to_string();
                    self.runtime.spawn(async move {
                        let _ = orchestrator::submit_tx_with_retry(
                            &bc,
                            &identity,
                            pid,
                            &msg_hash,
                            3,
                            std::time::Duration::from_millis(100),
                            std::time::Duration::from_secs(5),
                        )
                        .await;
                    });
                }
            } else {
                let pid = peer_id.to_string();
                self.runtime.spawn(async move {
                    let _ = orchestrator::submit_tx_with_retry(
                        &bc,
                        &identity,
                        pid,
                        &msg_hash,
                        3,
                        std::time::Duration::from_millis(100),
                        std::time::Duration::from_secs(5),
                    )
                    .await;
                });
            }
        }

        0
    }

    fn parse_untrusted_envelope_via_boundary(&self, blob: &[u8]) -> Result<Envelope, String> {
        let mut parser = self
            .untrusted_parser
            .lock()
            .map_err(|_| "untrusted parser boundary poisoned".to_string())?;
        parser.parse_envelope(blob)
    }

    fn parse_untrusted_inner_via_boundary(
        &self,
        expected_sender_id: &str,
        plaintext: &[u8],
    ) -> Result<InnerPayload, String> {
        let mut parser = self
            .untrusted_parser
            .lock()
            .map_err(|_| "untrusted parser boundary poisoned".to_string())?;
        parser.parse_inner_payload(expected_sender_id, plaintext)
    }

    fn parse_untrusted_initial_via_boundary(
        &self,
        ciphertext: &[u8],
    ) -> Result<InitialMessage, String> {
        let mut parser = self
            .untrusted_parser
            .lock()
            .map_err(|_| "untrusted parser boundary poisoned".to_string())?;
        parser.parse_initial_message(ciphertext)
    }

    pub fn poll_messages(&self) -> String {
        let mut new_messages = Vec::new();
        let mut guard = self.state.lock().unwrap();

        // Process all pending blobs fetched by the background poller
        let mut blobs = Vec::new();
        {
            let mut pending_queue = guard.pending_blobs.lock().unwrap();
            while let Some(item) = pending_queue.pop_front() {
                blobs.push(item);
            }
        }

        for (_msg_id, blob) in blobs {
            if let Err(reason) = validate_untrusted_envelope_blob_size(blob.len()) {
                append_log_locked(&mut guard, format!("Dropped untrusted blob: {reason}"));
                continue;
            }

            let env = match self.parse_untrusted_envelope_via_boundary(&blob) {
                Ok(env) => env,
                Err(reason) => {
                    append_log_locked(
                        &mut guard,
                        format!(
                            "Dropped untrusted envelope from relay via parser boundary: {reason}"
                        ),
                    );
                    continue;
                }
            };

            let mut processed = false;
            let mut attempted_existing_session = false;

            // Find session for sender
            let protocol_version_current = guard.protocol_version_current;
            let _ = guard.ensure_session_rekey_state(&env.sender_id, protocol_version_current);
            if let Some(reason) = guard.evaluate_session_rekey_requirement(&env.sender_id) {
                append_log_locked(
                    &mut guard,
                    format!(
                        "Dropped message from {}: forced rekey required ({})",
                        env.sender_id, reason
                    ),
                );
                continue;
            }
            if let Some(entry) = guard.sessions.get_mut(&env.sender_id) {
                attempted_existing_session = true;
                if let Some(session) = &mut entry.inner {
                    if let Ok(plaintext) = session.ratchet_decrypt(&env.ciphertext) {
                        let inner = match self
                            .parse_untrusted_inner_via_boundary(&env.sender_id, &plaintext)
                        {
                            Ok(inner) => inner,
                            Err(reason) => {
                                append_log_locked(
                                    &mut guard,
                                    format!(
                                        "Dropped untrusted decrypted payload from {}: {reason}",
                                        env.sender_id
                                    ),
                                );
                                guard.mark_session_rekey_pending(
                                    &env.sender_id,
                                    "compromise_indicator_untrusted_inner_payload",
                                );
                                continue;
                            }
                        };

                        let stored = StoredMessage {
                            id: hex::encode(crate::crypto::blake3::hash(&blob)), // Use blob hash as ID
                            timestamp: env.timestamp,
                            sender: env.sender_id.clone(),
                            content: inner.content,
                            msg_type: inner.msg_type,
                            group_id: inner.group_id,
                            read: false,
                        };
                        guard
                            .message_store
                            .entry(env.sender_id.clone())
                            .or_default()
                            .push(stored.clone());
                        guard.record_session_activity(&env.sender_id);
                        let _ = guard.evaluate_session_rekey_requirement(&env.sender_id);
                        new_messages.push(stored);
                        processed = true;
                    }
                }
            }

            if !processed && !attempted_existing_session {
                // Try to process as InitialMessage (Handshake)
                let initial_msg = match self.parse_untrusted_initial_via_boundary(&env.ciphertext) {
                    Ok(initial_msg) => initial_msg,
                    Err(reason) => {
                        append_log_locked(
                            &mut guard,
                            format!(
                                "Dropped untrusted initial handshake from {}: {reason}",
                                env.sender_id
                            ),
                        );
                        continue;
                    }
                };

                let my_id = guard.identity.clone();
                let mut secrets_opt = guard.prekey_secrets.clone();

                if let (Some(id), Some(mut secrets)) = (my_id, secrets_opt.as_mut()) {
                    if let Ok(shared_secret) =
                        crate::crypto::x3dh::respond_to_handshake(&id, &mut secrets, &initial_msg)
                    {
                        // Create session
                        let peer_ek = crate::crypto::x25519::PublicKey::from(
                            TryInto::<[u8; 32]>::try_into(initial_msg.ephemeral_key.as_slice())
                                .unwrap(),
                        );
                        let session = RatchetSession::new(shared_secret, Some(peer_ek));

                        let entry = SessionEntry {
                            wrapped_state: None,
                            inner: Some(session),
                            pending_handshake: None,
                            peer_seal_key: None,
                        };

                        guard.sessions.insert(env.sender_id.clone(), entry);
                        let session_protocol_version = initial_msg.protocol_version.unwrap_or(1);
                        guard.mark_session_established(
                            &env.sender_id,
                            session_protocol_version,
                            "initial_handshake",
                        );

                        // Update prekeys in state (one-time key might have been used)
                        guard.prekey_secrets = secrets_opt;

                        let stored = StoredMessage {
                            id: hex::encode(crate::crypto::blake3::hash(&blob)),
                            timestamp: env.timestamp,
                            sender: env.sender_id.clone(),
                            content: "New Session Established".to_string(),
                            msg_type: "system".to_string(),
                            group_id: None,
                            read: false,
                        };
                        guard
                            .message_store
                            .entry(env.sender_id.clone())
                            .or_default()
                            .push(stored.clone());
                        new_messages.push(stored);
                    }
                }
            }
        }

        serde_json::to_string(&new_messages).unwrap_or_else(|_| "[]".to_string())
    }

    pub fn send_file(&self, _peer_id: &str, _data: &[u8], _filename: &str) -> i32 {
        self.log_internal("File sending is disabled.".to_string());
        -1
    }
}

pub fn pad_envelope(data: Vec<u8>) -> Vec<u8> {
    data // Placeholder
}

pub fn pad_storage(data: Vec<u8>) -> Vec<u8> {
    data // Placeholder
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::IdentityKey;
    use crate::crypto::x25519;
    use crate::network::onion::OnionRouter;
    use crate::ratchet::double_ratchet::RatchetSession;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn seed_basic_session(engine: &ClientEngine, peer_id: &str) {
        let identity = IdentityKey::generate();
        let mut guard = engine.state.lock().unwrap();
        guard.identity = Some(identity);
        guard.sessions.insert(
            peer_id.to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(RatchetSession::new([7u8; 32], None)),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );
    }

    fn seed_strict_session(engine: &ClientEngine, peer_id: &str) {
        seed_basic_session(engine, peer_id);
        let (_, relay_pub) = x25519::generate_keypair();
        let onion_router = OnionRouter::new(vec![("https://relay.example".to_string(), relay_pub)]);
        let mut guard = engine.state.lock().unwrap();
        guard.onion_router = Some(onion_router);
    }

    #[test]
    fn redact_for_log_masks_long_hex_like_tokens() {
        let raw = "sender=0123456789abcdef0123456789abcdef";
        let redacted = redact_for_log(raw);
        assert!(!redacted.contains("0123456789abcdef0123456789abcdef"));
        assert!(redacted.contains("<redacted:"));
    }

    #[test]
    fn redact_for_log_keeps_short_operational_text() {
        let raw = "send failed for peer bob";
        let redacted = redact_for_log(raw);
        assert_eq!(redacted, raw);
    }

    #[test]
    fn strict_mode_blocks_direct_send_when_fixed_rate_loops_inactive() {
        let engine = ClientEngine::new();
        seed_strict_session(&engine, "peer-1");

        let rc = engine.send_payload("peer-1", "hello", "text", None, true, false, None);
        assert_eq!(
            rc, -9,
            "strict mode must fail-closed if fixed-rate loops are inactive"
        );

        let guard = engine.state.lock().unwrap();
        assert!(
            guard.outgoing_queue.lock().unwrap().is_empty(),
            "message must not bypass fixed-rate queue in strict mode"
        );
    }

    #[test]
    fn strict_mode_queues_real_messages_when_constant_rate_loop_is_active() {
        let engine = ClientEngine::new();
        seed_strict_session(&engine, "peer-2");
        {
            let guard = engine.state.lock().unwrap();
            guard.fixed_polling_enabled.store(true, Ordering::Relaxed);
            guard.constant_rate_enabled.store(true, Ordering::Relaxed);
        }

        let rc = engine.send_payload("peer-2", "queued", "text", None, true, false, None);
        assert_eq!(rc, 0);

        let guard = engine.state.lock().unwrap();
        let queue = guard.outgoing_queue.lock().unwrap();
        assert_eq!(queue.len(), 1, "expected one queued message");
        assert_eq!(queue.front().unwrap().peer_id, "peer-2");

        let stats = guard.traffic_stats.lock().unwrap();
        assert_eq!(stats.queued_real_messages, 1);
    }

    #[test]
    fn session_rekey_policy_marks_message_budget_exhaustion() {
        let mut state = AppState::new();
        state.forced_rekey_after_messages = 1;
        state.forced_rekey_after_secs = u64::MAX;
        state.sessions.insert(
            "peer-budget".to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(RatchetSession::new([5u8; 32], None)),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );

        state.record_session_activity("peer-budget");
        let reason = state.evaluate_session_rekey_requirement("peer-budget");
        assert_eq!(reason.as_deref(), Some("rekey_message_budget_exhausted"));
    }

    #[test]
    fn session_rekey_policy_marks_protocol_transition() {
        let mut state = AppState::new();
        state.protocol_version_current = 4;
        state.protocol_min_accepted_version = 1;
        state.sessions.insert(
            "peer-proto".to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(RatchetSession::new([8u8; 32], None)),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );
        state.mark_session_established("peer-proto", 3, "test_bootstrap");

        let reason = state.evaluate_session_rekey_requirement("peer-proto");
        assert_eq!(reason.as_deref(), Some("protocol_version_transition"));
    }

    #[test]
    fn send_payload_blocks_when_forced_rekey_is_pending() {
        let engine = ClientEngine::new();
        seed_basic_session(&engine, "peer-rekey");
        engine.mark_peer_for_rekey("peer-rekey", "compromise_indicator_manual");

        let rc = engine.send_payload("peer-rekey", "hello", "text", None, false, false, None);
        assert_eq!(rc, -10, "send must fail-closed when rekey is required");
    }

    #[test]
    fn mark_all_sessions_for_rekey_sets_pending_state() {
        let engine = ClientEngine::new();
        seed_basic_session(&engine, "peer-a");
        seed_basic_session(&engine, "peer-b");

        engine.mark_all_sessions_for_rekey("lifecycle_test");
        let mut guard = engine.state.lock().unwrap();
        let reason_a = guard.evaluate_session_rekey_requirement("peer-a");
        let reason_b = guard.evaluate_session_rekey_requirement("peer-b");
        assert_eq!(reason_a.as_deref(), Some("lifecycle_test"));
        assert_eq!(reason_b.as_deref(), Some("lifecycle_test"));
    }

    #[test]
    fn session_rekey_property_pending_state_is_sticky_after_trigger() {
        let mut rng = StdRng::seed_from_u64(0x1980_2026_A11C_E001);
        let mut state = AppState::new();
        state.protocol_version_current = 3;
        state.protocol_min_accepted_version = 1;
        state.forced_rekey_after_messages = 64;
        state.forced_rekey_after_secs = 3600;

        for idx in 0..96u32 {
            let peer = format!("peer-prop-{idx}");
            state.sessions.insert(
                peer.clone(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new([11u8; 32], None)),
                    pending_handshake: None,
                    peer_seal_key: None,
                },
            );

            let protocol_version = if idx % 5 == 0 { 2 } else { 3 };
            state.mark_session_established(&peer, protocol_version, "property_seed");

            let activity_steps: u64 = rng.gen_range(0..130);
            for _ in 0..activity_steps {
                state.record_session_activity(&peer);
            }

            if rng.gen_bool(0.25) {
                if let Some(session_state) = state.session_rekey_state.get_mut(&peer) {
                    session_state.last_rekey_at = session_state
                        .last_rekey_at
                        .saturating_sub(state.forced_rekey_after_secs.saturating_add(1));
                }
            }

            let first_reason = state.evaluate_session_rekey_requirement(&peer);
            if first_reason.is_some() {
                let sticky_reason = state.evaluate_session_rekey_requirement(&peer);
                assert_eq!(
                    sticky_reason, first_reason,
                    "pending forced rekey reason must stay sticky for {}",
                    peer,
                );
            }
        }
    }

    #[test]
    fn secure_wipe_zeroizes_sensitive_collections_and_tracks_report() {
        let engine = ClientEngine::new();
        {
            let mut guard = engine.state.lock().unwrap();
            guard.identity = Some(IdentityKey::generate());
            guard.message_store.insert(
                "peer-history".to_string(),
                vec![StoredMessage {
                    id: "m-secure".to_string(),
                    timestamp: unix_now_secs(),
                    sender: "peer-history".to_string(),
                    content: "classified payload".to_string(),
                    msg_type: "text".to_string(),
                    group_id: Some("group-secret".to_string()),
                    read: false,
                }],
            );
            guard
                .attachment_cache
                .insert("attachment-secret".to_string(), vec![0xAA; 80]);
            guard.log_buffer.push_back("sensitive log line".to_string());
            guard
                .nicknames
                .insert("peer-history".to_string(), "alias".to_string());
            guard
                .groups
                .insert("group-secret".to_string(), vec!["peer-history".to_string()]);
            guard.blocked_peers.insert("peer-blocked".to_string());
            guard.auto_delete_timers.insert("m-secure".to_string(), 60);
            guard.sessions.insert(
                "peer-session".to_string(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new([3u8; 32], None)),
                    pending_handshake: Some("hs".to_string()),
                    peer_seal_key: Some(vec![7u8; 16]),
                },
            );
            guard
                .pending_blobs
                .lock()
                .unwrap()
                .push_back(("pending-1".to_string(), vec![0x10, 0x11, 0x12, 0x13]));
            guard
                .outgoing_queue
                .lock()
                .unwrap()
                .push_back(OutgoingMessage {
                    msg_id: "out-1".to_string(),
                    peer_id: "peer-history".to_string(),
                    blob: vec![0x22; 12],
                });
            guard.commitment_proofs.lock().unwrap().insert(
                "proof-1".to_string(),
                CommitmentInclusionProof {
                    message_hash: "aa".repeat(32),
                    merkle_root: "bb".repeat(32),
                    receiver_commitment: "cc".repeat(32),
                    leaf_index: 0,
                    siblings: vec!["dd".repeat(32)],
                    batch_size: 1,
                    submitted_at: unix_now_secs(),
                },
            );
        }

        engine.wipe_memory();

        let guard = engine.state.lock().unwrap();
        assert!(guard.identity.is_none());
        assert!(guard.message_store.is_empty());
        assert!(guard.attachment_cache.is_empty());
        assert!(guard.sessions.is_empty());
        assert!(guard.nicknames.is_empty());
        assert!(guard.groups.is_empty());
        assert!(guard.blocked_peers.is_empty());
        assert!(guard.auto_delete_timers.is_empty());
        assert!(guard.pending_blobs.lock().unwrap().is_empty());
        assert!(guard.outgoing_queue.lock().unwrap().is_empty());
        assert!(guard.commitment_proofs.lock().unwrap().is_empty());
        assert_eq!(guard.log_buffer.len(), 1);
        assert!(
            guard
                .log_buffer
                .front()
                .is_some_and(|line| line.contains("Memory wiped securely")),
            "wipe audit log entry expected"
        );
        assert!(guard.last_zeroization_report.message_entries >= 1);
        assert!(guard.last_zeroization_report.attachment_entries >= 1);
        assert!(guard.last_zeroization_report.session_entries >= 1);
        assert!(guard.last_zeroization_report.log_entries >= 1);
        assert!(guard.last_zeroization_report.pending_blob_entries >= 1);
        assert!(guard.last_zeroization_report.outgoing_entries >= 1);
        assert!(guard.last_zeroization_report.proof_entries >= 1);
        assert!(guard.last_zeroization_report.metadata_entries >= 1);
    }

    #[test]
    fn untrusted_envelope_blob_size_gate_rejects_oversized() {
        let too_big = MAX_UNTRUSTED_ENVELOPE_BLOB_BYTES + 1;
        assert!(validate_untrusted_envelope_blob_size(too_big).is_err());
    }

    #[test]
    fn untrusted_envelope_gate_rejects_invalid_sender() {
        let env = Envelope {
            mailbox_id: "mailbox-1".to_string(),
            sender_id: "bad sender with spaces".to_string(),
            timestamp: unix_now_secs(),
            ciphertext: vec![1, 2, 3],
            pow_nonce: 0,
        };
        assert!(validate_untrusted_envelope(&env).is_err());
    }

    #[test]
    fn untrusted_inner_payload_gate_rejects_sender_mismatch() {
        let env = Envelope {
            mailbox_id: "mailbox-1".to_string(),
            sender_id: "sender-1".to_string(),
            timestamp: unix_now_secs(),
            ciphertext: vec![1, 2, 3],
            pow_nonce: 0,
        };
        let inner = InnerPayload {
            sender_id: "sender-2".to_string(),
            content: "hello".to_string(),
            msg_type: "text".to_string(),
            signature: vec![],
            group_id: None,
            counter: 0,
            commitment_nonce: 0,
        };
        assert!(validate_untrusted_inner_payload(&env, &inner, 32).is_err());
    }

    #[test]
    fn untrusted_inner_payload_gate_rejects_non_textual_message_type() {
        let env = Envelope {
            mailbox_id: "mailbox-1".to_string(),
            sender_id: "sender-1".to_string(),
            timestamp: unix_now_secs(),
            ciphertext: vec![1, 2, 3],
            pow_nonce: 0,
        };
        let inner = InnerPayload {
            sender_id: "sender-1".to_string(),
            content: "metadata for attachment".to_string(),
            msg_type: "attachment".to_string(),
            signature: vec![],
            group_id: None,
            counter: 0,
            commitment_nonce: 0,
        };
        assert!(validate_untrusted_inner_payload(&env, &inner, 64).is_err());
    }

    #[test]
    fn poll_messages_drops_non_text_message_type_in_poll_path() {
        let engine = ClientEngine::new();
        let sender_id = "peer-attachment";
        let shared_secret = [9u8; 32];
        let mut sender_session = RatchetSession::new(shared_secret, None);

        {
            let mut guard = engine.state.lock().unwrap();
            guard.sessions.insert(
                sender_id.to_string(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new(shared_secret, None)),
                    pending_handshake: None,
                    peer_seal_key: None,
                },
            );
        }

        let inner = InnerPayload {
            sender_id: sender_id.to_string(),
            content: "{\"kind\":\"image\",\"blob\":\"deadbeef\"}".to_string(),
            msg_type: "attachment".to_string(),
            signature: vec![],
            group_id: None,
            counter: 0,
            commitment_nonce: 0,
        };
        let inner_bytes = serde_json::to_vec(&inner).unwrap();
        let ciphertext = sender_session.ratchet_encrypt(&inner_bytes).unwrap();
        let envelope = Envelope {
            mailbox_id: "mailbox-1".to_string(),
            sender_id: sender_id.to_string(),
            timestamp: unix_now_secs(),
            ciphertext,
            pow_nonce: 0,
        };
        let blob = serde_json::to_vec(&envelope).unwrap();

        {
            let guard = engine.state.lock().unwrap();
            guard
                .pending_blobs
                .lock()
                .unwrap()
                .push_back(("msg-attachment".to_string(), blob));
        }

        let response = engine.poll_messages();
        let parsed: Vec<StoredMessage> = serde_json::from_str(&response).unwrap();
        assert!(parsed.is_empty(), "non-text payload must not be surfaced");

        let guard = engine.state.lock().unwrap();
        if let Some(messages) = guard.message_store.get(sender_id) {
            assert!(messages.is_empty(), "non-text payload must not be stored");
        }
        assert!(
            guard
                .log_buffer
                .iter()
                .any(|line| line.contains("invalid msg_type format")),
            "drop reason should be recorded for regression visibility"
        );
    }

    #[test]
    fn untrusted_initial_message_gate_rejects_invalid_pq_ciphertext_size() {
        let initial = InitialMessage {
            identity_key: vec![0u8; 32],
            ephemeral_key: vec![1u8; 32],
            one_time_prekey_id: None,
            ciphertext: vec![],
            handshake_mode: Some("classic".to_string()),
            protocol_version: Some(2),
            #[cfg(feature = "pq")]
            pq_ciphertext: Some(vec![0u8; MAX_UNTRUSTED_PQ_CIPHERTEXT_BYTES + 1]),
        };
        #[cfg(feature = "pq")]
        assert!(validate_untrusted_initial_message(&initial).is_err());
        #[cfg(not(feature = "pq"))]
        assert!(validate_untrusted_initial_message(&initial).is_ok());
    }

    #[test]
    fn fuzz_classify_blob_drops_unknown_envelope_fields() {
        let blob = br#"{"mailbox_id":"mailbox-1","sender_id":"sender-1","timestamp":1,"ciphertext":[1,2,3],"pow_nonce":0,"unknown":"x"}"#;
        let class = fuzz_classify_untrusted_blob(blob);
        assert_eq!(class, FUZZ_CLASS_DROPPED_ENVELOPE_PARSE);
    }

    #[test]
    fn fuzz_classify_blob_marks_valid_handshake_candidate() {
        let initial = InitialMessage {
            identity_key: vec![0u8; 32],
            ephemeral_key: vec![1u8; 32],
            one_time_prekey_id: None,
            ciphertext: vec![],
            handshake_mode: Some("classic".to_string()),
            protocol_version: Some(2),
            #[cfg(feature = "pq")]
            pq_ciphertext: None,
        };
        let initial_bytes = serde_json::to_vec(&initial).unwrap();
        let env = Envelope {
            mailbox_id: "mailbox-1".to_string(),
            sender_id: "sender-1".to_string(),
            timestamp: unix_now_secs(),
            ciphertext: initial_bytes,
            pow_nonce: 0,
        };
        let blob = serde_json::to_vec(&env).unwrap();
        let class = fuzz_classify_untrusted_blob(&blob);
        assert_eq!(class, FUZZ_CLASS_ACCEPTED_HANDSHAKE);
    }

    #[test]
    fn fuzz_inner_payload_validation_rejects_unknown_fields() {
        let plaintext = br#"{"sender_id":"sender-1","content":"hi","msg_type":"text","signature":[],"group_id":null,"counter":0,"commitment_nonce":0,"unexpected":true}"#;
        assert!(!fuzz_validate_untrusted_inner_payload(
            "sender-1", plaintext
        ));
    }

    fn parser_client_for_test_with_mask(
        mode: UntrustedParserMode,
        parser_class_mask: u8,
    ) -> UntrustedParserWorkerClient {
        UntrustedParserWorkerClient {
            timeout: Duration::from_millis(10),
            max_input_bytes: MAX_UNTRUSTED_ENVELOPE_BLOB_BYTES,
            parser_class_mask,
            mode,
            child: None,
            stdin: None,
            stdout: None,
            worker_launches: 0,
            worker_launch_failures: 0,
            worker_restarts: 0,
            worker_timeouts: 0,
            requests_total: 0,
            parse_denials: 0,
            io_failures: 0,
            protocol_mismatches: 0,
            last_error: None,
        }
    }

    fn parser_client_for_test(mode: UntrustedParserMode) -> UntrustedParserWorkerClient {
        parser_client_for_test_with_mask(mode, parse_parser_class_allowlist(None))
    }

    #[test]
    fn parser_boundary_fail_closed_when_worker_disabled() {
        let env = Envelope {
            mailbox_id: "mailbox-1".to_string(),
            sender_id: "sender-1".to_string(),
            timestamp: unix_now_secs(),
            ciphertext: vec![1, 2, 3],
            pow_nonce: 0,
        };
        let blob = serde_json::to_vec(&env).unwrap();
        let mut client = parser_client_for_test(UntrustedParserMode::Disabled);

        let err = match client.parse_envelope(&blob) {
            Ok(_) => panic!("expected parser boundary failure in disabled mode"),
            Err(err) => err,
        };
        assert!(err.contains("disabled"));
        assert_eq!(client.parse_denials, 1);
        assert_eq!(client.requests_total, 1);
        assert_eq!(client.mode_name(), "disabled");
    }

    #[test]
    fn parser_worker_command_detection_is_explicit() {
        let args = vec![
            "redoor-client".to_string(),
            "untrusted-parser-worker".to_string(),
        ];
        assert!(is_untrusted_parser_worker_command(&args));

        let args = vec!["redoor-client".to_string(), "scripted-loopback".to_string()];
        assert!(!is_untrusted_parser_worker_command(&args));
    }

    #[test]
    fn parser_allowlist_parser_ignores_unknown_tokens() {
        let mask = parse_parser_class_allowlist(Some(
            "envelope_json,unknown_class,inner_payload_json".to_string(),
        ));
        assert_ne!(
            mask & parser_class_bit(UntrustedParserClass::EnvelopeJson),
            0
        );
        assert_ne!(
            mask & parser_class_bit(UntrustedParserClass::InnerPayloadJson),
            0
        );
        assert_eq!(
            mask & parser_class_bit(UntrustedParserClass::InitialMessageJson),
            0
        );
    }

    #[test]
    fn parser_policy_rejects_disabled_parser_class() {
        let mask = parser_class_bit(UntrustedParserClass::EnvelopeJson);
        let mut client = parser_client_for_test_with_mask(UntrustedParserMode::InlineUnsafe, mask);

        let err = match client.parse_inner_payload("sender-1", br#"{"sender_id":"sender-1"}"#) {
            Ok(_) => panic!("expected parser class denial"),
            Err(err) => err,
        };
        assert!(err.contains("inner_payload_json"));
        assert_eq!(client.parse_denials, 1);
    }

    #[test]
    fn untrusted_json_structure_rejects_excessive_depth() {
        let payload = br#"{"outer":[[[[[[[[[[[[[1]]]]]]]]]]]]]}"#;
        assert!(
            validate_untrusted_json_structure(payload, 4, 10_000).is_err(),
            "excessive nesting should be rejected"
        );
    }
}
