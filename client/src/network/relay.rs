use crate::config;
use anyhow::{anyhow, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use reqwest::{Client, Proxy, StatusCode};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use x509_parser::parse_x509_certificate;

#[derive(Clone, Default)]
struct RelayTlsConfig {
    pinned_ca_der: Option<Vec<u8>>,
    pinned_spki_sha256: Option<Vec<u8>>,
}

#[derive(Clone)]
struct RelayTransportProfile {
    enabled: bool,
    user_agent: String,
    connection_header: String,
    force_http1_only: bool,
}

#[derive(Clone)]
struct ScopedCredential {
    token: String,
    token_sig_b64: String,
    token_fingerprint: String,
    secret: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RelayConnectionMetricsSnapshot {
    pub rtt_ms: u64,
    pub packet_loss_percent: f32,
    pub throughput_kbps: u64,
}

#[derive(Debug)]
struct RelayConnectionMetricsState {
    started_at: Instant,
    requests_total: u64,
    requests_failed: u64,
    requests_success: u64,
    total_rtt_ms: u128,
    bytes_transferred: u64,
}

impl Default for RelayConnectionMetricsState {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            requests_total: 0,
            requests_failed: 0,
            requests_success: 0,
            total_rtt_ms: 0,
            bytes_transferred: 0,
        }
    }
}

#[derive(Default)]
struct ScopedAuthState {
    endpoint_unavailable: bool,
    credential: Option<ScopedCredential>,
}

#[derive(serde::Deserialize)]
struct ScopedRegisterResponse {
    scoped_token: Option<String>,
    scoped_token_sig_b64: Option<String>,
    token_secret_b64: Option<String>,
    token_fingerprint: Option<String>,
    client_id: Option<String>,
    client_secret_b64: Option<String>,
    expires_at: u64,
}

enum ScopedRegisterError {
    EndpointUnavailable,
    Other,
}

const DEFAULT_SCOPED_REFRESH_WINDOW_SEC: u64 = 300;
const MIN_SCOPED_CREDENTIAL_VALIDITY_SEC: u64 = 15;
const MAILBOX_HANDLE_VERSION: &str = "mb1";
const DEFAULT_MAILBOX_EPOCH_SEC: u64 = 300;
const DEFAULT_MAILBOX_FETCH_PAST_EPOCHS: u64 = 2;
const DEFAULT_MAILBOX_BATCH_MAX_HANDLES: usize = 8;
const DEFAULT_MAILBOX_DECOY_FETCH_COUNT_SECURE: usize = 2;
const DEFAULT_FETCH_PENDING_MIRROR_MAX: usize = 2;
const DEFAULT_FETCH_PENDING_RELAY_QUORUM: usize = 1;

enum RequestAuthMode {
    Scoped {
        token: String,
        token_sig_b64: String,
        request_sig: String,
        timestamp: String,
        nonce: String,
    },
    Legacy {
        hmac: String,
        timestamp: String,
        nonce: String,
    },
    None,
}

impl RequestAuthMode {
    fn uses_legacy_hmac(&self) -> bool {
        matches!(self, Self::Legacy { .. })
    }
}

enum BatchFetchAttemptResult {
    Hit((String, Vec<u8>)),
    Miss,
    EndpointUnavailable,
}

enum FetchPendingRelayResult {
    Hit((String, Vec<u8>)),
    Miss,
}

#[derive(Clone, Debug)]
struct RelayHitCandidate {
    id: String,
    blob: Vec<u8>,
    confirmations: usize,
    first_relay_url: String,
}

// Relay Node Interaction
#[derive(Clone)]
pub struct RelayClient {
    pub base_url: String,
    client: Client,
    hmac_key: Option<Vec<u8>>,
    tls_config: RelayTlsConfig,
    transport_profile: RelayTransportProfile,
    scoped_auth_state: Arc<Mutex<ScopedAuthState>>,
    connection_metrics: Arc<std::sync::Mutex<RelayConnectionMetricsState>>,
}

impl RelayClient {
    pub fn new(relay_url: &str) -> Self {
        let hmac_key = std::env::var("RELAY_HMAC_KEY")
            .ok()
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());
        let tls_config = resolve_relay_tls_config();
        let transport_profile = resolve_relay_transport_profile();

        let client = build_client(&tls_config, &transport_profile);

        Self {
            client,
            base_url: relay_url.to_string(),
            hmac_key,
            tls_config,
            transport_profile,
            scoped_auth_state: Arc::new(Mutex::new(ScopedAuthState::default())),
            connection_metrics: Arc::new(std::sync::Mutex::new(
                RelayConnectionMetricsState::default(),
            )),
        }
    }

    /// Create a client with an explicit Base64-encoded HMAC key (avoids env lookup on mobile).
    #[allow(dead_code)]
    pub fn new_with_hmac_b64(relay_url: &str, key_b64: &str) -> Result<Self> {
        let hmac_key = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| anyhow!("Invalid base64 HMAC key: {}", e))?;
        let tls_config = resolve_relay_tls_config();
        let transport_profile = resolve_relay_transport_profile();

        Ok(Self {
            client: build_client(&tls_config, &transport_profile),
            base_url: relay_url.to_string(),
            hmac_key: Some(hmac_key),
            tls_config,
            transport_profile,
            scoped_auth_state: Arc::new(Mutex::new(ScopedAuthState::default())),
            connection_metrics: Arc::new(std::sync::Mutex::new(
                RelayConnectionMetricsState::default(),
            )),
        })
    }

    pub fn connection_metrics_snapshot(&self) -> RelayConnectionMetricsSnapshot {
        let guard = match self.connection_metrics.lock() {
            Ok(v) => v,
            Err(_) => return RelayConnectionMetricsSnapshot::default(),
        };

        let rtt_ms = if guard.requests_success == 0 {
            0
        } else {
            (guard.total_rtt_ms / guard.requests_success as u128) as u64
        };
        let packet_loss_percent = if guard.requests_total == 0 {
            0.0
        } else {
            (guard.requests_failed as f32 * 100.0) / guard.requests_total as f32
        };
        let elapsed_ms = guard.started_at.elapsed().as_millis().max(1) as u64;
        let throughput_kbps = (guard.bytes_transferred.saturating_mul(8)) / elapsed_ms;

        RelayConnectionMetricsSnapshot {
            rtt_ms,
            packet_loss_percent,
            throughput_kbps,
        }
    }

    fn record_request_outcome(
        &self,
        rtt: Duration,
        bytes_sent: usize,
        bytes_received: usize,
        success: bool,
    ) {
        let mut guard = match self.connection_metrics.lock() {
            Ok(v) => v,
            Err(_) => return,
        };

        guard.requests_total = guard.requests_total.saturating_add(1);
        if success {
            guard.requests_success = guard.requests_success.saturating_add(1);
            guard.total_rtt_ms = guard.total_rtt_ms.saturating_add(rtt.as_millis());
        } else {
            guard.requests_failed = guard.requests_failed.saturating_add(1);
        }
        guard.bytes_transferred = guard
            .bytes_transferred
            .saturating_add(bytes_sent.saturating_add(bytes_received) as u64);
    }

    #[cfg(test)]
    pub fn record_connection_sample_for_tests(
        &self,
        rtt: Duration,
        bytes_sent: usize,
        bytes_received: usize,
        success: bool,
    ) {
        self.record_request_outcome(rtt, bytes_sent, bytes_received, success);
    }

    pub async fn send_blob(&self, id: &str, receiver: &str, blob: &[u8]) -> Result<()> {
        self.send_blob_internal(id, receiver, blob, false).await
    }

    /// Send a blob that should be retained after direct fetches.
    /// Intended for public prekey bundles keyed by a stable identifier.
    pub async fn send_blob_persistent(&self, id: &str, receiver: &str, blob: &[u8]) -> Result<()> {
        self.send_blob_internal(id, receiver, blob, true).await
    }

    async fn send_blob_internal(
        &self,
        id: &str,
        receiver: &str,
        blob: &[u8],
        persistent: bool,
    ) -> Result<()> {
        ensure_https(&self.base_url)?;
        self.verify_server_pin()?;
        let blob = normalize_transport_payload(blob)?;
        maybe_delay();

        // Rotate mailbox handles by epoch to prevent stable receiver metadata.
        let blinded_receiver = derive_current_mailbox_handle(receiver);

        let mut req = self
            .client
            .post(&format!("{}/relay", self.base_url))
            .header("X-Message-ID", id)
            .header("X-Receiver-ID", &blinded_receiver)
            .body(blob.clone());
        req = apply_transport_profile_headers(req, &self.transport_profile);
        if persistent {
            req = req.header("X-Persistent", "true");
        }

        let auth = self
            .prepare_request_auth("POST", "/relay", id, &blinded_receiver, &blob)
            .await?;
        req = apply_request_auth_headers(req, &auth);

        let started = Instant::now();
        let res = match req.send().await {
            Ok(v) => v,
            Err(e) => {
                self.record_request_outcome(started.elapsed(), blob.len(), 0, false);
                return Err(e.into());
            }
        };

        if res.status().is_success() {
            if auth.uses_legacy_hmac() {
                let key = self
                    .hmac_key
                    .as_ref()
                    .ok_or_else(|| anyhow!("legacy auth mode selected without key"))?;
                if let Some(server_mac) = res.headers().get("X-HMAC").and_then(|v| v.to_str().ok())
                {
                    let expected = compute_hmac(key, id, &blinded_receiver, &blob)?;
                    if server_mac != expected {
                        return Err(anyhow!("Relay ACK HMAC verification failed"));
                    }
                }
            }
            self.record_request_outcome(started.elapsed(), blob.len(), 0, true);
            Ok(())
        } else {
            self.record_request_outcome(started.elapsed(), blob.len(), 0, false);
            Err(anyhow!("Failed to send blob"))
        }
    }

    #[allow(dead_code)]
    pub async fn fetch_blob(&self, id: &str) -> Result<Vec<u8>> {
        ensure_https(&self.base_url)?;
        self.verify_server_pin()?;
        let mut req = self
            .client
            .get(&format!("{}/fetch?id={}", self.base_url, id));
        req = apply_transport_profile_headers(req, &self.transport_profile);

        let auth = self
            .prepare_request_auth("GET", "/fetch", id, "", b"")
            .await?;
        req = apply_request_auth_headers(req, &auth);

        let started = Instant::now();
        let res = match req.send().await {
            Ok(v) => v,
            Err(e) => {
                self.record_request_outcome(started.elapsed(), 0, 0, false);
                return Err(e.into());
            }
        };

        if !res.status().is_success() {
            self.record_request_outcome(started.elapsed(), 0, 0, false);
            return Err(anyhow!("Failed to fetch blob"));
        }

        let headers = res.headers().clone();
        let hmac_header = headers
            .get("X-HMAC")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let pad_header = headers.get("X-Pad-Len").cloned();

        let bytes = res.bytes().await?;

        if auth.uses_legacy_hmac() {
            let key = self
                .hmac_key
                .as_ref()
                .ok_or_else(|| anyhow!("legacy auth mode selected without key"))?;
            let mac = hmac_header.ok_or_else(|| anyhow!("Missing X-HMAC on fetch response"))?;
            let expected = compute_hmac(key, id, "", &bytes)?;
            if mac != expected {
                self.record_request_outcome(started.elapsed(), 0, bytes.len(), false);
                return Err(anyhow!("HMAC verification failed for fetch blob"));
            }
        }

        let trimmed = match trim_pad(bytes.to_vec(), pad_header.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                self.record_request_outcome(started.elapsed(), 0, bytes.len(), false);
                return Err(e);
            }
        };
        let decoded = match decode_transport_payload(trimmed) {
            Ok(v) => v,
            Err(e) => {
                self.record_request_outcome(started.elapsed(), 0, bytes.len(), false);
                return Err(e);
            }
        };

        self.record_request_outcome(started.elapsed(), 0, bytes.len(), true);
        Ok(decoded)
    }

    pub async fn fetch_pending(&self, receiver: &str) -> Result<(String, Vec<u8>)> {
        let real_candidates = derive_fetch_mailbox_candidates(receiver);
        let relay_urls = fetch_pending_relay_urls(&self.base_url);
        let quorum = fetch_pending_relay_quorum();
        let best_effort_fallback = fetch_pending_quorum_best_effort_enabled();

        if relay_urls.is_empty() {
            return Err(anyhow!("No relay URLs configured for pending fetch"));
        }

        let mut join_set = JoinSet::new();
        for relay_url in relay_urls {
            let relay_client = if relay_url == self.base_url {
                self.clone()
            } else {
                self.clone_for_base_url(relay_url.clone())
            };
            let receiver_owned = receiver.to_string();
            let real_candidates_owned = real_candidates.clone();
            let relay_url_owned = relay_url.clone();
            join_set.spawn(async move {
                (
                    relay_url_owned,
                    relay_client
                        .fetch_pending_single_relay(&receiver_owned, &real_candidates_owned)
                        .await,
                )
            });
        }

        let mut hits = Vec::new();
        let mut last_error: Option<anyhow::Error> = None;
        let mut saw_miss = false;

        while let Some(joined) = join_set.join_next().await {
            match joined {
                Ok((relay_url, Ok(FetchPendingRelayResult::Hit((id, blob))))) => {
                    hits.push((relay_url, id, blob));
                }
                Ok((_relay_url, Ok(FetchPendingRelayResult::Miss))) => {
                    saw_miss = true;
                }
                Ok((_relay_url, Err(err))) => {
                    last_error = Some(err);
                }
                Err(join_err) => {
                    last_error = Some(anyhow!("parallel fetch worker failed: {}", join_err));
                }
            }
        }

        finalize_fetch_pending_outcome(
            &merge_fetch_pending_hits(hits),
            quorum,
            best_effort_fallback,
            saw_miss,
            last_error,
        )
    }

    fn clone_for_base_url(&self, relay_url: String) -> Self {
        Self {
            base_url: relay_url,
            client: build_client(&self.tls_config, &self.transport_profile),
            hmac_key: self.hmac_key.clone(),
            tls_config: self.tls_config.clone(),
            transport_profile: self.transport_profile.clone(),
            scoped_auth_state: Arc::new(Mutex::new(ScopedAuthState::default())),
            connection_metrics: Arc::new(std::sync::Mutex::new(
                RelayConnectionMetricsState::default(),
            )),
        }
    }

    async fn fetch_pending_single_relay(
        &self,
        receiver: &str,
        real_candidates: &[String],
    ) -> Result<FetchPendingRelayResult> {
        if mailbox_batch_fetch_enabled() {
            match self.fetch_pending_batch(receiver, real_candidates).await {
                Ok(BatchFetchAttemptResult::Hit(hit)) => {
                    return Ok(FetchPendingRelayResult::Hit(hit));
                }
                Ok(BatchFetchAttemptResult::Miss) => {
                    return Ok(FetchPendingRelayResult::Miss);
                }
                Ok(BatchFetchAttemptResult::EndpointUnavailable) => {}
                Err(err) => return Err(err),
            }
        }

        for handle in real_candidates {
            match self.fetch_pending_with_handle(handle).await {
                Ok(Some(result)) => return Ok(FetchPendingRelayResult::Hit(result)),
                Ok(None) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(FetchPendingRelayResult::Miss)
    }

    async fn fetch_pending_batch(
        &self,
        receiver: &str,
        real_candidates: &[String],
    ) -> Result<BatchFetchAttemptResult> {
        if real_candidates.is_empty() {
            return Ok(BatchFetchAttemptResult::Miss);
        }
        let batch_handles = build_batch_fetch_handles(receiver, real_candidates);
        if batch_handles.is_empty() {
            return Ok(BatchFetchAttemptResult::Miss);
        }

        ensure_https(&self.base_url)?;
        self.verify_server_pin()?;

        #[derive(serde::Serialize)]
        struct PendingBatchReq {
            receivers: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        struct PendingBatchItem {
            receiver: String,
            hit: bool,
            id: Option<String>,
            blob_base64: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct PendingBatchResp {
            results: Vec<PendingBatchItem>,
        }

        let req_body = serde_json::to_vec(&PendingBatchReq {
            receivers: batch_handles,
        })?;

        let mut req = self
            .client
            .post(&format!("{}/fetch_pending_batch", self.base_url))
            .header("Content-Type", "application/json")
            .body(req_body.clone());
        req = apply_transport_profile_headers(req, &self.transport_profile);

        let auth = self
            .prepare_request_auth("POST", "/fetch_pending_batch", "", "", &req_body)
            .await?;
        req = apply_request_auth_headers(req, &auth);

        let started = Instant::now();
        let res = match req.send().await {
            Ok(v) => v,
            Err(e) => {
                self.record_request_outcome(started.elapsed(), req_body.len(), 0, false);
                return Err(e.into());
            }
        };
        if res.status() == StatusCode::NOT_FOUND || res.status() == StatusCode::METHOD_NOT_ALLOWED {
            self.record_request_outcome(started.elapsed(), req_body.len(), 0, true);
            return Ok(BatchFetchAttemptResult::EndpointUnavailable);
        }
        if !res.status().is_success() {
            self.record_request_outcome(started.elapsed(), req_body.len(), 0, false);
            return Err(anyhow!(
                "batch fetch pending failed with status {}",
                res.status()
            ));
        }

        let hmac_header = res
            .headers()
            .get("X-HMAC")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = res.bytes().await?;
        if auth.uses_legacy_hmac() {
            let key = self
                .hmac_key
                .as_ref()
                .ok_or_else(|| anyhow!("legacy auth mode selected without key"))?;
            let mac =
                hmac_header.ok_or_else(|| anyhow!("Missing X-HMAC on batch pending response"))?;
            let expected = compute_hmac_bytes(key, &body_bytes)?;
            if mac != expected {
                return Err(anyhow!(
                    "HMAC verification failed for batch pending response"
                ));
            }
        }

        let parsed: PendingBatchResp = serde_json::from_slice(&body_bytes)?;
        let mut rank_by_receiver: HashMap<String, usize> = HashMap::new();
        for (idx, handle) in real_candidates.iter().enumerate() {
            rank_by_receiver.entry(handle.clone()).or_insert(idx);
        }

        let mut best_hit: Option<(usize, String, Vec<u8>)> = None;
        for item in parsed.results {
            if !item.hit {
                continue;
            }
            let Some(rank) = rank_by_receiver.get(&item.receiver).copied() else {
                continue;
            };
            let id = item
                .id
                .ok_or_else(|| anyhow!("batch fetch response missing id"))?;
            let blob_b64 = item
                .blob_base64
                .ok_or_else(|| anyhow!("batch fetch response missing blob_base64"))?;
            let raw_blob = base64::engine::general_purpose::STANDARD.decode(blob_b64)?;
            let blob = decode_transport_payload(raw_blob)?;

            match &best_hit {
                Some((best_rank, _, _)) if *best_rank <= rank => {}
                _ => best_hit = Some((rank, id, blob)),
            }
        }

        if let Some((_, id, blob)) = best_hit {
            self.record_request_outcome(started.elapsed(), req_body.len(), body_bytes.len(), true);
            Ok(BatchFetchAttemptResult::Hit((id, blob)))
        } else {
            self.record_request_outcome(started.elapsed(), req_body.len(), body_bytes.len(), true);
            Ok(BatchFetchAttemptResult::Miss)
        }
    }

    async fn fetch_pending_with_handle(
        &self,
        blinded_receiver: &str,
    ) -> Result<Option<(String, Vec<u8>)>> {
        ensure_https(&self.base_url)?;
        self.verify_server_pin()?;

        #[derive(serde::Deserialize)]
        struct PendingResp {
            id: String,
            blob_base64: String,
        }

        let mut req = self.client.get(&format!(
            "{}/fetch_pending?receiver={}",
            self.base_url, blinded_receiver
        ));
        req = apply_transport_profile_headers(req, &self.transport_profile);

        let auth = self
            .prepare_request_auth("GET", "/fetch_pending", "", blinded_receiver, b"")
            .await?;
        req = apply_request_auth_headers(req, &auth);

        let started = Instant::now();
        let res = match req.send().await {
            Ok(v) => v,
            Err(e) => {
                self.record_request_outcome(started.elapsed(), 0, 0, false);
                return Err(e.into());
            }
        };
        if res.status() == StatusCode::NOT_FOUND
            || res.status() == StatusCode::BAD_REQUEST
            || res.status() == StatusCode::GONE
        {
            self.record_request_outcome(started.elapsed(), 0, 0, true);
            return Ok(None);
        }
        if !res.status().is_success() {
            self.record_request_outcome(started.elapsed(), 0, 0, false);
            return Err(anyhow!("fetch pending failed with status {}", res.status()));
        }

        let hmac_header = res
            .headers()
            .get("X-HMAC")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = res.bytes().await?;
        if auth.uses_legacy_hmac() {
            let key = self
                .hmac_key
                .as_ref()
                .ok_or_else(|| anyhow!("legacy auth mode selected without key"))?;
            let mac = hmac_header.ok_or_else(|| anyhow!("Missing X-HMAC on pending response"))?;
            let expected = compute_hmac_bytes(key, &body_bytes)?;
            if mac != expected {
                return Err(anyhow!("HMAC verification failed for pending blob"));
            }
        }

        let parsed: PendingResp = serde_json::from_slice(&body_bytes)?;
        let raw_blob = base64::engine::general_purpose::STANDARD.decode(parsed.blob_base64)?;
        let blob = decode_transport_payload(raw_blob)?;
        self.record_request_outcome(started.elapsed(), 0, body_bytes.len(), true);
        Ok(Some((parsed.id, blob)))
    }

    async fn prepare_request_auth(
        &self,
        method: &str,
        path: &str,
        id: &str,
        receiver: &str,
        body: &[u8],
    ) -> Result<RequestAuthMode> {
        if let Some(cred) = self.maybe_get_scoped_credential().await {
            let (timestamp, nonce) = hmac_request_metadata();
            let request_sig = compute_scoped_request_signature(
                &cred.secret,
                &cred.token_fingerprint,
                method,
                path,
                id,
                receiver,
                body,
                &timestamp,
                &nonce,
            )?;
            return Ok(RequestAuthMode::Scoped {
                token: cred.token,
                token_sig_b64: cred.token_sig_b64,
                request_sig,
                timestamp,
                nonce,
            });
        }

        if let Some(key) = &self.hmac_key {
            let (timestamp, nonce) = hmac_request_metadata();
            let hmac = compute_request_hmac(key, id, receiver, body, &timestamp, &nonce)?;
            return Ok(RequestAuthMode::Legacy {
                hmac,
                timestamp,
                nonce,
            });
        }

        Ok(RequestAuthMode::None)
    }

    async fn maybe_get_scoped_credential(&self) -> Option<ScopedCredential> {
        let refresh_window = scoped_refresh_window_sec();
        let now = now_unix_secs();
        {
            let state = self.scoped_auth_state.lock().await;
            if state.endpoint_unavailable {
                return None;
            }
            if let Some(cred) = state.credential.clone() {
                if cred.is_valid_at(now) {
                    if cred.needs_refresh(now, refresh_window) {
                        drop(state);
                        if let Some(refreshed) = self.refresh_scoped_credential(&cred).await {
                            let mut state = self.scoped_auth_state.lock().await;
                            state.credential = Some(refreshed.clone());
                            return Some(refreshed);
                        }
                    }
                    return Some(cred);
                }
            }
        }

        match self.register_scoped_credential().await {
            Ok(cred) => {
                let mut state = self.scoped_auth_state.lock().await;
                state.endpoint_unavailable = false;
                state.credential = Some(cred.clone());
                Some(cred)
            }
            Err(ScopedRegisterError::EndpointUnavailable) => {
                let mut state = self.scoped_auth_state.lock().await;
                state.endpoint_unavailable = true;
                state.credential = None;
                None
            }
            Err(ScopedRegisterError::Other) => None,
        }
    }

    async fn register_scoped_credential(
        &self,
    ) -> std::result::Result<ScopedCredential, ScopedRegisterError> {
        #[derive(serde::Serialize)]
        struct ScopedRegisterRequest {
            blind_nonce_b64: String,
        }

        let blind_nonce = rand::random::<[u8; 32]>();
        let req_body = ScopedRegisterRequest {
            blind_nonce_b64: base64::engine::general_purpose::STANDARD.encode(blind_nonce),
        };

        let res = self
            .client
            .post(&format!("{}/auth/register", self.base_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(serde_json::to_vec(&req_body).map_err(|_err| ScopedRegisterError::Other)?);
        let res = apply_transport_profile_headers(res, &self.transport_profile)
            .send()
            .await
            .map_err(|_err| ScopedRegisterError::Other)?;

        if res.status() == StatusCode::NOT_FOUND || res.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Err(ScopedRegisterError::EndpointUnavailable);
        }
        if !res.status().is_success() {
            return Err(ScopedRegisterError::Other);
        }

        let parsed: ScopedRegisterResponse = res
            .json()
            .await
            .map_err(|_err| ScopedRegisterError::Other)?;
        scoped_credential_from_register(parsed).map_err(|_err| ScopedRegisterError::Other)
    }

    async fn refresh_scoped_credential(
        &self,
        current: &ScopedCredential,
    ) -> Option<ScopedCredential> {
        let (timestamp, nonce) = hmac_request_metadata();
        let request_sig = compute_scoped_request_signature(
            &current.secret,
            &current.token_fingerprint,
            "POST",
            "/auth/refresh",
            "",
            "",
            b"",
            &timestamp,
            &nonce,
        )
        .ok()?;

        let req = self
            .client
            .post(&format!("{}/auth/refresh", self.base_url))
            .header("X-Scoped-Token", &current.token)
            .header("X-Scoped-Token-Signature", &current.token_sig_b64)
            .header("X-Scoped-Request-Signature", request_sig)
            .header("X-Scoped-Timestamp", timestamp)
            .header("X-Scoped-Nonce", nonce);
        let res = apply_transport_profile_headers(req, &self.transport_profile)
            .send()
            .await
            .ok()?;

        if res.status() == StatusCode::NOT_FOUND || res.status() == StatusCode::METHOD_NOT_ALLOWED {
            return None;
        }
        if !res.status().is_success() {
            return None;
        }

        let parsed: ScopedRegisterResponse = res.json().await.ok()?;
        scoped_credential_from_register(parsed).ok()
    }

    /// Send dummy cover traffic to the relay to help hide timing/volume.
    /// Receiver is a reserved ID handled by the relay and immediately dropped.
    pub async fn send_cover(&self, size: usize) -> Result<()> {
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; size];
        rng.fill(&mut payload[..]);
        // random message id to avoid cache/linkability
        let msg_id = hex::encode(rand::random::<[u8; 16]>());
        self.send_blob(&msg_id, "__cover__", &payload).await
    }

    fn verify_server_pin(&self) -> Result<()> {
        let Some(expected_pin) = self.tls_config.pinned_spki_sha256.as_ref() else {
            return Ok(());
        };
        verify_relay_spki_pin(
            &self.base_url,
            expected_pin,
            self.tls_config.pinned_ca_der.as_deref(),
        )
    }
}

impl ScopedCredential {
    fn is_valid_at(&self, now: u64) -> bool {
        self.expires_at > now.saturating_add(MIN_SCOPED_CREDENTIAL_VALIDITY_SEC)
            && !self.secret.is_empty()
            && !self.token.trim().is_empty()
            && !self.token_sig_b64.trim().is_empty()
            && !self.token_fingerprint.trim().is_empty()
    }

    fn needs_refresh(&self, now: u64, refresh_window_sec: u64) -> bool {
        self.expires_at <= now.saturating_add(refresh_window_sec)
    }
}

fn scoped_credential_from_register(parsed: ScopedRegisterResponse) -> Result<ScopedCredential> {
    if let (Some(token), Some(token_sig_b64), Some(token_secret_b64), Some(token_fingerprint)) = (
        parsed.scoped_token,
        parsed.scoped_token_sig_b64,
        parsed.token_secret_b64,
        parsed.token_fingerprint,
    ) {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(token_secret_b64.as_bytes())
            .map_err(|err| anyhow!("invalid scoped token secret: {err}"))?;
        if token.trim().is_empty()
            || token_sig_b64.trim().is_empty()
            || token_fingerprint.trim().is_empty()
            || secret.is_empty()
        {
            return Err(anyhow!("invalid scoped token credential payload"));
        }
        return Ok(ScopedCredential {
            token,
            token_sig_b64,
            token_fingerprint,
            secret,
            expires_at: parsed.expires_at,
        });
    }

    // Backward compatibility with older relay credential payloads.
    let client_id = parsed
        .client_id
        .ok_or_else(|| anyhow!("missing legacy scoped client_id"))?;
    let client_secret_b64 = parsed
        .client_secret_b64
        .ok_or_else(|| anyhow!("missing legacy scoped client_secret_b64"))?;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(client_secret_b64.as_bytes())
        .map_err(|err| anyhow!("invalid scoped auth secret: {err}"))?;
    if client_id.trim().is_empty() || secret.is_empty() {
        return Err(anyhow!("invalid scoped auth credential payload"));
    }
    Ok(ScopedCredential {
        token: client_id.clone(),
        token_sig_b64: String::new(),
        token_fingerprint: client_id,
        secret,
        expires_at: parsed.expires_at,
    })
}

fn apply_request_auth_headers(
    mut req: reqwest::RequestBuilder,
    auth: &RequestAuthMode,
) -> reqwest::RequestBuilder {
    match auth {
        RequestAuthMode::Scoped {
            token,
            token_sig_b64,
            request_sig,
            timestamp,
            nonce,
        } => {
            req = req
                .header("X-Scoped-Token", token)
                .header("X-Scoped-Token-Signature", token_sig_b64)
                .header("X-Scoped-Request-Signature", request_sig)
                .header("X-Scoped-Timestamp", timestamp)
                .header("X-Scoped-Nonce", nonce);
        }
        RequestAuthMode::Legacy {
            hmac,
            timestamp,
            nonce,
        } => {
            req = req
                .header("X-HMAC", hmac)
                .header("X-HMAC-Timestamp", timestamp)
                .header("X-HMAC-Nonce", nonce);
        }
        RequestAuthMode::None => {}
    }
    req
}

fn apply_transport_profile_headers(
    mut req: reqwest::RequestBuilder,
    profile: &RelayTransportProfile,
) -> reqwest::RequestBuilder {
    if !profile.enabled {
        return req;
    }

    // Keep header set deterministic to reduce per-client HTTP-level fingerprint drift.
    req = req
        .header("User-Agent", &profile.user_agent)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .header("Connection", &profile.connection_header);

    req
}

/// Legacy static blinding used before epoch-rotating mailbox handles.
fn blind_receiver_id_legacy(receiver_id: &str) -> String {
    // Keep reserved namespaces unchanged.
    if receiver_id == "public" || receiver_id.starts_with("__") {
        return receiver_id.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(receiver_id.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn derive_rotating_mailbox_handle(receiver_id: &str, epoch: u64) -> String {
    if receiver_id == "public" || receiver_id.starts_with("__") {
        return receiver_id.to_string();
    }

    let mut hasher = Sha256::new();
    hasher.update(MAILBOX_HANDLE_VERSION.as_bytes());
    hasher.update(b":");
    hasher.update(epoch.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(receiver_id.as_bytes());
    let result = hasher.finalize();
    format!(
        "{}_{}_{}",
        MAILBOX_HANDLE_VERSION,
        epoch,
        hex::encode(result)
    )
}

fn derive_current_mailbox_handle(receiver_id: &str) -> String {
    let now = now_unix_secs();
    let epoch = now / mailbox_epoch_seconds();
    derive_rotating_mailbox_handle(receiver_id, epoch)
}

fn derive_fetch_mailbox_candidates(receiver_id: &str) -> Vec<String> {
    if receiver_id == "public" || receiver_id.starts_with("__") {
        return vec![receiver_id.to_string()];
    }

    let now = now_unix_secs();
    let epoch_seconds = mailbox_epoch_seconds();
    let current_epoch = now / epoch_seconds;
    let past_epochs = mailbox_fetch_past_epochs();

    let mut candidates = Vec::with_capacity((past_epochs as usize) + 2);
    for offset in 0..=past_epochs {
        let epoch = current_epoch.saturating_sub(offset);
        candidates.push(derive_rotating_mailbox_handle(receiver_id, epoch));
    }

    if mailbox_legacy_fallback_enabled() {
        candidates.push(blind_receiver_id_legacy(receiver_id));
    }

    candidates
}

fn build_batch_fetch_handles(receiver_id: &str, real_candidates: &[String]) -> Vec<String> {
    let max_handles = mailbox_batch_max_handles();
    if max_handles == 0 {
        return Vec::new();
    }

    let mut handles = Vec::with_capacity(max_handles);
    let mut seen = HashSet::with_capacity(max_handles);

    for candidate in real_candidates {
        if seen.insert(candidate.clone()) {
            handles.push(candidate.clone());
        }
        if handles.len() >= max_handles {
            break;
        }
    }
    if handles.is_empty() {
        return handles;
    }

    // Reserved namespaces are intentionally fixed and should not use decoys.
    let reserved = receiver_id == "public" || receiver_id.starts_with("__");
    let mut decoys_target = 0usize;
    if !reserved {
        decoys_target = mailbox_decoy_fetch_count();
        decoys_target = decoys_target.min(max_handles.saturating_sub(handles.len()));
    }

    if decoys_target > 0 {
        let now = now_unix_secs();
        let epoch = now / mailbox_epoch_seconds();
        while decoys_target > 0 {
            let random_hash = hex::encode(rand::random::<[u8; 32]>());
            let decoy = format!("{}_{}_{}", MAILBOX_HANDLE_VERSION, epoch, random_hash);
            if seen.insert(decoy.clone()) {
                handles.push(decoy);
                decoys_target -= 1;
            }
        }
    }

    handles.shuffle(&mut rand::thread_rng());
    handles
}

fn mailbox_epoch_seconds() -> u64 {
    std::env::var("RELAY_MAILBOX_EPOCH_SEC")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAILBOX_EPOCH_SEC)
}

fn mailbox_batch_fetch_enabled() -> bool {
    std::env::var("REDOOR_MAILBOX_BATCH_FETCH")
        .ok()
        .map(|raw| raw.trim() != "0")
        .unwrap_or(true)
}

fn mailbox_batch_max_handles() -> usize {
    std::env::var("REDOOR_MAILBOX_BATCH_MAX_HANDLES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAILBOX_BATCH_MAX_HANDLES)
}

fn mailbox_fetch_past_epochs() -> u64 {
    std::env::var("RELAY_MAILBOX_FETCH_PAST_EPOCHS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAILBOX_FETCH_PAST_EPOCHS)
}

fn mailbox_decoy_fetch_count() -> usize {
    std::env::var("REDOOR_MAILBOX_DECOY_FETCH_COUNT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or_else(|| {
            if config::secure_mode_enabled() {
                DEFAULT_MAILBOX_DECOY_FETCH_COUNT_SECURE
            } else {
                0
            }
        })
}

fn mailbox_legacy_fallback_enabled() -> bool {
    std::env::var("RELAY_MAILBOX_FETCH_LEGACY_FALLBACK")
        .ok()
        .map(|raw| raw.trim() != "0")
        .unwrap_or(true)
}

fn fetch_pending_mirror_max() -> usize {
    std::env::var("REDOOR_FETCH_PENDING_MIRROR_MAX")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|v| v.min(8))
        .unwrap_or(DEFAULT_FETCH_PENDING_MIRROR_MAX)
}

fn fetch_pending_relay_quorum() -> usize {
    std::env::var("REDOOR_FETCH_PENDING_RELAY_QUORUM")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .map(|v| v.min(8))
        .unwrap_or(DEFAULT_FETCH_PENDING_RELAY_QUORUM)
}

fn merge_fetch_pending_hits(hits: Vec<(String, String, Vec<u8>)>) -> Vec<RelayHitCandidate> {
    let mut dedup: HashMap<String, RelayHitCandidate> = HashMap::new();
    for (relay_url, id, blob) in hits {
        if let Some(existing) = dedup.get_mut(&id) {
            existing.confirmations = existing.confirmations.saturating_add(1);
            if relay_url < existing.first_relay_url {
                existing.first_relay_url = relay_url;
                existing.blob = blob;
            }
            continue;
        }

        dedup.insert(
            id.clone(),
            RelayHitCandidate {
                id,
                blob,
                confirmations: 1,
                first_relay_url: relay_url,
            },
        );
    }

    let mut merged: Vec<RelayHitCandidate> = dedup.into_values().collect();
    merged.sort_by(|a, b| {
        b.confirmations
            .cmp(&a.confirmations)
            .then_with(|| a.first_relay_url.cmp(&b.first_relay_url))
            .then_with(|| a.id.cmp(&b.id))
    });
    merged
}

fn select_fetch_pending_hit_with_quorum(
    merged_hits: &[RelayHitCandidate],
    quorum: usize,
) -> Option<&RelayHitCandidate> {
    merged_hits
        .iter()
        .find(|candidate| candidate.confirmations >= quorum)
}

fn finalize_fetch_pending_outcome(
    merged_hits: &[RelayHitCandidate],
    quorum: usize,
    best_effort_fallback: bool,
    saw_miss: bool,
    last_error: Option<anyhow::Error>,
) -> Result<(String, Vec<u8>)> {
    if let Some(selected) = select_fetch_pending_hit_with_quorum(merged_hits, quorum) {
        return Ok((selected.id.clone(), selected.blob.clone()));
    }

    if !merged_hits.is_empty() {
        if best_effort_fallback {
            let best = merged_hits
                .first()
                .expect("non-empty hits should have first entry");
            return Ok((best.id.clone(), best.blob.clone()));
        }
        let best = merged_hits.first().map(|c| c.confirmations).unwrap_or(0);
        return Err(anyhow!(
            "pending fetch quorum not met (required={}, best_confirmations={})",
            quorum,
            best
        ));
    }

    if saw_miss {
        return Err(anyhow!(
            "No pending blobs for receiver across active mailbox handles"
        ));
    }

    if let Some(err) = last_error {
        return Err(err);
    }

    Err(anyhow!(
        "No pending blobs for receiver across active mailbox handles"
    ))
}

fn normalize_relay_url(url: &str) -> Option<String> {
    let normalized = url.trim().trim_end_matches('/').to_string();
    if normalized.is_empty() {
        return None;
    }
    if !is_insecure_allowed() && !normalized.starts_with("https://") {
        return None;
    }
    Some(normalized)
}

fn parse_fetch_pending_mirrors(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let values: Vec<String> = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<String>>(trimmed).unwrap_or_default()
    } else {
        trimmed
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    };

    values
        .into_iter()
        .filter_map(|url| normalize_relay_url(&url))
        .collect()
}

fn fetch_pending_relay_urls(primary_relay_url: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let Some(primary) = normalize_relay_url(primary_relay_url) else {
        return urls;
    };
    urls.push(primary.clone());

    let mirror_raw = std::env::var("REDOOR_FETCH_PENDING_MIRRORS").unwrap_or_default();
    let mut mirrors = parse_fetch_pending_mirrors(&mirror_raw);
    mirrors.retain(|candidate| candidate != &primary);

    let mirror_cap = fetch_pending_mirror_max();
    if mirrors.len() > mirror_cap {
        mirrors.truncate(mirror_cap);
    }

    urls.extend(mirrors);
    urls.sort();
    urls.dedup();

    if let Some(seed) = fetch_pending_shuffle_seed() {
        let mut rng = StdRng::seed_from_u64(seed ^ (urls.len() as u64).rotate_left(7));
        urls.shuffle(&mut rng);
    } else {
        urls.shuffle(&mut rand::thread_rng());
    }
    urls
}

fn fetch_pending_shuffle_seed() -> Option<u64> {
    std::env::var("REDOOR_FETCH_PENDING_SHUFFLE_SEED")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
}

fn fetch_pending_quorum_best_effort_enabled() -> bool {
    std::env::var("REDOOR_FETCH_PENDING_QUORUM_BEST_EFFORT")
        .ok()
        .map(|raw| {
            let normalized = raw.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn compute_hmac(key: &[u8], id: &str, receiver: &str, data: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(id.as_bytes());
    mac.update(receiver.as_bytes());
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::STANDARD.encode(tag))
}

fn compute_request_hmac(
    key: &[u8],
    id: &str,
    receiver: &str,
    data: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(timestamp.as_bytes());
    mac.update(nonce.as_bytes());
    mac.update(id.as_bytes());
    mac.update(receiver.as_bytes());
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::STANDARD.encode(tag))
}

fn compute_hmac_bytes(key: &[u8], payload: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::STANDARD.encode(tag))
}

fn compute_scoped_request_signature(
    secret: &[u8],
    client_id: &str,
    method: &str,
    path: &str,
    id: &str,
    receiver: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Result<String> {
    let body_hash = Sha256::digest(body);
    let canonical = [
        timestamp,
        nonce,
        client_id,
        &method.to_ascii_uppercase(),
        path,
        id,
        receiver,
        &hex::encode(body_hash),
    ]
    .join("\n");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(canonical.as_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::STANDARD.encode(tag))
}

fn hmac_request_metadata() -> (String, String) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    (timestamp, nonce)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn scoped_refresh_window_sec() -> u64 {
    std::env::var("RELAY_SCOPED_REFRESH_WINDOW_SEC")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_SCOPED_REFRESH_WINDOW_SEC)
}

fn is_insecure_allowed() -> bool {
    // This foot-gun is only available in debug builds.
    #[cfg(debug_assertions)]
    {
        return std::env::var("RELAY_ALLOW_INSECURE").ok() == Some("1".to_string());
    }
    #[cfg(not(debug_assertions))]
    {
        return false;
    }
}

fn parse_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let normalized = v.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(default)
}

fn resolve_relay_transport_profile() -> RelayTransportProfile {
    let enabled = parse_env_bool("REDOOR_TRANSPORT_NORMALIZATION", true);
    let user_agent = std::env::var("REDOOR_TRANSPORT_USER_AGENT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "redoor-relay-client/1.0".to_string());
    let connection_header = std::env::var("REDOOR_TRANSPORT_CONNECTION_MODE")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| v == "close" || v == "keep-alive")
        .unwrap_or_else(|| "close".to_string());
    let force_http1_only = parse_env_bool("REDOOR_TRANSPORT_FORCE_HTTP1", true);

    RelayTransportProfile {
        enabled,
        user_agent,
        connection_header,
        force_http1_only,
    }
}

fn build_client(tls_config: &RelayTlsConfig, profile: &RelayTransportProfile) -> Client {
    // Enforce HTTPS unless explicitly allowed for local testing
    let allow_insecure = is_insecure_allowed();

    let mut builder = Client::builder()
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .timeout(Duration::from_secs(10))
        .tcp_nodelay(true)
        .pool_max_idle_per_host(0);

    if profile.force_http1_only {
        // ALPN normalization for relay traffic where feasible in reqwest/rustls.
        builder = builder.http1_only();
    }

    if let Some(ca_der) = tls_config.pinned_ca_der.as_ref() {
        if let Ok(cert) = reqwest::Certificate::from_der(ca_der) {
            builder = builder.add_root_certificate(cert);
        }
    }

    // Proxy support
    if let Some(proxy_url) = config::get_proxy() {
        if let Ok(proxy) = Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    }

    if !allow_insecure {
        builder = builder.danger_accept_invalid_certs(false);
    } else {
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder.build().expect("failed to build reqwest client")
}

fn resolve_relay_tls_config() -> RelayTlsConfig {
    let pinned_ca_der = config::get_relay_ca_b64()
        .map(|ca| {
            base64::engine::general_purpose::STANDARD
                .decode(ca.as_bytes())
                .map_err(|e| anyhow!("Invalid relay CA base64: {e}"))
        })
        .transpose()
        .expect("Invalid relay TLS CA pin configuration");

    let pinned_spki_sha256 = config::get_relay_spki_pin_b64()
        .map(|pin| decode_spki_pin_b64(&pin))
        .transpose()
        .expect("Invalid relay SPKI pin configuration");

    RelayTlsConfig {
        pinned_ca_der,
        pinned_spki_sha256,
    }
}

fn decode_spki_pin_b64(pin_b64: &str) -> Result<Vec<u8>> {
    let pin = base64::engine::general_purpose::STANDARD
        .decode(pin_b64.as_bytes())
        .map_err(|e| anyhow!("Invalid relay SPKI pin base64: {e}"))?;
    if pin.len() != 32 {
        return Err(anyhow!(
            "Invalid relay SPKI pin length: expected 32 bytes SHA-256 hash, got {}",
            pin.len()
        ));
    }
    Ok(pin)
}

fn verify_relay_spki_pin(
    relay_url: &str,
    expected_pin_sha256: &[u8],
    pinned_ca_der: Option<&[u8]>,
) -> Result<()> {
    let parsed = reqwest::Url::parse(relay_url)
        .map_err(|e| anyhow!("Invalid relay URL for pin verification: {e}"))?;

    // Pinning applies only to TLS endpoints.
    if parsed.scheme() != "https" {
        return Ok(());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("Relay URL is missing host"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow!("Relay URL is missing port"))?;
    let addr = format!("{host}:{port}");

    let mut socket = TcpStream::connect(addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;

    let root_store = build_root_store(pinned_ca_der)?;
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("Invalid relay host for TLS verification: {host}"))?;
    let mut conn = ClientConnection::new(Arc::new(tls_config), server_name)?;
    while conn.is_handshaking() {
        let _ = conn.complete_io(&mut socket)?;
    }

    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("TLS handshake did not provide relay certificate"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("TLS handshake returned empty relay certificate chain"))?;
    let actual_pin = spki_sha256_from_cert_der(leaf)?;

    if actual_pin != expected_pin_sha256 {
        let expected = base64::engine::general_purpose::STANDARD.encode(expected_pin_sha256);
        let actual = base64::engine::general_purpose::STANDARD.encode(actual_pin);
        return Err(anyhow!(
            "Relay SPKI pin mismatch. expected={expected}, actual={actual}"
        ));
    }

    Ok(())
}

fn build_root_store(pinned_ca_der: Option<&[u8]>) -> Result<RootCertStore> {
    if let Some(ca_der) = pinned_ca_der {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .map_err(|e| anyhow!("Invalid pinned relay CA DER: {e}"))?;
        return Ok(roots);
    }

    Ok(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
}

fn spki_sha256_from_cert_der(cert_der: &CertificateDer<'_>) -> Result<Vec<u8>> {
    let (_, cert) = parse_x509_certificate(cert_der.as_ref())
        .map_err(|e| anyhow!("Failed to parse relay leaf certificate: {e}"))?;
    let spki_raw: &[u8] = cert.public_key().raw;
    Ok(Sha256::digest(spki_raw).to_vec())
}

fn ensure_https(url: &str) -> Result<()> {
    if !is_insecure_allowed() && !url.starts_with("https://") {
        return Err(anyhow!(
            "Insecure relay URL rejected. Only https is allowed in release builds."
        ));
    }
    Ok(())
}

fn normalize_transport_payload(blob: &[u8]) -> Result<Vec<u8>> {
    let config = config::get_traffic_shaping();
    if config.pad_to == 0 {
        return Ok(blob.to_vec());
    }

    // Fixed-size transport cells:
    // [4-byte big-endian payload length][payload bytes][zero padding ...]
    if config.pad_to < 4 {
        return Err(anyhow!("invalid transport cell size: must be >= 4 bytes"));
    }
    if blob.len() > config.pad_to.saturating_sub(4) {
        return Err(anyhow!(
            "payload exceeds configured fixed cell size (payload={}, cell={})",
            blob.len(),
            config.pad_to
        ));
    }

    let mut cell = vec![0u8; config.pad_to];
    let len = blob.len() as u32;
    cell[..4].copy_from_slice(&len.to_be_bytes());
    cell[4..4 + blob.len()].copy_from_slice(blob);
    Ok(cell)
}

fn maybe_delay() {
    let config = config::get_traffic_shaping();
    if config.max_delay_ms == 0 {
        return;
    }
    let mut rng = rand::thread_rng();
    let delay = if config.max_delay_ms <= config.min_delay_ms {
        config.max_delay_ms
    } else {
        rng.gen_range(config.min_delay_ms..=config.max_delay_ms)
    };
    std::thread::sleep(Duration::from_millis(delay));
}

fn trim_pad(
    mut data: Vec<u8>,
    pad_header: Option<&reqwest::header::HeaderValue>,
) -> Result<Vec<u8>> {
    if let Some(v) = pad_header {
        let pad_len: usize = v
            .to_str()
            .map_err(|_| anyhow!("invalid X-Pad-Len header"))?
            .parse()
            .map_err(|_| anyhow!("invalid X-Pad-Len value"))?;
        if pad_len > data.len() {
            return Err(anyhow!("pad length larger than payload"));
        }
        let new_len = data.len() - pad_len;
        data.truncate(new_len);
    }
    Ok(data)
}

fn decode_transport_payload(data: Vec<u8>) -> Result<Vec<u8>> {
    let config = config::get_traffic_shaping();
    if config.pad_to == 0 {
        return Ok(data);
    }
    if data.len() != config.pad_to {
        return Err(anyhow!(
            "invalid transport cell size (got {}, expected {})",
            data.len(),
            config.pad_to
        ));
    }
    if data.len() < 4 {
        return Err(anyhow!("malformed transport cell"));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > data.len().saturating_sub(4) {
        return Err(anyhow!("transport cell payload length exceeds cell bounds"));
    }
    if data[4 + len..].iter().any(|b| *b != 0) {
        return Err(anyhow!("transport cell contains non-zero padding"));
    }
    Ok(data[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TRAFFIC_SHAPING_LOCK: Mutex<()> = Mutex::new(());
    static MAILBOX_ENV_LOCK: Mutex<()> = Mutex::new(());
    static TRANSPORT_PROFILE_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_transport_profile_env() {
        std::env::remove_var("REDOOR_TRANSPORT_NORMALIZATION");
        std::env::remove_var("REDOOR_TRANSPORT_USER_AGENT");
        std::env::remove_var("REDOOR_TRANSPORT_CONNECTION_MODE");
        std::env::remove_var("REDOOR_TRANSPORT_FORCE_HTTP1");
    }

    #[test]
    fn decode_spki_pin_accepts_sha256_hash() {
        let raw = [7u8; 32];
        let pin_b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let decoded = decode_spki_pin_b64(&pin_b64).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_spki_pin_rejects_non_sha256_length() {
        let raw = [7u8; 16];
        let pin_b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let err = decode_spki_pin_b64(&pin_b64).unwrap_err().to_string();
        assert!(err.contains("expected 32 bytes SHA-256 hash"));
    }

    #[test]
    fn fixed_cell_roundtrip_preserves_payload() {
        let _guard = TRAFFIC_SHAPING_LOCK.lock().expect("lock traffic shaping");
        let original = config::get_traffic_shaping();
        config::set_traffic_shaping(config::TrafficShapingConfig {
            pad_to: 64,
            min_delay_ms: original.min_delay_ms,
            max_delay_ms: original.max_delay_ms,
        });

        let payload = b"hello-cell";
        let encoded = normalize_transport_payload(payload).expect("encode fixed cell");
        assert_eq!(encoded.len(), 64);
        let decoded = decode_transport_payload(encoded).expect("decode fixed cell");
        assert_eq!(decoded, payload);

        config::set_traffic_shaping(original);
    }

    #[test]
    fn fixed_cell_rejects_oversize_payload() {
        let _guard = TRAFFIC_SHAPING_LOCK.lock().expect("lock traffic shaping");
        let original = config::get_traffic_shaping();
        config::set_traffic_shaping(config::TrafficShapingConfig {
            pad_to: 16,
            min_delay_ms: original.min_delay_ms,
            max_delay_ms: original.max_delay_ms,
        });

        let oversized = vec![0u8; 32];
        assert!(normalize_transport_payload(&oversized).is_err());

        config::set_traffic_shaping(original);
    }

    #[test]
    fn fixed_cell_rejects_non_zero_padding() {
        let _guard = TRAFFIC_SHAPING_LOCK.lock().expect("lock traffic shaping");
        let original = config::get_traffic_shaping();
        config::set_traffic_shaping(config::TrafficShapingConfig {
            pad_to: 16,
            min_delay_ms: original.min_delay_ms,
            max_delay_ms: original.max_delay_ms,
        });

        let mut malformed = vec![0u8; 16];
        malformed[..4].copy_from_slice(&(4u32.to_be_bytes()));
        malformed[4..8].copy_from_slice(b"ping");
        malformed[8] = 1;
        assert!(decode_transport_payload(malformed).is_err());

        config::set_traffic_shaping(original);
    }

    #[test]
    fn rotating_mailbox_handle_changes_between_epochs() {
        let h1 = derive_rotating_mailbox_handle("peer-abc", 1000);
        let h2 = derive_rotating_mailbox_handle("peer-abc", 1001);
        assert_ne!(h1, h2);
        assert!(h1.starts_with("mb1_"));
    }

    #[test]
    fn fetch_mailbox_candidates_include_rotation_window_and_legacy() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::set_var("RELAY_MAILBOX_EPOCH_SEC", "60");
        std::env::set_var("RELAY_MAILBOX_FETCH_PAST_EPOCHS", "2");
        std::env::set_var("RELAY_MAILBOX_FETCH_LEGACY_FALLBACK", "1");

        let candidates = derive_fetch_mailbox_candidates("peer-xyz");
        assert!(
            candidates.len() >= 4,
            "expected current+2 past epochs plus legacy fallback"
        );
        assert!(candidates
            .iter()
            .any(|c| c.starts_with("mb1_") && c.split('_').count() == 3));
        let legacy = blind_receiver_id_legacy("peer-xyz");
        assert_eq!(candidates.last(), Some(&legacy));

        std::env::remove_var("RELAY_MAILBOX_EPOCH_SEC");
        std::env::remove_var("RELAY_MAILBOX_FETCH_PAST_EPOCHS");
        std::env::remove_var("RELAY_MAILBOX_FETCH_LEGACY_FALLBACK");
    }

    #[test]
    fn batch_fetch_handles_add_decoys_in_secure_mode() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::set_var("REDOOR_SECURE_MODE", "1");
        std::env::set_var("REDOOR_MAILBOX_BATCH_MAX_HANDLES", "6");
        std::env::remove_var("REDOOR_MAILBOX_DECOY_FETCH_COUNT");

        let base = vec![
            derive_rotating_mailbox_handle("peer-1", 1000),
            derive_rotating_mailbox_handle("peer-1", 999),
        ];
        let handles = build_batch_fetch_handles("peer-1", &base);
        let base_set: std::collections::HashSet<_> = base.iter().cloned().collect();
        let decoy_count = handles.iter().filter(|h| !base_set.contains(*h)).count();

        assert!(handles.len() <= 6);
        assert!(
            decoy_count >= 1,
            "secure mode should include at least one decoy mailbox handle"
        );

        std::env::remove_var("REDOOR_SECURE_MODE");
        std::env::remove_var("REDOOR_MAILBOX_BATCH_MAX_HANDLES");
        std::env::remove_var("REDOOR_MAILBOX_DECOY_FETCH_COUNT");
    }

    #[test]
    fn batch_fetch_handles_respect_max_budget() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::set_var("REDOOR_MAILBOX_BATCH_MAX_HANDLES", "3");
        std::env::set_var("REDOOR_MAILBOX_DECOY_FETCH_COUNT", "5");

        let base = vec![
            derive_rotating_mailbox_handle("peer-2", 1000),
            derive_rotating_mailbox_handle("peer-2", 999),
            derive_rotating_mailbox_handle("peer-2", 998),
            derive_rotating_mailbox_handle("peer-2", 997),
        ];
        let handles = build_batch_fetch_handles("peer-2", &base);
        assert_eq!(
            handles.len(),
            3,
            "batch handle list must obey configured max handles"
        );

        std::env::remove_var("REDOOR_MAILBOX_BATCH_MAX_HANDLES");
        std::env::remove_var("REDOOR_MAILBOX_DECOY_FETCH_COUNT");
    }

    #[test]
    fn parse_fetch_pending_mirrors_accepts_csv_and_json() {
        let csv = parse_fetch_pending_mirrors(
            "https://relay-a.example, https://relay-b.example/, http://insecure.example",
        );
        assert!(csv.contains(&"https://relay-a.example".to_string()));
        assert!(csv.contains(&"https://relay-b.example".to_string()));
        assert!(
            !csv.iter().any(|u| u.starts_with("http://")),
            "non-https mirror must be dropped in secure builds"
        );

        let json = parse_fetch_pending_mirrors(
            "[\"https://relay-c.example\", \"https://relay-d.example/\"]",
        );
        assert!(json.contains(&"https://relay-c.example".to_string()));
        assert!(json.contains(&"https://relay-d.example".to_string()));
    }

    #[test]
    fn fetch_pending_relay_urls_include_primary_and_respect_cap() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::set_var(
            "REDOOR_FETCH_PENDING_MIRRORS",
            "https://relay-a.example,https://relay-b.example,https://relay-c.example",
        );
        std::env::set_var("REDOOR_FETCH_PENDING_MIRROR_MAX", "2");

        let urls = fetch_pending_relay_urls("https://relay-primary.example/");
        assert!(urls.contains(&"https://relay-primary.example".to_string()));
        assert!(
            urls.len() <= 3,
            "expected primary + at most two configured mirrors"
        );
        assert_eq!(
            urls.iter()
                .filter(|u| *u == "https://relay-primary.example")
                .count(),
            1
        );

        std::env::remove_var("REDOOR_FETCH_PENDING_MIRRORS");
        std::env::remove_var("REDOOR_FETCH_PENDING_MIRROR_MAX");
    }

    #[test]
    fn fetch_pending_relay_urls_are_deterministic_with_seed_override() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::set_var(
            "REDOOR_FETCH_PENDING_MIRRORS",
            "https://relay-a.example,https://relay-b.example,https://relay-c.example",
        );
        std::env::set_var("REDOOR_FETCH_PENDING_MIRROR_MAX", "3");
        std::env::set_var("REDOOR_FETCH_PENDING_SHUFFLE_SEED", "1337");

        let first = fetch_pending_relay_urls("https://relay-primary.example/");
        let second = fetch_pending_relay_urls("https://relay-primary.example/");
        assert_eq!(
            first, second,
            "seed override should stabilize relay query order"
        );

        std::env::remove_var("REDOOR_FETCH_PENDING_MIRRORS");
        std::env::remove_var("REDOOR_FETCH_PENDING_MIRROR_MAX");
        std::env::remove_var("REDOOR_FETCH_PENDING_SHUFFLE_SEED");
    }

    #[test]
    fn merge_fetch_pending_hits_is_deterministic_and_deduplicated() {
        let merged = merge_fetch_pending_hits(vec![
            (
                "https://relay-z.example".to_string(),
                "msg-a".to_string(),
                b"z-copy".to_vec(),
            ),
            (
                "https://relay-a.example".to_string(),
                "msg-a".to_string(),
                b"a-copy".to_vec(),
            ),
            (
                "https://relay-b.example".to_string(),
                "msg-b".to_string(),
                b"b-copy".to_vec(),
            ),
        ]);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "msg-a");
        assert_eq!(merged[0].confirmations, 2);
        assert_eq!(merged[0].first_relay_url, "https://relay-a.example");
        assert_eq!(merged[0].blob, b"a-copy".to_vec());
    }

    #[test]
    fn select_fetch_pending_hit_with_quorum_enforces_threshold() {
        let merged = merge_fetch_pending_hits(vec![
            (
                "https://relay-a.example".to_string(),
                "msg-1".to_string(),
                b"payload-1".to_vec(),
            ),
            (
                "https://relay-b.example".to_string(),
                "msg-1".to_string(),
                b"payload-1".to_vec(),
            ),
            (
                "https://relay-c.example".to_string(),
                "msg-2".to_string(),
                b"payload-2".to_vec(),
            ),
        ]);

        assert!(select_fetch_pending_hit_with_quorum(&merged, 3).is_none());
        let selected =
            select_fetch_pending_hit_with_quorum(&merged, 2).expect("quorum=2 should accept msg-1");
        assert_eq!(selected.id, "msg-1");
    }

    #[test]
    fn quorum_selection_resists_single_relay_collusion() {
        let merged = merge_fetch_pending_hits(vec![
            (
                "https://relay-a.example".to_string(),
                "msg-honest".to_string(),
                b"honest".to_vec(),
            ),
            (
                "https://relay-b.example".to_string(),
                "msg-honest".to_string(),
                b"honest".to_vec(),
            ),
            (
                "https://relay-c.example".to_string(),
                "msg-malicious".to_string(),
                b"evil".to_vec(),
            ),
        ]);

        let selected = select_fetch_pending_hit_with_quorum(&merged, 2)
            .expect("quorum=2 should prefer honest");
        assert_eq!(selected.id, "msg-honest");
    }

    #[test]
    fn finalize_fetch_pending_outcome_prefers_miss_on_partial_outage() {
        let err = finalize_fetch_pending_outcome(
            &[],
            1,
            false,
            true,
            Some(anyhow::anyhow!("relay unavailable")),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("No pending blobs"),
            "expected miss-style response under partial outage, got: {err}"
        );
    }

    #[test]
    fn finalize_fetch_pending_outcome_returns_error_when_all_relays_fail() {
        let err = finalize_fetch_pending_outcome(
            &[],
            1,
            false,
            false,
            Some(anyhow::anyhow!("relay timeout")),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("relay timeout"));
    }

    #[test]
    fn finalize_fetch_pending_outcome_supports_best_effort_fallback() {
        let merged = merge_fetch_pending_hits(vec![
            (
                "https://relay-a.example".to_string(),
                "msg-1".to_string(),
                b"payload".to_vec(),
            ),
            (
                "https://relay-b.example".to_string(),
                "msg-2".to_string(),
                b"other".to_vec(),
            ),
        ]);

        let selected = finalize_fetch_pending_outcome(&merged, 2, true, false, None)
            .expect("best effort should return top-ranked hit");
        assert_eq!(selected.0, "msg-1");
    }

    #[test]
    fn fetch_pending_relay_quorum_env_is_clamped_and_defaulted() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::remove_var("REDOOR_FETCH_PENDING_RELAY_QUORUM");
        assert_eq!(
            fetch_pending_relay_quorum(),
            DEFAULT_FETCH_PENDING_RELAY_QUORUM
        );

        std::env::set_var("REDOOR_FETCH_PENDING_RELAY_QUORUM", "0");
        assert_eq!(
            fetch_pending_relay_quorum(),
            DEFAULT_FETCH_PENDING_RELAY_QUORUM
        );

        std::env::set_var("REDOOR_FETCH_PENDING_RELAY_QUORUM", "99");
        assert_eq!(fetch_pending_relay_quorum(), 8);

        std::env::remove_var("REDOOR_FETCH_PENDING_RELAY_QUORUM");
    }

    #[test]
    fn fetch_pending_quorum_best_effort_env_defaults_false() {
        let _guard = MAILBOX_ENV_LOCK.lock().expect("lock mailbox env");
        std::env::remove_var("REDOOR_FETCH_PENDING_QUORUM_BEST_EFFORT");
        assert!(!fetch_pending_quorum_best_effort_enabled());

        std::env::set_var("REDOOR_FETCH_PENDING_QUORUM_BEST_EFFORT", "1");
        assert!(fetch_pending_quorum_best_effort_enabled());

        std::env::remove_var("REDOOR_FETCH_PENDING_QUORUM_BEST_EFFORT");
    }

    #[test]
    fn transport_profile_defaults_are_normalized_and_repeatable() {
        let _guard = TRANSPORT_PROFILE_ENV_LOCK
            .lock()
            .expect("lock transport profile env");
        clear_transport_profile_env();

        let profile = resolve_relay_transport_profile();
        assert!(profile.enabled);
        assert!(profile.force_http1_only);
        assert_eq!(profile.user_agent, "redoor-relay-client/1.0");
        assert_eq!(profile.connection_header, "close");
    }

    #[test]
    fn transport_profile_can_disable_normalization() {
        let _guard = TRANSPORT_PROFILE_ENV_LOCK
            .lock()
            .expect("lock transport profile env");
        clear_transport_profile_env();
        std::env::set_var("REDOOR_TRANSPORT_NORMALIZATION", "0");

        let profile = resolve_relay_transport_profile();
        assert!(!profile.enabled);

        clear_transport_profile_env();
    }

    #[test]
    fn transport_profile_honors_custom_connection_mode_and_user_agent() {
        let _guard = TRANSPORT_PROFILE_ENV_LOCK
            .lock()
            .expect("lock transport profile env");
        clear_transport_profile_env();
        std::env::set_var("REDOOR_TRANSPORT_CONNECTION_MODE", "keep-alive");
        std::env::set_var("REDOOR_TRANSPORT_USER_AGENT", "redoor-test-agent/2.0");
        std::env::set_var("REDOOR_TRANSPORT_FORCE_HTTP1", "false");

        let profile = resolve_relay_transport_profile();
        assert!(profile.enabled);
        assert!(!profile.force_http1_only);
        assert_eq!(profile.user_agent, "redoor-test-agent/2.0");
        assert_eq!(profile.connection_header, "keep-alive");

        clear_transport_profile_env();
    }

    #[test]
    fn normalized_request_profile_applies_expected_headers() {
        let _guard = TRANSPORT_PROFILE_ENV_LOCK
            .lock()
            .expect("lock transport profile env");
        clear_transport_profile_env();

        let profile = resolve_relay_transport_profile();
        let request = apply_transport_profile_headers(
            reqwest::Client::new().get("https://relay.example/health"),
            &profile,
        )
        .build()
        .expect("build request");

        assert_eq!(
            request
                .headers()
                .get("user-agent")
                .and_then(|v| v.to_str().ok()),
            Some("redoor-relay-client/1.0")
        );
        assert_eq!(
            request
                .headers()
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("identity")
        );
        assert_eq!(
            request
                .headers()
                .get("connection")
                .and_then(|v| v.to_str().ok()),
            Some("close")
        );

        clear_transport_profile_env();
    }

    #[test]
    fn connection_metrics_snapshot_defaults_to_zeroes() {
        let relay = RelayClient::new("https://relay.example");
        let snapshot = relay.connection_metrics_snapshot();

        assert_eq!(snapshot.rtt_ms, 0);
        assert_eq!(snapshot.packet_loss_percent, 0.0);
        assert_eq!(snapshot.throughput_kbps, 0);
    }

    #[test]
    fn connection_metrics_snapshot_reflects_recorded_samples() {
        let relay = RelayClient::new("https://relay.example");
        relay.record_connection_sample_for_tests(std::time::Duration::from_millis(100), 4000, 2000, true);
        relay.record_connection_sample_for_tests(std::time::Duration::from_millis(300), 0, 0, false);

        let snapshot = relay.connection_metrics_snapshot();
        assert_eq!(snapshot.rtt_ms, 100);
        assert_eq!(snapshot.packet_loss_percent, 50.0);
        assert!(snapshot.throughput_kbps > 0);
    }
}
