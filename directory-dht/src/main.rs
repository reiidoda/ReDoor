use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::time::Instant;

type Store = Arc<RwLock<HashMap<String, UsernameRecord>>>;
type PrekeyStore = Arc<RwLock<HashMap<String, TimedBlob>>>;

#[derive(Clone)]
struct UsernameRecord {
    public_key: Vec<u8>,
    seq: u64,
    expires_at: u64,
}

#[derive(Clone)]
struct TimedBlob {
    data: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct AppState {
    store: Store,
    prekey_store: PrekeyStore,
    publish_token: Option<String>,
    limiter: Arc<IpLimiter>,
    require_tls: bool,
    resolve_signing_key: Arc<SigningKey>,
    username_max_lease_secs: u64,
    prekey_max_ttl_secs: u64,
    anomaly: Arc<RwLock<DirectoryAnomalyController>>,
}

#[derive(Clone)]
struct DirectoryAnomalyController {
    window_sec: u64,
    replay_cfg: DetectorConfig,
    malformed_cfg: DetectorConfig,
    credential_cfg: DetectorConfig,
    replay: DetectorState,
    malformed: DetectorState,
    credential: DetectorState,
}

#[derive(Clone, Copy)]
struct DetectorConfig {
    threshold: u64,
    rate_multiplier: f64,
}

#[derive(Clone, Default)]
struct DetectorState {
    window_start_unix: u64,
    current_count: u64,
    previous_count: u64,
    alerts: u64,
    last_alert_at_unix: u64,
    last_alert_count: u64,
    last_alert_reason: String,
    alerted_window_start_unix: u64,
}

#[derive(Serialize, Deserialize)]
struct DetectorSnapshot {
    current_window_count: u64,
    previous_window_count: u64,
    threshold: u64,
    rate_multiplier: f64,
    alerts: u64,
    last_alert_at_unix: u64,
    last_alert_count: u64,
    last_alert_reason: String,
}

#[derive(Serialize, Deserialize)]
struct DirectoryAnomalySnapshot {
    window_sec: u64,
    generated_at_unix: u64,
    replay_spike: DetectorSnapshot,
    malformed_burst: DetectorSnapshot,
    credential_spray: DetectorSnapshot,
    action_map: HashMap<String, String>,
}

#[derive(Deserialize)]
struct PublishReq {
    #[serde(alias = "id")]
    username: String,
    #[serde(alias = "data_b64")]
    public_key: String,
    signature: String,
    seq: u64,
    expires_at: u64,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Serialize)]
struct QueryResp {
    data_b64: String,
}

#[derive(Serialize, Deserialize)]
struct ResolveResp {
    public_key: String,
    signature: String,
    key_id: String,
    issued_at: u64,
    seq: u64,
    expires_at: u64,
}

#[derive(Deserialize)]
struct ResolveReq {
    username: String,
}

#[derive(Deserialize)]
struct PrekeyPublishReq {
    id: String,
    data_b64: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PrekeyQueryResp {
    data_b64: String,
    expires_at: u64,
}

struct IpLimiter {
    inner: RwLock<HashMap<String, Bucket>>,
    rps: f64,
    burst: f64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

fn is_https(headers: &HeaderMap) -> bool {
    if let Some(proto) = headers.get("x-forwarded-proto") {
        if let Ok(v) = proto.to_str() {
            return v.eq_ignore_ascii_case("https");
        }
    }
    // If no header is present, we conservatively fail (when TLS is required).
    false
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn prekey_ttl_secs(req_ttl: Option<u64>, max_ttl: u64) -> u64 {
    let requested = req_ttl.unwrap_or(3600);
    requested.max(60).min(max_ttl.max(60))
}

async fn security_headers(req: Request<Body>, next: Next) -> impl IntoResponse {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    res
}

impl IpLimiter {
    fn new(rps: f64, burst: f64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            rps,
            burst,
        }
    }

    fn allow(&self, ip: &str) -> bool {
        if self.rps <= 0.0 {
            return true;
        }
        let mut map = self.inner.write();
        let now = Instant::now();
        let b = map.entry(ip.to_string()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * self.rps).min(self.burst);
        if b.tokens < 1.0 {
            return false;
        }
        b.tokens -= 1.0;
        true
    }
}

impl DirectoryAnomalyController {
    fn from_env() -> Self {
        let window_sec = std::env::var("DIR_ANOMALY_WINDOW_SEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(60);
        let rate_multiplier = std::env::var("DIR_ANOMALY_RATE_MULTIPLIER")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|v| *v >= 1.0)
            .unwrap_or(3.0);

        Self {
            window_sec,
            replay_cfg: DetectorConfig {
                threshold: std::env::var("DIR_REPLAY_SPIKE_THRESHOLD")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|v| *v > 0)
                    .unwrap_or(20),
                rate_multiplier,
            },
            malformed_cfg: DetectorConfig {
                threshold: std::env::var("DIR_MALFORMED_BURST_THRESHOLD")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|v| *v > 0)
                    .unwrap_or(25),
                rate_multiplier,
            },
            credential_cfg: DetectorConfig {
                threshold: std::env::var("DIR_CREDENTIAL_SPRAY_THRESHOLD")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|v| *v > 0)
                    .unwrap_or(30),
                rate_multiplier,
            },
            replay: DetectorState::default(),
            malformed: DetectorState::default(),
            credential: DetectorState::default(),
        }
    }

    fn observe_replay(&mut self) {
        let now = now_unix_secs();
        Self::observe_detector(now, self.window_sec, self.replay_cfg, &mut self.replay);
    }

    fn observe_malformed(&mut self) {
        let now = now_unix_secs();
        Self::observe_detector(
            now,
            self.window_sec,
            self.malformed_cfg,
            &mut self.malformed,
        );
    }

    fn observe_credential(&mut self) {
        let now = now_unix_secs();
        Self::observe_detector(
            now,
            self.window_sec,
            self.credential_cfg,
            &mut self.credential,
        );
    }

    fn snapshot(&mut self) -> DirectoryAnomalySnapshot {
        let now = now_unix_secs();
        Self::rotate(now, self.window_sec, &mut self.replay);
        Self::rotate(now, self.window_sec, &mut self.malformed);
        Self::rotate(now, self.window_sec, &mut self.credential);

        let mut action_map = HashMap::new();
        action_map.insert(
            "directory_replay_spike".to_string(),
            "runbook:section-3-b-directory-signing-key-rotation".to_string(),
        );
        action_map.insert(
            "directory_malformed_burst".to_string(),
            "runbook:section-2-immediate-triage".to_string(),
        );
        action_map.insert(
            "directory_credential_spray".to_string(),
            "runbook:section-2-immediate-triage".to_string(),
        );

        DirectoryAnomalySnapshot {
            window_sec: self.window_sec,
            generated_at_unix: now,
            replay_spike: Self::to_snapshot(self.replay.clone(), self.replay_cfg),
            malformed_burst: Self::to_snapshot(self.malformed.clone(), self.malformed_cfg),
            credential_spray: Self::to_snapshot(self.credential.clone(), self.credential_cfg),
            action_map,
        }
    }

    fn observe_detector(now: u64, window_sec: u64, cfg: DetectorConfig, st: &mut DetectorState) {
        Self::rotate(now, window_sec, st);
        st.current_count = st.current_count.saturating_add(1);
        if st.alerted_window_start_unix == st.window_start_unix {
            return;
        }

        let threshold_triggered = st.current_count >= cfg.threshold;
        let rate_triggered = st.previous_count > 0
            && (st.current_count as f64) >= (st.previous_count as f64) * cfg.rate_multiplier;
        if !threshold_triggered && !rate_triggered {
            return;
        }

        st.alerts = st.alerts.saturating_add(1);
        st.last_alert_at_unix = now;
        st.last_alert_count = st.current_count;
        st.last_alert_reason = if threshold_triggered {
            "threshold".to_string()
        } else {
            "rate_of_change".to_string()
        };
        st.alerted_window_start_unix = st.window_start_unix;
    }

    fn rotate(now: u64, window_sec: u64, st: &mut DetectorState) {
        let win = window_sec.max(1);
        if st.window_start_unix == 0 {
            st.window_start_unix = now - (now % win);
            return;
        }
        if now < st.window_start_unix.saturating_add(win) {
            return;
        }
        let elapsed = now.saturating_sub(st.window_start_unix);
        let windows = elapsed / win;
        st.previous_count = if windows > 1 { 0 } else { st.current_count };
        st.current_count = 0;
        st.window_start_unix = st.window_start_unix.saturating_add(windows * win);
    }

    fn to_snapshot(st: DetectorState, cfg: DetectorConfig) -> DetectorSnapshot {
        DetectorSnapshot {
            current_window_count: st.current_count,
            previous_window_count: st.previous_count,
            threshold: cfg.threshold,
            rate_multiplier: cfg.rate_multiplier,
            alerts: st.alerts,
            last_alert_at_unix: st.last_alert_at_unix,
            last_alert_count: st.last_alert_count,
            last_alert_reason: st.last_alert_reason,
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Starting Redoor Directory DHT Node (HTTP facade)...");

    let publish_token = std::env::var("DIR_TOKEN").ok();
    let rps = std::env::var("DIR_RPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10.0);
    let burst = std::env::var("DIR_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0);
    let max_body_bytes = std::env::var("DIR_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(64 * 1024);
    let username_max_lease_secs = std::env::var("DIR_USERNAME_MAX_LEASE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(7 * 24 * 60 * 60);
    let prekey_max_ttl_secs = std::env::var("DIR_PREKEY_MAX_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(24 * 60 * 60);
    let require_tls = std::env::var("DIR_REQUIRE_TLS").ok() == Some("1".to_string());
    let resolve_signing_key = load_resolve_signing_key()
        .expect("DIR_SIGNING_KEY_HEX must be a 32-byte hex ed25519 secret key");
    println!(
        "Directory resolve signing pubkey: {}",
        hex::encode(resolve_signing_key.verifying_key().to_bytes())
    );

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        prekey_store: Arc::new(RwLock::new(HashMap::new())),
        publish_token,
        limiter: Arc::new(IpLimiter::new(rps, burst)),
        require_tls,
        resolve_signing_key: Arc::new(resolve_signing_key),
        username_max_lease_secs,
        prekey_max_ttl_secs,
        anomaly: Arc::new(RwLock::new(DirectoryAnomalyController::from_env())),
    };

    let app = Router::new()
        .route("/publish", post(publish))
        .route("/query/:id", get(query))
        .route("/resolve", get(resolve))
        .route("/prekey/publish", post(prekey_publish))
        .route("/prekey/query/:id", get(prekey_query))
        .route("/metrics/anomaly", get(anomaly_metrics))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn(security_headers));

    let addr: SocketAddr = std::env::var("DIR_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:7070".to_string())
        .parse()
        .expect("invalid DIR_ADDR");

    let cert_file = std::env::var("DIR_CERT_FILE").ok();
    let key_file = std::env::var("DIR_KEY_FILE").ok();

    if cert_file.is_some() && key_file.is_some() {
        let tls_config =
            RustlsConfig::from_pem_file(cert_file.as_ref().unwrap(), key_file.as_ref().unwrap())
                .await
                .expect("failed to load TLS certs");
        println!("Directory listening on {} (TLS)", addr);
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("directory server failed");
    } else {
        if require_tls {
            panic!("DIR_REQUIRE_TLS=1 but DIR_CERT_FILE/DIR_KEY_FILE not set");
        }
        println!("Directory listening on {} (plaintext)", addr);
        let listener = TcpListener::bind(addr).await.expect("bind failed");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("directory server failed");
    }
}

async fn publish(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PublishReq>,
) -> impl IntoResponse {
    if state.require_tls && !is_https(&headers) {
        return (StatusCode::UPGRADE_REQUIRED, "https required").into_response();
    }
    if !state.limiter.allow(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    if let Some(tok) = &state.publish_token {
        if req.token.as_deref() != Some(tok) {
            state.anomaly.write().observe_credential();
            return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
        }
    }

    if req.username.len() > 128 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "username too long").into_response();
    }
    if req.public_key.len() > 128 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "public key too long").into_response();
    }
    if req.signature.len() > 256 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "signature too long").into_response();
    }
    if req.seq == 0 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "seq must be >= 1").into_response();
    }
    let now = now_unix_secs();
    if req.expires_at <= now {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "expires_at must be in the future").into_response();
    }
    let max_allowed_expiry = now.saturating_add(state.username_max_lease_secs.max(60));
    if req.expires_at > max_allowed_expiry {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "expires_at exceeds lease policy").into_response();
    }
    if let Err(msg) = verify_publish_signature(
        &req.username,
        &req.public_key,
        req.seq,
        req.expires_at,
        &req.signature,
    ) {
        state.anomaly.write().observe_credential();
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    let public_key_bytes = match hex::decode(&req.public_key) {
        Ok(v) => v,
        Err(_) => {
            state.anomaly.write().observe_malformed();
            return (StatusCode::BAD_REQUEST, "invalid public key hex").into_response();
        }
    };

    {
        let mut map = state.store.write();
        if let Some(existing) = map.get(&req.username) {
            if existing.public_key.as_slice() != public_key_bytes.as_slice() {
                return (
                    StatusCode::CONFLICT,
                    "username already claimed by another public key",
                )
                    .into_response();
            }
            if req.seq <= existing.seq {
                state.anomaly.write().observe_replay();
                return (
                    StatusCode::CONFLICT,
                    "non-monotonic sequence for username update",
                )
                    .into_response();
            }
        } else if req.seq != 1 {
            state.anomaly.write().observe_replay();
            return (StatusCode::CONFLICT, "first claim must start at seq=1").into_response();
        }
        map.insert(
            req.username.clone(),
            UsernameRecord {
                public_key: public_key_bytes,
                seq: req.seq,
                expires_at: req.expires_at,
            },
        );
    }
    (StatusCode::OK, "published").into_response()
}

async fn query(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.require_tls && !is_https(&headers) {
        return (StatusCode::UPGRADE_REQUIRED, "https required").into_response();
    }
    if !state.limiter.allow(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let now = now_unix_secs();
    let mut map = state.store.write();
    let data = map.get(&id).cloned();
    match data {
        Some(d) if d.expires_at > now => {
            let resp = QueryResp {
                data_b64: B64.encode(d.public_key),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Some(_) => {
            map.remove(&id);
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn resolve(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(req): Query<ResolveReq>,
) -> impl IntoResponse {
    if state.require_tls && !is_https(&headers) {
        return (StatusCode::UPGRADE_REQUIRED, "https required").into_response();
    }
    if !state.limiter.allow(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let now = now_unix_secs();
    let mut map = state.store.write();
    let data = map.get(&req.username).cloned();

    match data {
        Some(d) if d.expires_at > now => {
            let public_key_hex = hex::encode(&d.public_key);
            let issued_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let signature = hex::encode(
                state
                    .resolve_signing_key
                    .sign(&resolve_signing_message(
                        &req.username,
                        &public_key_hex,
                        d.seq,
                        d.expires_at,
                        issued_at,
                    ))
                    .to_bytes(),
            );
            let resp = ResolveResp {
                public_key: public_key_hex,
                signature,
                key_id: hex::encode(state.resolve_signing_key.verifying_key().to_bytes()),
                issued_at,
                seq: d.seq,
                expires_at: d.expires_at,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Some(_) => {
            map.remove(&req.username);
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn prekey_publish(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PrekeyPublishReq>,
) -> impl IntoResponse {
    if state.require_tls && !is_https(&headers) {
        return (StatusCode::UPGRADE_REQUIRED, "https required").into_response();
    }
    if !state.limiter.allow(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    if let Some(tok) = &state.publish_token {
        if req.token.as_deref() != Some(tok) {
            state.anomaly.write().observe_credential();
            return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
        }
    }

    if req.id.is_empty() || req.id.len() > 256 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "invalid prekey id").into_response();
    }
    if req.data_b64.is_empty() || req.data_b64.len() > 128 * 1024 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "invalid prekey payload").into_response();
    }

    let payload = match B64.decode(req.data_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => {
            state.anomaly.write().observe_malformed();
            return (StatusCode::BAD_REQUEST, "invalid base64 payload").into_response();
        }
    };
    if payload.len() > 64 * 1024 {
        state.anomaly.write().observe_malformed();
        return (StatusCode::BAD_REQUEST, "prekey payload too large").into_response();
    }

    let ttl = prekey_ttl_secs(req.ttl_secs, state.prekey_max_ttl_secs);
    let expires_at = now_unix_secs().saturating_add(ttl);

    let mut map = state.prekey_store.write();
    map.insert(
        req.id,
        TimedBlob {
            data: payload,
            expires_at,
        },
    );

    (StatusCode::OK, "published").into_response()
}

async fn prekey_query(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.require_tls && !is_https(&headers) {
        return (StatusCode::UPGRADE_REQUIRED, "https required").into_response();
    }
    if !state.limiter.allow(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let now = now_unix_secs();
    let mut map = state.prekey_store.write();
    let entry = map.get(&id).cloned();
    match entry {
        Some(blob) if blob.expires_at > now => {
            let resp = PrekeyQueryResp {
                data_b64: B64.encode(blob.data),
                expires_at: blob.expires_at,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Some(_) => {
            map.remove(&id);
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn anomaly_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let mut anomaly = state.anomaly.write();
    let snapshot = anomaly.snapshot();
    (StatusCode::OK, Json(snapshot)).into_response()
}

fn load_resolve_signing_key() -> Result<SigningKey, &'static str> {
    let key_hex = std::env::var("DIR_SIGNING_KEY_HEX")
        .map_err(|_| "missing DIR_SIGNING_KEY_HEX environment variable")?;
    let key_bytes = hex::decode(key_hex).map_err(|_| "invalid DIR_SIGNING_KEY_HEX hex")?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "DIR_SIGNING_KEY_HEX must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&key_arr))
}

fn publish_signing_message(
    username: &str,
    public_key_hex: &str,
    seq: u64,
    expires_at: u64,
) -> Vec<u8> {
    format!("redoor-directory-publish:v2:{username}:{public_key_hex}:{seq}:{expires_at}")
        .into_bytes()
}

fn resolve_signing_message(
    username: &str,
    public_key_hex: &str,
    seq: u64,
    expires_at: u64,
    issued_at: u64,
) -> Vec<u8> {
    format!(
        "redoor-directory-resolve:v2:{username}:{public_key_hex}:{seq}:{expires_at}:{issued_at}"
    )
    .into_bytes()
}

fn verify_publish_signature(
    username: &str,
    public_key_hex: &str,
    seq: u64,
    expires_at: u64,
    signature_hex: &str,
) -> Result<(), &'static str> {
    let public_key_bytes = hex::decode(public_key_hex).map_err(|_| "invalid public key hex")?;
    let signature_bytes = hex::decode(signature_hex).map_err(|_| "invalid signature hex")?;

    let public_key_arr: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid public key length")?;
    let signature_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid signature length")?;

    let vk = VerifyingKey::from_bytes(&public_key_arr).map_err(|_| "invalid public key format")?;
    let sig = Signature::from_bytes(&signature_arr);
    let msg = publish_signing_message(username, public_key_hex, seq, expires_at);
    vk.verify(&msg, &sig).map_err(|_| "invalid signature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::Response;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_state() -> AppState {
        AppState {
            store: Arc::new(RwLock::new(HashMap::new())),
            prekey_store: Arc::new(RwLock::new(HashMap::new())),
            publish_token: None,
            limiter: Arc::new(IpLimiter::new(0.0, 0.0)),
            require_tls: false,
            resolve_signing_key: Arc::new(signing_key(42)),
            username_max_lease_secs: 3600,
            prekey_max_ttl_secs: 3600,
            anomaly: Arc::new(RwLock::new(DirectoryAnomalyController::from_env())),
        }
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    async fn publish_call(state: AppState, req: PublishReq) -> Response {
        publish(
            State(state),
            ConnectInfo("127.0.0.1:7000".parse().unwrap()),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .into_response()
    }

    #[tokio::test]
    async fn publish_accepts_valid_signature() {
        let sk = signing_key(7);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let seq = 1;
        let expires_at = now_unix_secs().saturating_add(120);
        let sig = hex::encode(
            sk.sign(&publish_signing_message("alice", &pk_hex, seq, expires_at))
                .to_bytes(),
        );
        let state = test_state();

        let resp = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk_hex.clone(),
                signature: sig,
                seq,
                expires_at,
                token: None,
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resolve_resp = resolve(
            State(state.clone()),
            ConnectInfo("127.0.0.1:7000".parse().unwrap()),
            HeaderMap::new(),
            Query(ResolveReq {
                username: "alice".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resolve_resp.status(), StatusCode::OK);
        let body = to_bytes(resolve_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: ResolveResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.public_key, pk_hex);
        assert_eq!(
            parsed.key_id,
            hex::encode(state.resolve_signing_key.verifying_key().to_bytes())
        );
        assert_eq!(parsed.seq, seq);
        assert_eq!(parsed.expires_at, expires_at);
        let msg = resolve_signing_message(
            "alice",
            &parsed.public_key,
            parsed.seq,
            parsed.expires_at,
            parsed.issued_at,
        );
        let sig_bytes = hex::decode(parsed.signature).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_arr);
        state
            .resolve_signing_key
            .verifying_key()
            .verify(&msg, &sig)
            .unwrap();
    }

    #[tokio::test]
    async fn publish_rejects_invalid_signature() {
        let sk = signing_key(8);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let bad_sig = hex::encode(sk.sign(b"wrong-message").to_bytes());
        let state = test_state();

        let resp = publish_call(
            state,
            PublishReq {
                username: "alice".to_string(),
                public_key: pk_hex,
                signature: bad_sig,
                seq: 1,
                expires_at: now_unix_secs().saturating_add(120),
                token: None,
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_rejects_username_takeover_by_different_key() {
        let sk1 = signing_key(10);
        let pk1 = hex::encode(sk1.verifying_key().to_bytes());
        let seq1 = 1;
        let expires1 = now_unix_secs().saturating_add(120);
        let sig1 = hex::encode(
            sk1.sign(&publish_signing_message("alice", &pk1, seq1, expires1))
                .to_bytes(),
        );

        let sk2 = signing_key(11);
        let pk2 = hex::encode(sk2.verifying_key().to_bytes());
        let seq2 = 2;
        let expires2 = now_unix_secs().saturating_add(240);
        let sig2 = hex::encode(
            sk2.sign(&publish_signing_message("alice", &pk2, seq2, expires2))
                .to_bytes(),
        );

        let state = test_state();

        let first = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk1,
                signature: sig1,
                seq: seq1,
                expires_at: expires1,
                token: None,
            },
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = publish_call(
            state,
            PublishReq {
                username: "alice".to_string(),
                public_key: pk2,
                signature: sig2,
                seq: seq2,
                expires_at: expires2,
                token: None,
            },
        )
        .await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn publish_rejects_oversized_public_key_field() {
        let state = test_state();
        let oversized_key = "a".repeat(129);
        let resp = publish_call(
            state,
            PublishReq {
                username: "alice".to_string(),
                public_key: oversized_key,
                signature: "b".repeat(64),
                seq: 1,
                expires_at: now_unix_secs().saturating_add(120),
                token: None,
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_allows_valid_monotonic_update() {
        let sk = signing_key(12);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let first_seq = 1;
        let first_expiry = now_unix_secs().saturating_add(120);
        let first_sig = hex::encode(
            sk.sign(&publish_signing_message(
                "alice",
                &pk,
                first_seq,
                first_expiry,
            ))
            .to_bytes(),
        );

        let second_seq = 2;
        let second_expiry = now_unix_secs().saturating_add(240);
        let second_sig = hex::encode(
            sk.sign(&publish_signing_message(
                "alice",
                &pk,
                second_seq,
                second_expiry,
            ))
            .to_bytes(),
        );

        let state = test_state();
        let first = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk.clone(),
                signature: first_sig,
                seq: first_seq,
                expires_at: first_expiry,
                token: None,
            },
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk,
                signature: second_sig,
                seq: second_seq,
                expires_at: second_expiry,
                token: None,
            },
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn publish_rejects_replay_update_with_same_seq() {
        let sk = signing_key(13);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let seq = 1;
        let expires_at = now_unix_secs().saturating_add(120);
        let sig = hex::encode(
            sk.sign(&publish_signing_message("alice", &pk, seq, expires_at))
                .to_bytes(),
        );

        let state = test_state();
        let first = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk.clone(),
                signature: sig.clone(),
                seq,
                expires_at,
                token: None,
            },
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let replay = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk,
                signature: sig,
                seq,
                expires_at,
                token: None,
            },
        )
        .await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn publish_rejects_expired_update() {
        let sk = signing_key(14);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let seq = 1;
        let expires_at = now_unix_secs().saturating_sub(1);
        let sig = hex::encode(
            sk.sign(&publish_signing_message("alice", &pk, seq, expires_at))
                .to_bytes(),
        );

        let state = test_state();
        let resp = publish_call(
            state,
            PublishReq {
                username: "alice".to_string(),
                public_key: pk,
                signature: sig,
                seq,
                expires_at,
                token: None,
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    async fn prekey_publish_call(state: AppState, req: PrekeyPublishReq) -> Response {
        prekey_publish(
            State(state),
            ConnectInfo("127.0.0.1:7000".parse().unwrap()),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .into_response()
    }

    #[tokio::test]
    async fn prekey_publish_and_query_roundtrip() {
        let state = test_state();
        let payload = b"{\"bundle\":\"v1\"}".to_vec();
        let key_id = "alice-key".to_string();

        let publish_resp = prekey_publish_call(
            state.clone(),
            PrekeyPublishReq {
                id: key_id.clone(),
                data_b64: B64.encode(&payload),
                ttl_secs: Some(120),
                token: None,
            },
        )
        .await;
        assert_eq!(publish_resp.status(), StatusCode::OK);

        let query_resp = prekey_query(
            State(state),
            ConnectInfo("127.0.0.1:7000".parse().unwrap()),
            HeaderMap::new(),
            Path(key_id),
        )
        .await
        .into_response();
        assert_eq!(query_resp.status(), StatusCode::OK);
        let body = to_bytes(query_resp.into_body(), usize::MAX).await.unwrap();
        let parsed: PrekeyQueryResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(B64.decode(parsed.data_b64).unwrap(), payload);
        assert!(parsed.expires_at > now_unix_secs());
    }

    #[tokio::test]
    async fn prekey_query_removes_expired_entry() {
        let state = test_state();
        {
            let mut map = state.prekey_store.write();
            map.insert(
                "expired".to_string(),
                TimedBlob {
                    data: b"stale".to_vec(),
                    expires_at: now_unix_secs().saturating_sub(1),
                },
            );
        }

        let query_resp = prekey_query(
            State(state.clone()),
            ConnectInfo("127.0.0.1:7000".parse().unwrap()),
            HeaderMap::new(),
            Path("expired".to_string()),
        )
        .await
        .into_response();
        assert_eq!(query_resp.status(), StatusCode::NOT_FOUND);

        let map = state.prekey_store.read();
        assert!(!map.contains_key("expired"));
    }

    #[tokio::test]
    async fn anomaly_records_replay_and_credential_signals() {
        let state = test_state();
        let sk = signing_key(77);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let seq = 1;
        let expires_at = now_unix_secs().saturating_add(120);
        let sig = hex::encode(
            sk.sign(&publish_signing_message("alice", &pk, seq, expires_at))
                .to_bytes(),
        );

        let first = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk.clone(),
                signature: sig.clone(),
                seq,
                expires_at,
                token: None,
            },
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let replay = publish_call(
            state.clone(),
            PublishReq {
                username: "alice".to_string(),
                public_key: pk,
                signature: sig,
                seq,
                expires_at,
                token: None,
            },
        )
        .await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        let bad_sig = publish_call(
            state.clone(),
            PublishReq {
                username: "mallory".to_string(),
                public_key: "11".repeat(32),
                signature: "22".repeat(64),
                seq: 1,
                expires_at: now_unix_secs().saturating_add(120),
                token: None,
            },
        )
        .await;
        assert_eq!(bad_sig.status(), StatusCode::BAD_REQUEST);

        let snapshot = state.anomaly.write().snapshot();
        assert!(snapshot.replay_spike.current_window_count > 0);
        assert!(snapshot.credential_spray.current_window_count > 0);
    }

    #[tokio::test]
    async fn anomaly_metrics_exposes_action_map() {
        let state = test_state();
        state.anomaly.write().observe_malformed();

        let resp = anomaly_metrics(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let snapshot: DirectoryAnomalySnapshot = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            snapshot
                .action_map
                .get("directory_malformed_burst")
                .map(String::as_str),
            Some("runbook:section-2-immediate-triage")
        );
    }
}
