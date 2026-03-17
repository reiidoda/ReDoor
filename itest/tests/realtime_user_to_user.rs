use anyhow::{anyhow, Context, Result};
use base64::Engine;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use redoor_client::config::{self, TrafficShapingConfig};
use redoor_client::crypto::x25519;
use redoor_client::engine::{ClientEngine, SessionEntry};
use redoor_client::network::relay::RelayClient;
use redoor_client::orchestrator;
use redoor_client::ratchet::double_ratchet::RatchetSession;
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    fn spawn(name: &'static str, mut cmd: Command) -> Result<Self> {
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn {name}"))?;
        Ok(Self { child })
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[derive(Default)]
struct EnvGuard {
    saved: HashMap<String, Option<String>>,
}

impl EnvGuard {
    fn set(&mut self, key: &str, value: String) {
        self.saved
            .entry(key.to_string())
            .or_insert_with(|| std::env::var(key).ok());
        std::env::set_var(key, value);
    }

    fn remove(&mut self, key: &str) {
        self.saved
            .entry(key.to_string())
            .or_insert_with(|| std::env::var(key).ok());
        std::env::remove_var(key);
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain() {
            if let Some(value) = prev {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct PolledMessage {
    sender: String,
    content: String,
    msg_type: String,
}

#[derive(Debug, Serialize, Clone)]
struct ReliabilityThresholds {
    cycles: usize,
    messages_per_cycle: usize,
    relay_down_ms: u64,
    delivery_timeout_ms: u64,
    reconnect_timeout_ms: u64,
    min_delivery_ratio: f64,
    max_reconnect_latency_ms: u128,
    max_runtime_growth_bytes: usize,
}

#[derive(Debug, Serialize, Clone, Default)]
struct ReliabilityMetrics {
    total_send_attempts: usize,
    successful_sends: usize,
    send_failures: usize,
    delivery_eligible_sends: usize,
    delivery_successes: usize,
    delivery_misses: usize,
    fetch_attempts: usize,
    fetch_successes: usize,
    fetch_empty_polls: usize,
    reconnect_events: usize,
    reconnect_timeouts: usize,
    chaos_outage_failures: usize,
    baseline_runtime_bytes: usize,
    max_runtime_bytes_after_cleanup: usize,
    reconnect_latency_ms: Vec<u128>,
    reconnect_p95_ms: u128,
    delivery_latency_ms: Vec<u128>,
    delivery_ratio: f64,
    error_rate: f64,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize, Clone)]
struct ReliabilityReport {
    thresholds: ReliabilityThresholds,
    metrics: ReliabilityMetrics,
    checks_passed: bool,
    violations: Vec<String>,
}

fn repo_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("failed to resolve repository root"))
}

fn reserve_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("bind ephemeral port")?;
    let port = listener
        .local_addr()
        .context("read local socket addr")?
        .port();
    Ok(port)
}

fn wait_for_tcp(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow!("port {port} not ready after {:?}", timeout))
}

fn write_relay_cert_pair(work_dir: &Path) -> Result<(PathBuf, PathBuf, String)> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert =
        Certificate::from_params(params).context("generate relay self-signed certificate")?;
    let cert_pem = cert
        .serialize_pem()
        .context("serialize relay certificate pem")?;
    let cert_der = cert
        .serialize_der()
        .context("serialize relay certificate der")?;
    let key_pem = cert.serialize_private_key_pem();

    let cert_path = work_dir.join("relay-cert.pem");
    let key_path = work_dir.join("relay-key.pem");
    fs::write(&cert_path, cert_pem).context("write relay certificate")?;
    fs::write(&key_path, key_pem).context("write relay key")?;

    let ca_b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
    Ok((cert_path, key_path, ca_b64))
}

fn build_https_client_with_cert(relay_cert_path: &Path) -> Result<HttpClient> {
    let cert_pem = fs::read(relay_cert_path).context("read relay cert pem")?;
    let cert = reqwest::Certificate::from_pem(&cert_pem).context("parse relay cert pem")?;

    reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .use_rustls_tls()
        .build()
        .context("build reqwest client with relay cert")
}

fn spawn_relay(
    root: &Path,
    relay_cert_path: &Path,
    relay_key_path: &Path,
    relay_port: u16,
) -> Result<ManagedChild> {
    let mut relay_cmd = Command::new("go");
    relay_cmd
        .current_dir(root.join("relay-node"))
        .arg("run")
        .arg("./src/main.go")
        .env("RELAY_CERT_FILE", relay_cert_path)
        .env("RELAY_KEY_FILE", relay_key_path)
        .env("RELAY_ADDR", format!("127.0.0.1:{relay_port}"));
    ManagedChild::spawn("relay", relay_cmd)
}

fn env_or_default_usize(key: &str, default_value: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_value)
}

fn env_or_default_u64(key: &str, default_value: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_value)
}

fn env_or_default_f64(key: &str, default_value: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default_value)
}

fn runtime_bytes(engine: &ClientEngine) -> usize {
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

    let mut pending_size = 0usize;
    for (id, blob) in guard.pending_blobs.lock().unwrap().iter() {
        pending_size += id.len() + blob.len();
    }

    msg_store_size + attach_size + log_size + pending_size
}

fn clear_runtime_buffers(engine: &ClientEngine) {
    let mut guard = engine.state.lock().unwrap();
    guard.message_store.clear();
    guard.attachment_cache.clear();
    guard.log_buffer.clear();
    guard.pending_blobs.lock().unwrap().clear();
}

fn wait_for_expected_message(
    engine: &ClientEngine,
    receiver_id: &str,
    expected_sender_id: &str,
    expected_payload: &str,
    timeout: Duration,
    metrics: &mut ReliabilityMetrics,
) -> Result<Duration> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        metrics.fetch_attempts += 1;
        match fetch_one_pending_into_engine(engine, receiver_id) {
            Ok(()) => {
                metrics.fetch_successes += 1;
                let polled = poll_messages(engine)?;
                if polled.iter().any(|msg| {
                    msg.msg_type == "text"
                        && msg.sender == expected_sender_id
                        && msg.content == expected_payload
                }) {
                    return Ok(started.elapsed());
                }
            }
            Err(_) => {
                metrics.fetch_empty_polls += 1;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }

    Err(anyhow!(
        "timed out waiting for payload '{expected_payload}' after {:?}",
        timeout
    ))
}

fn drain_pending_mailbox(
    engine: &ClientEngine,
    receiver_id: &str,
    max_fetches: usize,
) -> Result<usize> {
    let mut drained = 0usize;
    for _ in 0..max_fetches {
        if fetch_one_pending_into_engine(engine, receiver_id).is_ok() {
            let _ = poll_messages(engine)?;
            drained += 1;
        } else {
            break;
        }
    }
    Ok(drained)
}

fn percentile_u128(values: &[u128], percentile: f64) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn write_reliability_report(path: &Path, report: &ReliabilityReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create artifact directory {}", parent.display()))?;
    }

    let json = serde_json::to_vec_pretty(report).context("serialize reliability report")?;
    fs::write(path, json).with_context(|| format!("write reliability report {}", path.display()))
}

fn setup_user_engine(engine: &ClientEngine, relay_url: &str) -> String {
    engine.initialize_keys();
    let relay = RelayClient::new(relay_url);

    let mut guard = engine.state.lock().unwrap();
    guard.relay_client = Some(relay);
    // This integration test validates real-time relay behavior with direct delivery.
    // Onion-path behavior is validated separately in dedicated strict-anonymity tests.
    guard.anonymity_mode_enabled.store(false, Ordering::Relaxed);
    hex::encode(
        guard
            .identity
            .as_ref()
            .expect("identity initialized")
            .public_key_bytes(),
    )
}

fn set_relay_client(engine: &ClientEngine, relay_url: &str) {
    let mut guard = engine.state.lock().unwrap();
    guard.relay_client = Some(RelayClient::new(relay_url));
}

fn pair_sessions(alice: &ClientEngine, bob: &ClientEngine, alice_id: &str, bob_id: &str) {
    let (alice_priv, alice_pub) = x25519::generate_keypair();
    let (bob_priv, bob_pub) = x25519::generate_keypair();
    let alice_shared = x25519::diffie_hellman(&alice_priv, &bob_pub);
    let bob_shared = x25519::diffie_hellman(&bob_priv, &alice_pub);
    assert_eq!(alice_shared, bob_shared, "shared secret mismatch");

    let alice_session = RatchetSession::new(alice_shared, Some(bob_pub));
    let bob_session = RatchetSession::new(bob_shared, Some(alice_pub));

    {
        let mut guard = alice.state.lock().unwrap();
        guard.sessions.insert(
            bob_id.to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(alice_session),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );
    }

    {
        let mut guard = bob.state.lock().unwrap();
        guard.sessions.insert(
            alice_id.to_string(),
            SessionEntry {
                wrapped_state: None,
                inner: Some(bob_session),
                pending_handshake: None,
                peer_seal_key: None,
            },
        );
    }
}

fn send_payload_with_retry(
    sender: &ClientEngine,
    receiver_id: &str,
    payload: &str,
    timeout: Duration,
) -> i32 {
    let started = Instant::now();
    let mut last_rc = -1;
    while started.elapsed() < timeout {
        last_rc = sender.send_payload(receiver_id, payload, "text", None, false, false, None);
        if last_rc == 0 {
            return 0;
        }
        thread::sleep(Duration::from_millis(100));
    }
    last_rc
}

fn fetch_one_pending_into_engine(engine: &ClientEngine, receiver_id: &str) -> Result<()> {
    let relay = {
        let guard = engine.state.lock().unwrap();
        guard
            .relay_client
            .clone()
            .ok_or_else(|| anyhow!("missing relay client"))?
    };

    let (msg_id, blob) = engine
        .runtime
        .block_on(orchestrator::fetch_pending_with_retry(
            &relay,
            receiver_id,
            0,
            Duration::from_millis(50),
            Duration::from_millis(500),
        ))?;

    let guard = engine.state.lock().unwrap();
    guard
        .pending_blobs
        .lock()
        .unwrap()
        .push_back((msg_id, blob));
    Ok(())
}

fn poll_messages(engine: &ClientEngine) -> Result<Vec<PolledMessage>> {
    let json = engine.poll_messages();
    let parsed: Vec<PolledMessage> =
        serde_json::from_str(&json).context("decode polled messages")?;
    Ok(parsed)
}

fn decode_fixed_transport_cell(cell: &[u8]) -> Result<Vec<u8>> {
    if cell.len() < 4 {
        return Err(anyhow!("cell too short"));
    }
    let payload_len = u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]) as usize;
    if payload_len > cell.len() - 4 {
        return Err(anyhow!("cell payload length exceeds bounds"));
    }
    Ok(cell[4..4 + payload_len].to_vec())
}

#[test]
#[ignore]
fn realtime_user_to_user_single_message() -> Result<()> {
    if std::env::var("INTEGRATION_RUN").is_err() {
        return Ok(());
    }

    let root = repo_root()?;
    let work_dir = TempDir::new().context("create integration temp dir")?;
    let relay_port = reserve_port()?;
    let (relay_cert_path, relay_key_path, relay_ca_b64) = write_relay_cert_pair(work_dir.path())?;

    let mut relay_cmd = Command::new("go");
    relay_cmd
        .current_dir(root.join("relay-node"))
        .arg("run")
        .arg("./src/main.go")
        .env("RELAY_CERT_FILE", &relay_cert_path)
        .env("RELAY_KEY_FILE", &relay_key_path)
        .env("RELAY_ADDR", format!("127.0.0.1:{relay_port}"));
    let _relay = ManagedChild::spawn("relay", relay_cmd)?;
    wait_for_tcp(relay_port, Duration::from_secs(90))?;

    let mut env_guard = EnvGuard::default();
    env_guard.set("RELAY_CA_B64", relay_ca_b64);
    env_guard.remove("RELAY_HMAC_KEY");
    env_guard.remove("RELAY_ALLOW_INSECURE");
    env_guard.remove("RELAY_PINNED_CERT_HASH");

    let relay_url = format!("https://localhost:{relay_port}");
    let alice = ClientEngine::new();
    let bob = ClientEngine::new();

    let alice_id = setup_user_engine(&alice, &relay_url);
    let bob_id = setup_user_engine(&bob, &relay_url);
    pair_sessions(&alice, &bob, &alice_id, &bob_id);

    let payload = "hello bob in real-time";
    let started = Instant::now();
    let send_rc = send_payload_with_retry(&alice, &bob_id, payload, Duration::from_secs(3));
    assert_eq!(send_rc, 0, "alice send failed with code {send_rc}");

    let mut delivered = None;
    while started.elapsed() < Duration::from_secs(5) {
        if fetch_one_pending_into_engine(&bob, &bob_id).is_ok() {
            let polled = poll_messages(&bob)?;
            if let Some(msg) = polled
                .iter()
                .find(|m| m.msg_type == "text" && m.sender == alice_id && m.content == payload)
            {
                delivered = Some(msg.content.clone());
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(
        delivered.as_deref(),
        Some(payload),
        "bob did not receive payload"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "delivery exceeded realtime threshold"
    );

    let second_fetch = fetch_one_pending_into_engine(&bob, &bob_id);
    assert!(
        second_fetch.is_err(),
        "mailbox should be empty after message was fetched once"
    );

    Ok(())
}

#[test]
#[ignore]
fn realtime_user_to_user_burst_delivery() -> Result<()> {
    if std::env::var("INTEGRATION_RUN").is_err() {
        return Ok(());
    }

    let root = repo_root()?;
    let work_dir = TempDir::new().context("create integration temp dir")?;
    let relay_port = reserve_port()?;
    let (relay_cert_path, relay_key_path, relay_ca_b64) = write_relay_cert_pair(work_dir.path())?;

    let mut relay_cmd = Command::new("go");
    relay_cmd
        .current_dir(root.join("relay-node"))
        .arg("run")
        .arg("./src/main.go")
        .env("RELAY_CERT_FILE", &relay_cert_path)
        .env("RELAY_KEY_FILE", &relay_key_path)
        .env("RELAY_ADDR", format!("127.0.0.1:{relay_port}"));
    let _relay = ManagedChild::spawn("relay", relay_cmd)?;
    wait_for_tcp(relay_port, Duration::from_secs(90))?;

    let mut env_guard = EnvGuard::default();
    env_guard.set("RELAY_CA_B64", relay_ca_b64);
    env_guard.remove("RELAY_HMAC_KEY");
    env_guard.remove("RELAY_ALLOW_INSECURE");
    env_guard.remove("RELAY_PINNED_CERT_HASH");

    let relay_url = format!("https://localhost:{relay_port}");
    let alice = ClientEngine::new();
    let bob = ClientEngine::new();

    let alice_id = setup_user_engine(&alice, &relay_url);
    let bob_id = setup_user_engine(&bob, &relay_url);
    pair_sessions(&alice, &bob, &alice_id, &bob_id);

    let sent = vec!["msg-1", "msg-2", "msg-3"];
    for msg in &sent {
        let rc = send_payload_with_retry(&alice, &bob_id, msg, Duration::from_secs(3));
        assert_eq!(rc, 0, "alice send failed for {msg} with code {rc}");
    }

    let started = Instant::now();
    let mut received: Vec<String> = Vec::new();
    while started.elapsed() < Duration::from_secs(8) && received.len() < sent.len() {
        if fetch_one_pending_into_engine(&bob, &bob_id).is_ok() {
            let polled = poll_messages(&bob)?;
            for msg in polled {
                if msg.msg_type == "text" && msg.sender == alice_id {
                    received.push(msg.content);
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(
        received.len(),
        sent.len(),
        "did not receive all burst messages"
    );
    assert_eq!(received, sent, "burst delivery order changed");

    Ok(())
}

#[test]
#[ignore]
fn realtime_transport_fixed_cells_preserve_shape_and_decode() -> Result<()> {
    if std::env::var("INTEGRATION_RUN").is_err() {
        return Ok(());
    }

    let root = repo_root()?;
    let work_dir = TempDir::new().context("create integration temp dir")?;
    let relay_port = reserve_port()?;
    let (relay_cert_path, relay_key_path, relay_ca_b64) = write_relay_cert_pair(work_dir.path())?;

    let mut relay_cmd = Command::new("go");
    relay_cmd
        .current_dir(root.join("relay-node"))
        .arg("run")
        .arg("./src/main.go")
        .env("RELAY_CERT_FILE", &relay_cert_path)
        .env("RELAY_KEY_FILE", &relay_key_path)
        .env("RELAY_ADDR", format!("127.0.0.1:{relay_port}"))
        .env("RELAY_FIXED_CELL_BYTES", "256");
    let _relay = ManagedChild::spawn("relay", relay_cmd)?;
    wait_for_tcp(relay_port, Duration::from_secs(90))?;

    let mut env_guard = EnvGuard::default();
    env_guard.set("RELAY_CA_B64", relay_ca_b64);
    env_guard.remove("RELAY_HMAC_KEY");
    env_guard.remove("RELAY_ALLOW_INSECURE");
    env_guard.remove("RELAY_PINNED_CERT_HASH");

    let original_shaping = config::get_traffic_shaping();
    config::set_traffic_shaping(TrafficShapingConfig {
        pad_to: 256,
        min_delay_ms: original_shaping.min_delay_ms,
        max_delay_ms: original_shaping.max_delay_ms,
    });

    let result = (|| -> Result<()> {
        let relay_url = format!("https://localhost:{relay_port}");
        let relay_client = RelayClient::new(&relay_url);
        let runtime = tokio::runtime::Runtime::new().context("create tokio runtime")?;

        let short_payload = b"short-message".to_vec();
        let long_payload = vec![b'x'; 128];
        runtime.block_on(relay_client.send_blob("shape-short", "bob", &short_payload))?;
        runtime.block_on(relay_client.send_blob("shape-long", "bob", &long_payload))?;

        let http_client = build_https_client_with_cert(&relay_cert_path)?;
        let short_raw = http_client
            .get(format!("{relay_url}/fetch?id=shape-short"))
            .send()
            .context("fetch shape-short")?;
        if !short_raw.status().is_success() {
            return Err(anyhow!("shape-short fetch failed: {}", short_raw.status()));
        }
        let short_cell = short_raw
            .bytes()
            .context("read shape-short response bytes")?
            .to_vec();

        let long_raw = http_client
            .get(format!("{relay_url}/fetch?id=shape-long"))
            .send()
            .context("fetch shape-long")?;
        if !long_raw.status().is_success() {
            return Err(anyhow!("shape-long fetch failed: {}", long_raw.status()));
        }
        let long_cell = long_raw
            .bytes()
            .context("read shape-long response bytes")?
            .to_vec();

        assert_eq!(short_cell.len(), 256, "short payload cell size drifted");
        assert_eq!(long_cell.len(), 256, "long payload cell size drifted");

        let decoded_short = decode_fixed_transport_cell(&short_cell)?;
        let decoded_long = decode_fixed_transport_cell(&long_cell)?;
        assert_eq!(
            decoded_short, short_payload,
            "short payload decode mismatch"
        );
        assert_eq!(decoded_long, long_payload, "long payload decode mismatch");

        let roundtrip_payload = b"decode-roundtrip-message".to_vec();
        runtime.block_on(relay_client.send_blob("shape-roundtrip", "bob", &roundtrip_payload))?;
        let recovered = runtime
            .block_on(relay_client.fetch_blob("shape-roundtrip"))
            .context("relay client fixed-cell decode fetch")?;
        assert_eq!(
            recovered, roundtrip_payload,
            "relay client decode path regressed"
        );

        Ok(())
    })();

    config::set_traffic_shaping(original_shaping);
    result
}

#[test]
#[ignore]
fn realtime_user_to_user_soak_with_reconnect_chaos() -> Result<()> {
    if std::env::var("INTEGRATION_RUN").is_err() {
        return Ok(());
    }

    let root = repo_root()?;
    let work_dir = TempDir::new().context("create integration temp dir")?;
    let relay_port = reserve_port()?;
    let (relay_cert_path, relay_key_path, relay_ca_b64) = write_relay_cert_pair(work_dir.path())?;

    let thresholds = ReliabilityThresholds {
        cycles: env_or_default_usize("RELIABILITY_SOAK_CYCLES", 5),
        messages_per_cycle: env_or_default_usize("RELIABILITY_SOAK_MESSAGES_PER_CYCLE", 24),
        relay_down_ms: env_or_default_u64("RELIABILITY_RELAY_DOWN_MS", 900),
        delivery_timeout_ms: env_or_default_u64("RELIABILITY_DELIVERY_TIMEOUT_MS", 6000),
        reconnect_timeout_ms: env_or_default_u64("RELIABILITY_RECONNECT_TIMEOUT_MS", 15000),
        min_delivery_ratio: env_or_default_f64("RELIABILITY_MIN_DELIVERY_RATIO", 0.99),
        max_reconnect_latency_ms: env_or_default_u64("RELIABILITY_MAX_RECONNECT_LATENCY_MS", 9000)
            as u128,
        max_runtime_growth_bytes: env_or_default_usize(
            "RELIABILITY_MAX_RUNTIME_GROWTH_BYTES",
            192 * 1024,
        ),
    };

    let artifact_path = std::env::var("RELIABILITY_ARTIFACT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("itest/artifacts/reliability-soak.json"));

    let _relay = spawn_relay(&root, &relay_cert_path, &relay_key_path, relay_port)?;
    wait_for_tcp(relay_port, Duration::from_secs(90))?;

    let mut env_guard = EnvGuard::default();
    env_guard.set("RELAY_CA_B64", relay_ca_b64);
    env_guard.remove("RELAY_HMAC_KEY");
    env_guard.remove("RELAY_ALLOW_INSECURE");
    env_guard.remove("RELAY_PINNED_CERT_HASH");

    let relay_url = format!("https://localhost:{relay_port}");
    let alice = ClientEngine::new();
    let bob = ClientEngine::new();

    let alice_id = setup_user_engine(&alice, &relay_url);
    let bob_id = setup_user_engine(&bob, &relay_url);
    pair_sessions(&alice, &bob, &alice_id, &bob_id);

    clear_runtime_buffers(&alice);
    clear_runtime_buffers(&bob);

    let test_started = Instant::now();
    let mut metrics = ReliabilityMetrics::default();
    metrics.baseline_runtime_bytes = runtime_bytes(&alice) + runtime_bytes(&bob);
    metrics.max_runtime_bytes_after_cleanup = metrics.baseline_runtime_bytes;

    for cycle in 0..thresholds.cycles {
        let _ = drain_pending_mailbox(&bob, &bob_id, 64)?;
        clear_runtime_buffers(&alice);
        clear_runtime_buffers(&bob);

        for msg_index in 0..thresholds.messages_per_cycle {
            let payload = format!("soak-{cycle:03}-{msg_index:04}");
            metrics.total_send_attempts += 1;

            let rc = send_payload_with_retry(&alice, &bob_id, &payload, Duration::from_secs(3));
            if rc != 0 {
                metrics.send_failures += 1;
                continue;
            }
            metrics.successful_sends += 1;
            metrics.delivery_eligible_sends += 1;

            match wait_for_expected_message(
                &bob,
                &bob_id,
                &alice_id,
                &payload,
                Duration::from_millis(thresholds.delivery_timeout_ms),
                &mut metrics,
            ) {
                Ok(latency) => {
                    metrics.delivery_successes += 1;
                    metrics.delivery_latency_ms.push(latency.as_millis());
                }
                Err(_) => {
                    metrics.delivery_misses += 1;
                }
            }
        }

        clear_runtime_buffers(&alice);
        clear_runtime_buffers(&bob);
        let runtime_after_cleanup = runtime_bytes(&alice) + runtime_bytes(&bob);
        metrics.max_runtime_bytes_after_cleanup = metrics
            .max_runtime_bytes_after_cleanup
            .max(runtime_after_cleanup);

        metrics.reconnect_events += 1;
        let offline_port = reserve_port()?;
        let offline_url = format!("https://localhost:{offline_port}");
        set_relay_client(&alice, &offline_url);
        set_relay_client(&bob, &offline_url);
        thread::sleep(Duration::from_millis(thresholds.relay_down_ms));

        metrics.fetch_attempts += 1;
        if fetch_one_pending_into_engine(&bob, &bob_id).is_err() {
            metrics.chaos_outage_failures += 1;
        } else {
            metrics.fetch_successes += 1;
        }

        set_relay_client(&alice, &relay_url);
        set_relay_client(&bob, &relay_url);

        let reconnect_started = Instant::now();
        let reconnect_deadline = Duration::from_millis(thresholds.reconnect_timeout_ms);
        let reconnect_payload = format!("reconnect-probe-{cycle:03}");
        let mut reconnected = false;

        while reconnect_started.elapsed() < reconnect_deadline {
            metrics.total_send_attempts += 1;
            let rc = alice.send_payload(
                &bob_id,
                &reconnect_payload,
                "text",
                None,
                false,
                false,
                None,
            );

            if rc != 0 {
                metrics.send_failures += 1;
                thread::sleep(Duration::from_millis(80));
                continue;
            }
            metrics.successful_sends += 1;
            metrics.delivery_eligible_sends += 1;

            match wait_for_expected_message(
                &bob,
                &bob_id,
                &alice_id,
                &reconnect_payload,
                Duration::from_millis(thresholds.delivery_timeout_ms),
                &mut metrics,
            ) {
                Ok(delivery_latency) => {
                    metrics.delivery_successes += 1;
                    metrics
                        .delivery_latency_ms
                        .push(delivery_latency.as_millis());
                    metrics
                        .reconnect_latency_ms
                        .push(reconnect_started.elapsed().as_millis());
                    reconnected = true;
                    break;
                }
                Err(_) => {
                    metrics.delivery_misses += 1;
                }
            }
        }

        if !reconnected {
            metrics.reconnect_timeouts += 1;
        }

        let _ = drain_pending_mailbox(&bob, &bob_id, 64)?;
        clear_runtime_buffers(&alice);
        clear_runtime_buffers(&bob);
    }

    metrics.elapsed_ms = test_started.elapsed().as_millis();
    metrics.reconnect_p95_ms = percentile_u128(&metrics.reconnect_latency_ms, 0.95);
    metrics.delivery_ratio = if metrics.delivery_eligible_sends == 0 {
        0.0
    } else {
        metrics.delivery_successes as f64 / metrics.delivery_eligible_sends as f64
    };
    metrics.error_rate = if metrics.total_send_attempts == 0 {
        0.0
    } else {
        (metrics.send_failures + metrics.delivery_misses + metrics.reconnect_timeouts) as f64
            / metrics.total_send_attempts as f64
    };

    let mut violations = Vec::new();
    if metrics.delivery_ratio < thresholds.min_delivery_ratio {
        violations.push(format!(
            "delivery ratio below threshold: {:.4} < {:.4}",
            metrics.delivery_ratio, thresholds.min_delivery_ratio
        ));
    }
    if metrics.reconnect_events == 0 {
        violations.push("no reconnect events were executed".to_string());
    }
    if metrics.reconnect_timeouts > 0 {
        violations.push(format!(
            "reconnect timed out {} times",
            metrics.reconnect_timeouts
        ));
    }
    if !metrics.reconnect_latency_ms.is_empty()
        && metrics.reconnect_p95_ms > thresholds.max_reconnect_latency_ms
    {
        violations.push(format!(
            "reconnect p95 latency too high: {}ms > {}ms",
            metrics.reconnect_p95_ms, thresholds.max_reconnect_latency_ms
        ));
    }
    let runtime_limit = metrics.baseline_runtime_bytes + thresholds.max_runtime_growth_bytes;
    if metrics.max_runtime_bytes_after_cleanup > runtime_limit {
        violations.push(format!(
            "runtime memory growth exceeded budget: {} > {} bytes",
            metrics.max_runtime_bytes_after_cleanup, runtime_limit
        ));
    }
    if metrics.chaos_outage_failures == 0 {
        violations.push(
            "chaos outage did not trigger any send failures; reconnect path was not exercised"
                .to_string(),
        );
    }

    let checks_passed = violations.is_empty();
    let report = ReliabilityReport {
        thresholds: thresholds.clone(),
        metrics: metrics.clone(),
        checks_passed,
        violations: violations.clone(),
    };
    write_reliability_report(&artifact_path, &report)?;

    assert!(
        checks_passed,
        "reliability thresholds violated; report written to {}: {:?}",
        artifact_path.display(),
        violations
    );

    Ok(())
}
