use anyhow::{anyhow, Context, Result};
use base64::Engine;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use redoor_client::api::scripted_loopback_custom;
use std::collections::HashMap;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    // reqwest/rustls expects pinned roots to carry CA basic constraints.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn full_roundtrip_hmac() -> Result<()> {
    if std::env::var("INTEGRATION_RUN").is_err() {
        return Ok(());
    }

    let root = repo_root()?;
    let work_dir = TempDir::new().context("create integration temp dir")?;

    let relay_port = reserve_port()?;
    let blockchain_tcp_port = reserve_port()?;
    let blockchain_http_port = reserve_port()?;

    let hmac_key_b64 = base64::engine::general_purpose::STANDARD.encode(b"itest-relay-hmac-0001");
    let (relay_cert_path, relay_key_path, relay_ca_b64) = write_relay_cert_pair(work_dir.path())?;

    let mut relay_cmd = Command::new("go");
    relay_cmd
        .current_dir(root.join("relay-node"))
        .arg("run")
        .arg("./src/main.go")
        .env("RELAY_HMAC_KEY", &hmac_key_b64)
        .env("RELAY_CERT_FILE", &relay_cert_path)
        .env("RELAY_KEY_FILE", &relay_key_path)
        .env("RELAY_ADDR", format!("127.0.0.1:{relay_port}"));
    let _relay = ManagedChild::spawn("relay", relay_cmd)?;
    wait_for_tcp(relay_port, Duration::from_secs(90))?;

    let mut blockchain_cmd = Command::new("cargo");
    blockchain_cmd
        .current_dir(work_dir.path())
        .arg("run")
        .arg("--manifest-path")
        .arg(root.join("blockchain-node/Cargo.toml"))
        .env(
            "BLOCKCHAIN_ADDR",
            format!("127.0.0.1:{blockchain_tcp_port}"),
        )
        .env(
            "BLOCKCHAIN_HTTP_ADDR",
            format!("127.0.0.1:{blockchain_http_port}"),
        );
    let _blockchain = ManagedChild::spawn("blockchain", blockchain_cmd)?;
    wait_for_tcp(blockchain_http_port, Duration::from_secs(120))?;

    let mut env_guard = EnvGuard::default();
    env_guard.set("RELAY_HMAC_KEY", hmac_key_b64);
    env_guard.set("RELAY_CA_B64", relay_ca_b64);
    env_guard.remove("RELAY_ALLOW_INSECURE");
    env_guard.remove("RELAY_PINNED_CERT_HASH");

    let relay_url = format!("https://localhost:{relay_port}");
    let blockchain_url = format!("http://127.0.0.1:{blockchain_http_port}");

    scripted_loopback_custom(&relay_url, &blockchain_url, "hello-itest", false, false)
        .await
        .context("scripted loopback flow failed")?;

    Ok(())
}
