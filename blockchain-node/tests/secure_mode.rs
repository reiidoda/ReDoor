use redoor_blockchain::config::NodeConfig;
use std::collections::HashMap;

fn env_map(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn secure_mode_rejects_missing_tls_material() {
    let vars = env_map(&[
        ("BLOCKCHAIN_ADDR", "0.0.0.0:9000"),
        ("BLOCKCHAIN_HTTP_ADDR", "127.0.0.1:9444"),
        ("ADMIN_TOKEN", "admin-token"),
    ]);
    let err = NodeConfig::from_map(&vars).expect_err("expected secure mode misconfiguration");
    assert!(err.contains("BLOCKCHAIN_CERT_FILE and BLOCKCHAIN_KEY_FILE"));
}

#[test]
fn secure_mode_rejects_non_loopback_http_bind() {
    let vars = env_map(&[
        ("BLOCKCHAIN_SECURE_MODE", "1"),
        ("BLOCKCHAIN_ADDR", "0.0.0.0:9000"),
        ("BLOCKCHAIN_HTTP_ADDR", "0.0.0.0:9444"),
        ("BLOCKCHAIN_CERT_FILE", "cert.pem"),
        ("BLOCKCHAIN_KEY_FILE", "key.pem"),
        ("ADMIN_TOKEN", "admin-token"),
    ]);
    let err = NodeConfig::from_map(&vars).expect_err("expected non-loopback http rejection");
    assert!(err.contains("BLOCKCHAIN_HTTP_ADDR"));
    assert!(err.contains("loopback"));
}

#[test]
fn secure_mode_rejects_missing_admin_token() {
    let vars = env_map(&[
        ("BLOCKCHAIN_SECURE_MODE", "1"),
        ("BLOCKCHAIN_ADDR", "0.0.0.0:9000"),
        ("BLOCKCHAIN_HTTP_ADDR", "127.0.0.1:9444"),
        ("BLOCKCHAIN_CERT_FILE", "cert.pem"),
        ("BLOCKCHAIN_KEY_FILE", "key.pem"),
    ]);
    let err = NodeConfig::from_map(&vars).expect_err("expected missing admin token rejection");
    assert!(err.contains("ADMIN_TOKEN"));
}

#[test]
fn plaintext_non_loopback_requires_explicit_override() {
    let vars = env_map(&[
        ("BLOCKCHAIN_SECURE_MODE", "0"),
        ("BLOCKCHAIN_ADDR", "0.0.0.0:9000"),
        ("BLOCKCHAIN_HTTP_ADDR", "127.0.0.1:9444"),
    ]);
    let err = NodeConfig::from_map(&vars).expect_err("expected plaintext rejection");
    assert!(err.contains("BLOCKCHAIN_ALLOW_PLAINTEXT_NONLOCAL"));
}

#[test]
fn plaintext_non_loopback_override_allows_startup() {
    let vars = env_map(&[
        ("BLOCKCHAIN_SECURE_MODE", "0"),
        ("BLOCKCHAIN_ALLOW_PLAINTEXT_NONLOCAL", "1"),
        ("BLOCKCHAIN_ADDR", "0.0.0.0:9000"),
        ("BLOCKCHAIN_HTTP_ADDR", "127.0.0.1:9444"),
    ]);
    let config = NodeConfig::from_map(&vars).expect("override should permit plaintext bind");
    assert!(!config.secure_mode);
}
