use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;

const DEFAULT_TCP_ADDR: &str = "127.0.0.1:9000";
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:9444";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub tcp_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub admin_token: Option<String>,
    pub secure_mode: bool,
}

impl NodeConfig {
    pub fn from_env() -> Result<Self, String> {
        let vars: HashMap<String, String> = env::vars().collect();
        Self::from_map(&vars)
    }

    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self, String> {
        let tcp_addr = parse_socket_addr(
            vars.get("BLOCKCHAIN_ADDR")
                .map(String::as_str)
                .unwrap_or(DEFAULT_TCP_ADDR),
            "BLOCKCHAIN_ADDR",
        )?;
        let http_addr = parse_socket_addr(
            vars.get("BLOCKCHAIN_HTTP_ADDR")
                .map(String::as_str)
                .unwrap_or(DEFAULT_HTTP_ADDR),
            "BLOCKCHAIN_HTTP_ADDR",
        )?;

        let cert_file = opt_non_empty(vars, "BLOCKCHAIN_CERT_FILE");
        let key_file = opt_non_empty(vars, "BLOCKCHAIN_KEY_FILE");
        let admin_token = opt_non_empty(vars, "ADMIN_TOKEN");

        if cert_file.is_some() ^ key_file.is_some() {
            return Err(
                "BLOCKCHAIN_CERT_FILE and BLOCKCHAIN_KEY_FILE must be set together".to_string(),
            );
        }

        let require_tls = parse_bool_env(
            vars.get("BLOCKCHAIN_REQUIRE_TLS").map(String::as_str),
            "BLOCKCHAIN_REQUIRE_TLS",
        )?
        .unwrap_or(false);
        let explicit_secure_mode = parse_bool_env(
            vars.get("BLOCKCHAIN_SECURE_MODE").map(String::as_str),
            "BLOCKCHAIN_SECURE_MODE",
        )?;
        let allow_plaintext_nonlocal = parse_bool_env(
            vars.get("BLOCKCHAIN_ALLOW_PLAINTEXT_NONLOCAL")
                .map(String::as_str),
            "BLOCKCHAIN_ALLOW_PLAINTEXT_NONLOCAL",
        )?
        .unwrap_or(false);

        let non_loopback_bind = !tcp_addr.ip().is_loopback() || !http_addr.ip().is_loopback();
        let secure_mode = require_tls || explicit_secure_mode.unwrap_or(non_loopback_bind);

        if secure_mode {
            if cert_file.is_none() || key_file.is_none() {
                return Err(
                    "secure mode requires BLOCKCHAIN_CERT_FILE and BLOCKCHAIN_KEY_FILE".to_string(),
                );
            }
            if !http_addr.ip().is_loopback() {
                return Err(format!(
                    "secure mode requires BLOCKCHAIN_HTTP_ADDR to bind loopback; got {}",
                    http_addr
                ));
            }
            if admin_token.is_none() {
                return Err(
                    "secure mode requires ADMIN_TOKEN for admin endpoint protection".to_string(),
                );
            }
        } else if non_loopback_bind && !allow_plaintext_nonlocal {
            return Err(
                "plaintext mode on non-loopback addresses is blocked. Set BLOCKCHAIN_SECURE_MODE=1 \
                 (recommended) or BLOCKCHAIN_ALLOW_PLAINTEXT_NONLOCAL=1 for controlled testing."
                    .to_string(),
            );
        }

        Ok(Self {
            tcp_addr,
            http_addr,
            cert_file,
            key_file,
            admin_token,
            secure_mode,
        })
    }
}

fn parse_socket_addr(value: &str, name: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("{name} must be a valid socket address, got `{value}`"))
}

fn opt_non_empty(vars: &HashMap<String, String>, key: &str) -> Option<String> {
    vars.get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_bool_env(value: Option<&str>, name: &str) -> Result<Option<bool>, String> {
    let raw = match value {
        Some(v) => v.trim().to_ascii_lowercase(),
        None => return Ok(None),
    };
    match raw.as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(format!(
            "{name} must be one of 1/0/true/false/yes/no/on/off, got `{}`",
            raw
        )),
    }
}
