use crate::crypto::ed25519;
use anyhow::Result;
use base64::Engine;
use once_cell::sync::OnceCell;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_dilithium::dilithium2::{detached_sign, keypair, DetachedSignature, SecretKey};
use pqcrypto_traits::sign::DetachedSignature as PQDetachedSigTrait;
use pqcrypto_traits::sign::PublicKey;
use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    message_hash: String,  // Hex encoded
    sender_pubkey: String, // Hex encoded public key, to verify the signature
    signature: String,     // Hex encoded signature of (message_hash + timestamp)
    timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_pub_b64: Option<String>, // Optional post-quantum pubkey (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pq_sig_b64: Option<String>, // Optional post-quantum detached signature (base64)
}

// Verify block hashes and signatures
#[derive(Clone)]
pub struct BlockchainClient {
    pub base_url: String, // Changed from node_address to base_url to match engine usage
    tls: Option<TlsConnector>,
    server_name: Option<ServerName<'static>>,
}

impl BlockchainClient {
    pub fn new(base_url: String) -> Self {
        let (tls, server_name) = build_tls_connector();
        Self {
            base_url,
            tls,
            server_name,
        }
    }

    pub async fn submit_transaction(
        &self,
        sender_keypair: &ed25519::IdentityKey,
        message_hash: &[u8],
    ) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Prepare data to sign: message_hash + timestamp
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(message_hash);
        data_to_sign.extend_from_slice(&timestamp.to_le_bytes());

        // 2. Sign the data
        let signature = sender_keypair.sign(&data_to_sign);

        // Optional PQ signature (Dilithium2)
        let (pq_pub_b64, pq_sig_b64) = maybe_pq_sign(&data_to_sign)?;

        // 3. Create Transaction struct
        let tx = Transaction {
            message_hash: hex::encode(message_hash),
            sender_pubkey: hex::encode(sender_keypair.public_key_bytes()),
            signature: hex::encode(signature),
            timestamp,
            pq_pub_b64,
            pq_sig_b64,
        };

        // 4. Serialize and send to Blockchain Node
        let serialized_tx = serde_json::to_vec(&tx)?;

        // Note: This raw TCP/TLS logic might conflict with the HTTP-based logic in orchestrator.rs
        // orchestrator.rs uses reqwest to POST to /tx.
        // This method seems to be a legacy or alternative raw socket implementation.
        // We will keep it for now but ensure the struct fields are compatible.

        if let Some(tls) = &self.tls {
            let sn = self
                .server_name
                .clone()
                .ok_or_else(|| anyhow::anyhow!("TLS server name not configured"))?;
            // Assuming base_url contains host:port for TCP connection here, which might be fragile if it's an HTTP URL
            // For now, we assume base_url is just "host:port" for this method, or we parse it.
            // But orchestrator uses it as HTTP base.
            // Let's try to parse host:port from base_url if it has http/https prefix.
            let addr = self
                .base_url
                .trim_start_matches("http://")
                .trim_start_matches("https://");

            let tcp = TcpStream::connect(addr).await?;
            let mut stream: TlsStream<TcpStream> = tls.connect(sn, tcp).await?;
            stream.write_all(&serialized_tx).await?;
        } else {
            let addr = self
                .base_url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_all(&serialized_tx).await?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn verify_block(
        &self,
        block_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        // Stub for future light-client verification; unused for now
        let _ = (block_hash, signature, public_key);
        Ok(())
    }
}

fn is_insecure_allowed() -> bool {
    // This foot-gun is only available in debug builds.
    #[cfg(debug_assertions)]
    {
        return std::env::var("BLOCKCHAIN_ALLOW_INSECURE").ok() == Some("1".to_string());
    }
    #[cfg(not(debug_assertions))]
    {
        return false;
    }
}

fn build_tls_connector() -> (Option<TlsConnector>, Option<ServerName<'static>>) {
    // Optional: BLOCKCHAIN_CA_B64 (base64 DER) to pin a root.
    let ca_b64 = std::env::var("BLOCKCHAIN_CA_B64").ok();
    let allow_insecure = is_insecure_allowed();
    let server_name = std::env::var("BLOCKCHAIN_SNI")
        .ok()
        .and_then(|s| ServerName::try_from(s).ok());

    if allow_insecure {
        return (None, None);
    }

    let mut root_store = RootCertStore::empty();
    if let Some(ca) = ca_b64 {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(ca) {
            let cert: CertificateDer<'static> = CertificateDer::from(bytes);
            let _ = root_store.add_parsable_certificates([cert]);
        }
    } else {
        // Fallback to webpki roots for convenience
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (Some(Arc::new(config).into()), server_name)
}

// Returns (pub_b64, sig_b64) if PQ signing is enabled via env BLOCKCHAIN_PQ=1.
fn maybe_pq_sign(message: &[u8]) -> Result<(Option<String>, Option<String>)> {
    if std::env::var("BLOCKCHAIN_PQ").ok() != Some("1".to_string()) {
        return Ok((None, None));
    }

    let (pk, sk) = get_pq_keys();
    let sig: DetachedSignature = detached_sign(message, &sk);
    let pub_bytes: Vec<u8> = pk.as_bytes().to_vec();
    let sig_bytes: Vec<u8> = sig.as_bytes().to_vec();

    Ok((
        Some(base64::engine::general_purpose::STANDARD.encode(pub_bytes)),
        Some(base64::engine::general_purpose::STANDARD.encode(sig_bytes)),
    ))
}

fn get_pq_keys() -> (&'static dilithium2::PublicKey, &'static SecretKey) {
    static KEYS: OnceCell<(dilithium2::PublicKey, SecretKey)> = OnceCell::new();
    let tuple = KEYS.get_or_init(|| keypair());
    (&tuple.0, &tuple.1)
}
