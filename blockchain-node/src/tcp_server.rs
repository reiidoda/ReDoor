use crate::crypto;
use crate::dto::{SignedBlockRequest, Transaction};
use crate::ledger;
use crate::ledger::chain::Blockchain;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pqcrypto_dilithium::dilithium2::{DetachedSignature, PublicKey as PQPublicKey};
use pqcrypto_traits::sign::{DetachedSignature as PQDetachedTrait, PublicKey as PQPubTrait};
use rustls::{pki_types::CertificateDer, pki_types::PrivateKeyDer, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> AsyncReadWrite for T {}

fn redact_token_for_log(value: &str) -> String {
    if value.len() < 16 {
        return value.to_string();
    }
    let digest = blake3::hash(value.as_bytes());
    let digest_hex = hex::encode(digest.as_bytes());
    format!("<redacted:{}>", &digest_hex[..12])
}

fn redact_hex_for_log(value: &str) -> String {
    if let Ok(decoded) = hex::decode(value) {
        let digest = blake3::hash(&decoded);
        let digest_hex = hex::encode(digest.as_bytes());
        return format!("<redacted:{}>", &digest_hex[..12]);
    }
    redact_token_for_log(value)
}

pub fn make_tls_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.map(|c| c.into()))
        .collect::<Result<_, _>>()?;

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|r| r.map(|k| k.into()))
        .collect::<Result<_, _>>()?;
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| "no private key found".to_string())?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(std::sync::Arc::new(config)))
}

pub async fn handle_connection(
    socket: tokio::net::TcpStream,
    blockchain: Arc<Mutex<Blockchain>>,
    tls_acceptor: Option<TlsAcceptor>,
) {
    let mut stream: Box<dyn AsyncReadWrite + Unpin + Send> = if let Some(acceptor) = tls_acceptor {
        match acceptor.accept(socket).await {
            Ok(s) => Box::new(s),
            Err(e) => {
                eprintln!("TLS handshake failed: {:?}", e);
                return;
            }
        }
    } else {
        Box::new(socket)
    };

    let mut buf = vec![0u8; 8192];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n == 0 => return,
        Ok(n) => n,
        Err(e) => {
            eprintln!("failed to read from socket; err = {:?}", e);
            return;
        }
    };

    let body = &buf[0..n];
    let tx: Result<Transaction, _> = serde_json::from_slice(body);

    if let Ok(transaction) = tx {
        println!(
            "Received transaction signer={} receiver={} timestamp={}",
            redact_hex_for_log(&transaction.signer_id),
            redact_token_for_log(&transaction.receiver_commitment),
            transaction.timestamp
        );

        let signer_pubkey_bytes = match hex::decode(&transaction.signer_id) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = stream.write_all(b"Invalid signer_id hex format").await;
                return;
            }
        };
        let signature_bytes = match hex::decode(&transaction.signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = stream.write_all(b"Invalid signature hex").await;
                return;
            }
        };
        let message_hash_bytes = match hex::decode(&transaction.message_hash) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = stream.write_all(b"Invalid message_hash hex").await;
                return;
            }
        };

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&transaction.timestamp.to_be_bytes());
        signed_data.extend_from_slice(&signer_pubkey_bytes);
        signed_data.extend_from_slice(transaction.receiver_commitment.as_bytes());
        signed_data.extend_from_slice(&message_hash_bytes);

        if !crypto::ed25519::verify_signature(&signer_pubkey_bytes, &signed_data, &signature_bytes)
        {
            println!(
                "ED25519 signature verification failed for signer={}",
                redact_hex_for_log(&transaction.signer_id)
            );
            let _ = stream.write_all(b"Invalid signature").await;
            return;
        }

        if let (Some(pq_pub_b64), Some(pq_sig_b64)) = (
            transaction.pq_pub_b64.as_ref(),
            transaction.pq_sig_b64.as_ref(),
        ) {
            let pq_pub = match B64
                .decode(pq_pub_b64)
                .ok()
                .and_then(|bytes| PQPublicKey::from_bytes(&bytes).ok())
            {
                Some(pk) => pk,
                None => {
                    eprintln!("Invalid PQ pubkey format");
                    let _ = stream.write_all(b"Invalid PQ pubkey format").await;
                    return;
                }
            };
            let pq_sig = match B64.decode(pq_sig_b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("Invalid PQ signature format: {}", e);
                    let _ = stream.write_all(b"Invalid PQ signature format").await;
                    return;
                }
            };
            let det_sig = match DetachedSignature::from_bytes(&pq_sig) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Invalid PQ signature");
                    let _ = stream.write_all(b"Invalid PQ signature").await;
                    return;
                }
            };
            if pqcrypto_dilithium::dilithium2::verify_detached_signature(
                &det_sig,
                &signed_data,
                &pq_pub,
            )
            .is_err()
            {
                eprintln!("PQ signature verification failed");
                let _ = stream.write_all(b"Invalid PQ signature").await;
                return;
            }
        }

        println!("Signature verified successfully.");
        {
            let mut chain = blockchain.lock().await;
            chain.add_block(message_hash_bytes);
            drop(chain);
        }
        let _ = stream.write_all(b"Transaction accepted").await;
        return;
    }

    let sb: Result<SignedBlockRequest, _> = serde_json::from_slice(body);
    if let Ok(signed_req) = sb {
        println!(
            "Received signed block submission index={} signer={} hash={}",
            signed_req.index,
            redact_hex_for_log(&signed_req.signer_pub_hex),
            redact_hex_for_log(&signed_req.hash_hex)
        );
        let previous_hash_bytes = match hex::decode(&signed_req.previous_hash_hex) {
            Ok(b) => b,
            Err(_) => {
                let _ = stream.write_all(b"Invalid previous_hash_hex").await;
                return;
            }
        };
        let hash_bytes = match hex::decode(&signed_req.hash_hex) {
            Ok(b) => b,
            Err(_) => {
                let _ = stream.write_all(b"Invalid hash_hex").await;
                return;
            }
        };
        let data_bytes = match B64.decode(&signed_req.data_b64) {
            Ok(b) => b,
            Err(_) => {
                let _ = stream.write_all(b"Invalid data_b64").await;
                return;
            }
        };
        let sig_bytes = match hex::decode(&signed_req.signature_hex) {
            Ok(b) => b,
            Err(_) => {
                let _ = stream.write_all(b"Invalid signature_hex").await;
                return;
            }
        };
        let signer_pub = match hex::decode(&signed_req.signer_pub_hex) {
            Ok(b) => b,
            Err(_) => {
                let _ = stream.write_all(b"Invalid signer_pub_hex").await;
                return;
            }
        };

        if previous_hash_bytes.len() != 32 || hash_bytes.len() != 32 || sig_bytes.len() != 64 {
            let _ = stream.write_all(b"Invalid field lengths").await;
            return;
        }
        let mut prev_arr = [0u8; 32];
        prev_arr.copy_from_slice(&previous_hash_bytes);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash_bytes);

        let block = ledger::block::Block {
            version: 1,
            index: signed_req.index,
            timestamp: signed_req.timestamp,
            previous_hash: prev_arr,
            hash: hash_arr,
            data: data_bytes,
            signature: sig_bytes,
            signer_pub: signer_pub.clone(),
        };

        let mut chain = blockchain.lock().await;
        let result = chain.add_signed_block(block);
        drop(chain);
        match result {
            Ok(()) => {
                let _ = stream.write_all(b"Signed block appended").await;
            }
            Err(e) => {
                let _ = stream
                    .write_all(format!("Signed block rejected: {}", e).as_bytes())
                    .await;
            }
        }
        return;
    }
    let _ = stream
        .write_all(b"Invalid request format: expected Transaction or SignedBlockRequest")
        .await;
}

#[cfg(test)]
mod tests {
    use super::{redact_hex_for_log, redact_token_for_log};

    #[test]
    fn redact_hex_for_log_masks_raw_values() {
        let raw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let redacted = redact_hex_for_log(raw);
        assert!(redacted.starts_with("<redacted:"));
        assert!(!redacted.contains(raw));
    }

    #[test]
    fn redact_token_for_log_keeps_short_values() {
        let short = "peer-1";
        assert_eq!(redact_token_for_log(short), short);
    }
}
