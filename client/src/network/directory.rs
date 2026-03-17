#![allow(dead_code)]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct DirectoryClient {
    client: Client,
    base_url: String,
    trusted_signing_key: Option<VerifyingKey>,
}

#[derive(Serialize)]
struct PublishReq {
    username: String,
    public_key: String,
    signature: String,
    seq: u64,
    expires_at: u64,
}

#[derive(Serialize)]
struct PrekeyPublishReq {
    id: String,
    data_b64: String,
    ttl_secs: u64,
}

#[derive(Deserialize)]
struct ResolveResp {
    public_key: String,
    signature: String,
    key_id: String,
    issued_at: u64,
    seq: u64,
    expires_at: u64,
}

#[derive(Deserialize)]
struct PrekeyQueryResp {
    data_b64: String,
}

#[derive(Clone, Debug)]
pub struct DirectoryRecord {
    pub public_key: String,
    pub seq: u64,
    pub expires_at: u64,
}

impl DirectoryClient {
    pub fn new(base_url: &str) -> Self {
        let trusted_signing_key = crate::config::get_directory_signing_pubkey_hex()
            .and_then(|hex| parse_verifying_key_hex(&hex).ok());

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build directory http client"),
            base_url: base_url.to_string(),
            trusted_signing_key,
        }
    }

    pub async fn publish(
        &self,
        username: &str,
        public_key_hex: &str,
        signature_hex: &str,
        seq: u64,
        expires_at: u64,
    ) -> Result<()> {
        let req = PublishReq {
            username: username.to_string(),
            public_key: public_key_hex.to_string(),
            signature: signature_hex.to_string(),
            seq,
            expires_at,
        };

        let res = self
            .client
            .post(&format!("{}/publish", self.base_url))
            .json(&req)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow!("Failed to publish identity"));
        }
        Ok(())
    }

    pub async fn resolve(&self, username: &str) -> Result<String> {
        let record = self
            .resolve_record_optional(username)
            .await?
            .ok_or_else(|| anyhow!("Failed to resolve username"))?;
        Ok(record.public_key)
    }

    pub async fn resolve_record_optional(&self, username: &str) -> Result<Option<DirectoryRecord>> {
        let res = self
            .client
            .get(&format!("{}/resolve", self.base_url))
            .query(&[("username", username)])
            .send()
            .await?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            return Err(anyhow!("Failed to resolve username"));
        }

        let body: ResolveResp = res.json().await?;
        verify_resolve_response(username, &body, self.trusted_signing_key.as_ref())?;
        Ok(Some(DirectoryRecord {
            public_key: body.public_key,
            seq: body.seq,
            expires_at: body.expires_at,
        }))
    }

    pub async fn publish_prekey_bundle(
        &self,
        key_id: &str,
        blob: &[u8],
        ttl_secs: u64,
    ) -> Result<()> {
        let req = PrekeyPublishReq {
            id: key_id.to_string(),
            data_b64: B64.encode(blob),
            ttl_secs,
        };

        let res = self
            .client
            .post(&format!("{}/prekey/publish", self.base_url))
            .json(&req)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow!("Failed to publish prekey bundle"));
        }
        Ok(())
    }

    pub async fn fetch_prekey_bundle(&self, key_id: &str) -> Result<Vec<u8>> {
        let res = self
            .client
            .get(&format!("{}/prekey/query/{}", self.base_url, key_id))
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow!("Failed to fetch prekey bundle"));
        }

        let body: PrekeyQueryResp = res.json().await?;
        B64.decode(body.data_b64.as_bytes())
            .map_err(|e| anyhow!("Invalid prekey bundle encoding: {e}"))
    }
}

fn parse_verifying_key_hex(pubkey_hex: &str) -> Result<VerifyingKey> {
    let bytes =
        hex::decode(pubkey_hex).map_err(|_| anyhow!("invalid directory signing key hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("directory signing key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("invalid directory signing key format"))
}

fn verify_resolve_response(
    username: &str,
    response: &ResolveResp,
    trusted_signing_key: Option<&VerifyingKey>,
) -> Result<()> {
    let trusted =
        trusted_signing_key.ok_or_else(|| anyhow!("directory signing key pin not configured"))?;
    let expected_key_id = hex::encode(trusted.to_bytes());
    if !response.key_id.eq_ignore_ascii_case(&expected_key_id) {
        return Err(anyhow!("directory signing key mismatch"));
    }

    let signature_bytes =
        hex::decode(&response.signature).map_err(|_| anyhow!("invalid resolve signature hex"))?;
    let signature_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid resolve signature length"))?;
    let signature = Signature::from_bytes(&signature_arr);
    let msg = resolve_signing_message(
        username,
        &response.public_key,
        response.seq,
        response.expires_at,
        response.issued_at,
    );
    trusted
        .verify(&msg, &signature)
        .map_err(|_| anyhow!("invalid directory resolve signature"))
}

pub fn publish_signing_message(
    username: &str,
    public_key_hex: &str,
    seq: u64,
    expires_at: u64,
) -> Vec<u8> {
    format!("redoor-directory-publish:v2:{username}:{public_key_hex}:{seq}:{expires_at}")
        .into_bytes()
}

pub fn resolve_signing_message(
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn verify_resolve_response_accepts_valid_signature() {
        let sk = signing_key(7);
        let key_id = hex::encode(sk.verifying_key().to_bytes());
        let public_key = "abcd".to_string();
        let seq = 2;
        let expires_at = 1_700_000_120;
        let issued_at = 1_700_000_000;
        let signature = hex::encode(
            sk.sign(&resolve_signing_message(
                "alice",
                &public_key,
                seq,
                expires_at,
                issued_at,
            ))
            .to_bytes(),
        );
        let response = ResolveResp {
            public_key,
            signature,
            key_id,
            issued_at,
            seq,
            expires_at,
        };

        let trusted = sk.verifying_key();
        let verified = verify_resolve_response("alice", &response, Some(&trusted));
        assert!(verified.is_ok());
    }

    #[test]
    fn verify_resolve_response_rejects_invalid_signature() {
        let sk = signing_key(7);
        let key_id = hex::encode(sk.verifying_key().to_bytes());
        let public_key = "abcd".to_string();
        let seq = 2;
        let expires_at = 1_700_000_120;
        let issued_at = 1_700_000_000;
        let signature = hex::encode(
            sk.sign(&resolve_signing_message(
                "alice", "tampered", seq, expires_at, issued_at,
            ))
            .to_bytes(),
        );
        let response = ResolveResp {
            public_key,
            signature,
            key_id,
            issued_at,
            seq,
            expires_at,
        };

        let trusted = sk.verifying_key();
        let verified = verify_resolve_response("alice", &response, Some(&trusted));
        assert!(verified.is_err());
    }

    #[test]
    fn verify_resolve_response_rejects_unpinned_key() {
        let sk = signing_key(7);
        let key_id = hex::encode(sk.verifying_key().to_bytes());
        let public_key = "abcd".to_string();
        let seq = 2;
        let expires_at = 1_700_000_120;
        let issued_at = 1_700_000_000;
        let signature = hex::encode(
            sk.sign(&resolve_signing_message(
                "alice",
                &public_key,
                seq,
                expires_at,
                issued_at,
            ))
            .to_bytes(),
        );
        let response = ResolveResp {
            public_key,
            signature,
            key_id,
            issued_at,
            seq,
            expires_at,
        };

        let verified = verify_resolve_response("alice", &response, None);
        assert!(verified.is_err());
    }
}
