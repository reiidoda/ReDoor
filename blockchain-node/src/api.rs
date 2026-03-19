use crate::crypto;
use crate::dto::{DelegatedCommitmentRequest, SignedBlockRequest, Transaction};
use crate::ledger;
use crate::ledger::chain::Blockchain;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use warp::{Filter, Reply};

struct IpRateLimiter {
    rps: f64,
    burst: f64,
    buckets: StdMutex<HashMap<String, RateBucket>>,
}

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: f64,
    last: Instant,
}

impl IpRateLimiter {
    fn new(rps: f64, burst: f64) -> Self {
        Self {
            rps,
            burst,
            buckets: StdMutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: &str) -> bool {
        if self.rps <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let b = buckets.entry(ip.to_string()).or_insert(RateBucket {
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

fn parse_rate_limit_env() -> (f64, f64) {
    let rps = env::var("BLOCKCHAIN_HTTP_RPS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(20.0);
    let burst = env::var("BLOCKCHAIN_HTTP_BURST")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(40.0);
    (rps, burst)
}

fn parse_body_limit_env(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

#[derive(Clone)]
struct DelegatePolicy {
    min_threshold: usize,
    max_cosigners: usize,
    allowed_signers: Arc<HashSet<String>>,
}

fn normalize_signer_hex(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() != 32 {
        return None;
    }

    Some(hex::encode(bytes))
}

fn parse_delegate_policy_env() -> DelegatePolicy {
    let min_threshold = env::var("BLOCKCHAIN_DELEGATE_AUTH_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.clamp(1, 32))
        .unwrap_or(1);
    let max_cosigners = env::var("BLOCKCHAIN_DELEGATE_MAX_COSIGNERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.clamp(0, 31))
        .unwrap_or(8);

    let mut allowed_signers = HashSet::new();
    if let Ok(raw) = env::var("BLOCKCHAIN_DELEGATE_ALLOWED_SIGNERS") {
        for candidate in raw.split(',') {
            match normalize_signer_hex(candidate) {
                Some(hex_key) => {
                    allowed_signers.insert(hex_key);
                }
                None => {
                    if !candidate.trim().is_empty() {
                        eprintln!("Ignoring invalid delegate allowlist signer key.");
                    }
                }
            }
        }
    }

    DelegatePolicy {
        min_threshold,
        max_cosigners,
        allowed_signers: Arc::new(allowed_signers),
    }
}

fn delegated_signing_payload(
    timestamp: u64,
    origin_signer_pubkey: &[u8],
    receiver_commitment: &str,
    message_hash: &[u8],
    auth_threshold: u8,
) -> Vec<u8> {
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&timestamp.to_be_bytes());
    signed_data.extend_from_slice(origin_signer_pubkey);
    signed_data.extend_from_slice(receiver_commitment.as_bytes());
    signed_data.extend_from_slice(message_hash);
    signed_data.push(auth_threshold);
    signed_data
}

fn remote_ip(remote: Option<SocketAddr>) -> String {
    remote
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn too_many_requests() -> warp::reply::WithStatus<warp::reply::Json> {
    warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"error":"rate_limited"})),
        warp::http::StatusCode::TOO_MANY_REQUESTS,
    )
}

pub fn routes(
    blockchain: Arc<Mutex<Blockchain>>,
    admin_token: Option<String>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let (rps, burst) = parse_rate_limit_env();
    let rate_limiter = Arc::new(IpRateLimiter::new(rps, burst));
    let admin_max_body = parse_body_limit_env("BLOCKCHAIN_ADMIN_MAX_BODY_BYTES", 16 * 1024);
    let tx_max_body = parse_body_limit_env("BLOCKCHAIN_TX_MAX_BODY_BYTES", 1_048_576);
    let delegate_max_body = parse_body_limit_env("BLOCKCHAIN_DELEGATE_MAX_BODY_BYTES", tx_max_body);
    let signed_block_max_body =
        parse_body_limit_env("BLOCKCHAIN_SIGNED_BLOCK_MAX_BODY_BYTES", 2_097_152);
    let delegate_policy = Arc::new(parse_delegate_policy_env());

    let blockchain_tx = blockchain.clone();
    let blockchain_delegate = blockchain.clone();
    let blockchain_sb = blockchain.clone();

    let admin_token_list = admin_token.clone();
    let admin_token_set = admin_token.clone();
    let limiter_admin_list = rate_limiter.clone();
    let limiter_admin_set = rate_limiter.clone();
    let limiter_tx = rate_limiter.clone();
    let limiter_delegate = rate_limiter.clone();
    let limiter_signed_block = rate_limiter.clone();
    let limiter_health = rate_limiter.clone();
    let limiter_metrics = rate_limiter.clone();

    let admin_list_route = warp::get()
        .and(warp::path("admin"))
        .and(warp::path("validators"))
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::addr::remote())
        .and_then(move |auth: Option<String>, remote: Option<SocketAddr>| {
            let token = admin_token_list.clone();
            let limiter = limiter_admin_list.clone();
            async move {
                if !limiter.allow(&remote_ip(remote)) {
                    return Ok::<_, warp::Rejection>(too_many_requests());
                }

                if let Some(expected) = token {
                    if !admin_token_authorized(auth, Some(expected.as_str())) {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"error":"unauthorized"})),
                            warp::http::StatusCode::UNAUTHORIZED,
                        ));
                    }
                } else {
                    return Ok::<_, warp::Rejection>(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"error":"unauthorized"})),
                        warp::http::StatusCode::UNAUTHORIZED,
                    ));
                }

                let list = crate::consensus::authority::list_validators();
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&list),
                    warp::http::StatusCode::OK,
                ))
            }
        });

    let admin_set_route = warp::post()
        .and(warp::path("admin"))
        .and(warp::path("validators"))
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::addr::remote())
        .and(warp::body::content_length_limit(admin_max_body))
        .and(warp::body::json())
        .and_then(
            move |auth: Option<String>, remote: Option<SocketAddr>, body: Vec<String>| {
                let token = admin_token_set.clone();
                let limiter = limiter_admin_set.clone();
                async move {
                    if !limiter.allow(&remote_ip(remote)) {
                        return Ok::<_, warp::Rejection>(too_many_requests());
                    }

                    if let Some(expected) = token {
                        if !admin_token_authorized(auth, Some(expected.as_str())) {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"error":"unauthorized"})),
                                warp::http::StatusCode::UNAUTHORIZED,
                            ));
                        }
                    } else {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"error":"unauthorized"})),
                            warp::http::StatusCode::UNAUTHORIZED,
                        ));
                    }

                    let mut validators: Vec<Vec<u8>> = Vec::new();
                    for s in body.iter() {
                        match hex::decode(s) {
                            Ok(b) => validators.push(b),
                            Err(_) => {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(
                                        &serde_json::json!({"error":"invalid hex in body"}),
                                    ),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ))
                            }
                        }
                    }
                    crate::consensus::authority::init_validators(validators);
                    let _ = crate::consensus::authority::save_validators_to_file();
                    Ok(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"validators updated"})),
                        warp::http::StatusCode::OK,
                    ))
                }
            },
        );

    let tx_route = warp::post()
        .and(warp::path("tx"))
        .and(warp::addr::remote())
        .and(warp::body::content_length_limit(tx_max_body))
        .and(warp::body::json())
        .and_then(move |remote: Option<SocketAddr>, tx: Transaction| {
            let blockchain = blockchain_tx.clone();
            let limiter = limiter_tx.clone();
            async move {
                if !limiter.allow(&remote_ip(remote)) {
                    return Ok::<_, warp::Rejection>(too_many_requests());
                }

                let signer_pubkey_bytes = match hex::decode(&tx.signer_id) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid signer_id hex"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                if signer_pubkey_bytes.len() != 32 {
                    return Ok(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"error":"Invalid signer_id length"})),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }
                let signature_bytes = match hex::decode(&tx.signature) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid signature hex"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let message_hash_bytes = match hex::decode(&tx.message_hash) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid message_hash hex"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                if message_hash_bytes.len() != 32 {
                    return Ok(warp::reply::with_status(
                        warp::reply::json(
                            &serde_json::json!({"error":"Invalid message_hash length"}),
                        ),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                let mut signed_data = Vec::new();
                signed_data.extend_from_slice(&tx.timestamp.to_be_bytes());
                signed_data.extend_from_slice(&signer_pubkey_bytes);
                signed_data.extend_from_slice(tx.receiver_commitment.as_bytes());
                signed_data.extend_from_slice(&message_hash_bytes);

                if !crypto::ed25519::verify_signature(
                    &signer_pubkey_bytes,
                    &signed_data,
                    &signature_bytes,
                ) {
                    return Ok(warp::reply::with_status(
                        warp::reply::json(
                            &serde_json::json!({"error":"Invalid ED25519 signature"}),
                        ),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                let mut chain = blockchain.lock().await;
                chain.add_block(message_hash_bytes);
                drop(chain);

                Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status":"accepted"})),
                    warp::http::StatusCode::OK,
                ))
            }
        });

    let delegate_route = warp::post()
        .and(warp::path("delegate"))
        .and(warp::path("commitment"))
        .and(warp::addr::remote())
        .and(warp::body::content_length_limit(delegate_max_body))
        .and(warp::body::json())
        .and_then(
            move |remote: Option<SocketAddr>, request: DelegatedCommitmentRequest| {
                let blockchain = blockchain_delegate.clone();
                let limiter = limiter_delegate.clone();
                let policy = delegate_policy.clone();
                async move {
                    if !limiter.allow(&remote_ip(remote)) {
                        return Ok::<_, warp::Rejection>(too_many_requests());
                    }

                    let origin_pubkey_bytes = match hex::decode(&request.origin_signer_id) {
                        Ok(bytes) if bytes.len() == 32 => bytes,
                        Ok(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "error":"Invalid origin_signer_id length"
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                        Err(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"error":"Invalid origin_signer_id hex"}),
                                ),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                    };
                    let origin_signer_id = hex::encode(&origin_pubkey_bytes);

                    if !policy.allowed_signers.is_empty()
                        && !policy.allowed_signers.contains(&origin_signer_id)
                    {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"origin signer not authorized"}),
                            ),
                            warp::http::StatusCode::FORBIDDEN,
                        ));
                    }

                    if request.co_signatures.len() > policy.max_cosigners {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Too many co_signatures"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ));
                    }

                    let message_hash_bytes = match hex::decode(&request.message_hash) {
                        Ok(bytes) if bytes.len() == 32 => bytes,
                        Ok(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "error":"Invalid message_hash length"
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                        Err(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"error":"Invalid message_hash hex"}),
                                ),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                    };
                    let origin_signature_bytes = match hex::decode(&request.origin_signature) {
                        Ok(bytes) if bytes.len() == 64 => bytes,
                        Ok(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "error":"Invalid origin_signature length"
                                })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                        Err(_) => {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"error":"Invalid origin_signature hex"}),
                                ),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                    };

                    let requested_threshold =
                        usize::from(request.auth_threshold.unwrap_or(1).max(1));
                    let auth_threshold = requested_threshold.min(32) as u8;
                    let effective_threshold = policy.min_threshold.max(requested_threshold.min(32));

                    let signed_data = delegated_signing_payload(
                        request.timestamp,
                        &origin_pubkey_bytes,
                        &request.receiver_commitment,
                        &message_hash_bytes,
                        auth_threshold,
                    );
                    if !crypto::ed25519::verify_signature(
                        &origin_pubkey_bytes,
                        &signed_data,
                        &origin_signature_bytes,
                    ) {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid origin signature"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ));
                    }

                    let mut valid_signers = HashSet::new();
                    valid_signers.insert(origin_signer_id);

                    for co in request.co_signatures.iter() {
                        let co_signer_pubkey_bytes = match hex::decode(&co.signer_id) {
                            Ok(bytes) if bytes.len() == 32 => bytes,
                            _ => {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(
                                        &serde_json::json!({"error":"Invalid co-signer signer_id"}),
                                    ),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ))
                            }
                        };
                        let co_signature_bytes = match hex::decode(&co.signature) {
                            Ok(bytes) if bytes.len() == 64 => bytes,
                            _ => {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(
                                        &serde_json::json!({"error":"Invalid co-signer signature"}),
                                    ),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ))
                            }
                        };

                        let co_signer_id = hex::encode(&co_signer_pubkey_bytes);
                        if !policy.allowed_signers.is_empty()
                            && !policy.allowed_signers.contains(&co_signer_id)
                        {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"error":"co-signer not authorized"}),
                                ),
                                warp::http::StatusCode::FORBIDDEN,
                            ));
                        }

                        if !crypto::ed25519::verify_signature(
                            &co_signer_pubkey_bytes,
                            &signed_data,
                            &co_signature_bytes,
                        ) {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(
                                    &serde_json::json!({"error":"Invalid co-signer signature"}),
                                ),
                                warp::http::StatusCode::BAD_REQUEST,
                            ));
                        }

                        valid_signers.insert(co_signer_id);
                    }

                    if valid_signers.len() < effective_threshold {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Insufficient delegated signatures"}),
                            ),
                            warp::http::StatusCode::FORBIDDEN,
                        ));
                    }

                    let mut chain = blockchain.lock().await;
                    chain.add_block(message_hash_bytes);
                    drop(chain);

                    Ok(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "status":"accepted",
                            "mode":"delegated",
                            "valid_signers": valid_signers.len(),
                            "effective_threshold": effective_threshold
                        })),
                        warp::http::StatusCode::OK,
                    ))
                }
            },
        );

    let sb_route = warp::post()
        .and(warp::path("signed_block"))
        .and(warp::addr::remote())
        .and(warp::body::content_length_limit(signed_block_max_body))
        .and(warp::body::json())
        .and_then(move |remote: Option<SocketAddr>, sb: SignedBlockRequest| {
            let blockchain = blockchain_sb.clone();
            let limiter = limiter_signed_block.clone();
            async move {
                if !limiter.allow(&remote_ip(remote)) {
                    return Ok::<_, warp::Rejection>(too_many_requests());
                }

                let previous_hash_bytes = match hex::decode(&sb.previous_hash_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok::<_, warp::Rejection>(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid previous_hash_hex"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let hash_bytes = match hex::decode(&sb.hash_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"error":"Invalid hash_hex"})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let data_bytes = match B64.decode(&sb.data_b64) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"error":"Invalid data_b64"})),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let sig_bytes = match hex::decode(&sb.signature_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid signature_hex"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };
                let signer_pub = match hex::decode(&sb.signer_pub_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(warp::reply::with_status(
                            warp::reply::json(
                                &serde_json::json!({"error":"Invalid signer_pub_hex"}),
                            ),
                            warp::http::StatusCode::BAD_REQUEST,
                        ))
                    }
                };

                if previous_hash_bytes.len() != 32
                    || hash_bytes.len() != 32
                    || sig_bytes.len() != 64
                    || signer_pub.len() != 32
                {
                    return Ok(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"error":"Invalid field lengths"})),
                        warp::http::StatusCode::BAD_REQUEST,
                    ));
                }

                let mut prev_arr = [0u8; 32];
                prev_arr.copy_from_slice(&previous_hash_bytes);
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash_bytes);

                let block = ledger::block::Block {
                    version: 1,
                    index: sb.index,
                    timestamp: sb.timestamp,
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
                    Ok(()) => Ok(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"status":"signed_block_appended"})),
                        warp::http::StatusCode::OK,
                    )),
                    Err(e) => Ok(warp::reply::with_status(
                        warp::reply::json(
                            &serde_json::json!({"error": format!("Signed block rejected: {}", e)}),
                        ),
                        warp::http::StatusCode::BAD_REQUEST,
                    )),
                }
            }
        });

    let health_route = warp::path("health").and(warp::addr::remote()).and_then(
        move |remote: Option<SocketAddr>| {
            let limiter = limiter_health.clone();
            async move {
                if !limiter.allow(&remote_ip(remote)) {
                    return Ok::<_, warp::Rejection>(too_many_requests());
                }
                Ok::<_, warp::Rejection>(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status": "ok"})),
                    warp::http::StatusCode::OK,
                ))
            }
        },
    );
    let metrics_route = warp::path("metrics").and(warp::addr::remote()).and_then(
        move |remote: Option<SocketAddr>| {
            let limiter = limiter_metrics.clone();
            async move {
                if !limiter.allow(&remote_ip(remote)) {
                    return Ok::<_, warp::Rejection>(too_many_requests().into_response());
                }
                Ok::<_, warp::Rejection>(
                    warp::reply::with_status(
                        warp::reply::html(crate::metrics::gather_metrics()),
                        warp::http::StatusCode::OK,
                    )
                    .into_response(),
                )
            }
        },
    );

    admin_list_route
        .or(admin_set_route)
        .or(tx_route)
        .or(delegate_route)
        .or(sb_route)
        .or(health_route)
        .or(metrics_route)
}

fn admin_token_authorized(auth_header: Option<String>, expected_token: Option<&str>) -> bool {
    let expected = match expected_token {
        Some(token) => token,
        None => return false,
    };
    let provided = match auth_header
        .as_deref()
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(str::trim)
    {
        Some(token) if !token.is_empty() => token,
        _ => return false,
    };

    let expected_hash = blake3::hash(expected.as_bytes());
    let provided_hash = blake3::hash(provided.as_bytes());
    expected_hash
        .as_bytes()
        .ct_eq(provided_hash.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::{admin_token_authorized, delegated_signing_payload, routes};
    use crate::ledger::chain::Blockchain;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::Mutex;
    use warp::http::StatusCode;

    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn clear_delegate_env() {
        std::env::remove_var("BLOCKCHAIN_DELEGATE_AUTH_THRESHOLD");
        std::env::remove_var("BLOCKCHAIN_DELEGATE_MAX_COSIGNERS");
        std::env::remove_var("BLOCKCHAIN_DELEGATE_ALLOWED_SIGNERS");
        std::env::remove_var("BLOCKCHAIN_DELEGATE_MAX_BODY_BYTES");
    }

    #[test]
    fn admin_token_authorized_requires_configured_token() {
        assert!(!admin_token_authorized(
            Some("Bearer abc".to_string()),
            None
        ));
    }

    #[test]
    fn admin_token_authorized_rejects_invalid_or_missing_header() {
        assert!(!admin_token_authorized(None, Some("abc")));
        assert!(!admin_token_authorized(
            Some("abc".to_string()),
            Some("abc")
        ));
        assert!(!admin_token_authorized(
            Some("Bearer wrong".to_string()),
            Some("abc")
        ));
    }

    #[test]
    fn admin_token_authorized_accepts_matching_bearer_token() {
        assert!(admin_token_authorized(
            Some("Bearer abc".to_string()),
            Some("abc")
        ));
    }

    #[tokio::test]
    async fn health_route_enforces_rate_limit() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCKCHAIN_HTTP_RPS", "1");
        std::env::set_var("BLOCKCHAIN_HTTP_BURST", "1");

        let filter = routes(Arc::new(Mutex::new(Blockchain::new())), None);
        let remote: std::net::SocketAddr = "127.0.0.1:3456".parse().unwrap();

        let first = warp::test::request()
            .method("GET")
            .path("/health")
            .remote_addr(remote)
            .reply(&filter)
            .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = warp::test::request()
            .method("GET")
            .path("/health")
            .remote_addr(remote)
            .reply(&filter)
            .await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        std::env::remove_var("BLOCKCHAIN_HTTP_RPS");
        std::env::remove_var("BLOCKCHAIN_HTTP_BURST");
    }

    #[tokio::test]
    async fn tx_route_respects_configured_body_limit() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCKCHAIN_TX_MAX_BODY_BYTES", "4");
        std::env::set_var("BLOCKCHAIN_HTTP_RPS", "1000");
        std::env::set_var("BLOCKCHAIN_HTTP_BURST", "1000");

        let filter = routes(Arc::new(Mutex::new(Blockchain::new())), None);
        let remote: std::net::SocketAddr = "127.0.0.1:4567".parse().unwrap();

        let response = warp::test::request()
            .method("POST")
            .path("/tx")
            .remote_addr(remote)
            .header("content-type", "application/json")
            .body("{\"too\":\"big\"}")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        std::env::remove_var("BLOCKCHAIN_TX_MAX_BODY_BYTES");
        std::env::remove_var("BLOCKCHAIN_HTTP_RPS");
        std::env::remove_var("BLOCKCHAIN_HTTP_BURST");
    }

    #[tokio::test]
    async fn delegated_route_accepts_threshold_multisig_submission() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCKCHAIN_HTTP_RPS", "1000");
        std::env::set_var("BLOCKCHAIN_HTTP_BURST", "1000");
        clear_delegate_env();
        std::env::set_var("BLOCKCHAIN_DELEGATE_AUTH_THRESHOLD", "2");

        let filter = routes(Arc::new(Mutex::new(Blockchain::new())), None);
        let remote: std::net::SocketAddr = "127.0.0.1:4568".parse().unwrap();

        let origin = SigningKey::generate(&mut OsRng);
        let co_signer = SigningKey::generate(&mut OsRng);

        let message_hash = [0xAB; 32];
        let receiver_commitment = hex::encode(blake3::hash(b"receiver").as_bytes());
        let timestamp = 1_700_000_100u64;
        let auth_threshold = 2u8;

        let payload = delegated_signing_payload(
            timestamp,
            &origin.verifying_key().to_bytes(),
            &receiver_commitment,
            &message_hash,
            auth_threshold,
        );
        let origin_sig = origin.sign(&payload).to_bytes();
        let co_sig = co_signer.sign(&payload).to_bytes();

        let request_body = serde_json::json!({
            "origin_signer_id": hex::encode(origin.verifying_key().to_bytes()),
            "message_hash": hex::encode(message_hash),
            "origin_signature": hex::encode(origin_sig),
            "timestamp": timestamp,
            "receiver_commitment": receiver_commitment,
            "auth_threshold": auth_threshold,
            "co_signatures": [{
                "signer_id": hex::encode(co_signer.verifying_key().to_bytes()),
                "signature": hex::encode(co_sig),
            }]
        });

        let response = warp::test::request()
            .method("POST")
            .path("/delegate/commitment")
            .remote_addr(remote)
            .header("content-type", "application/json")
            .json(&request_body)
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_json: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body_json["mode"], "delegated");
        assert_eq!(body_json["effective_threshold"], 2);
        assert_eq!(body_json["valid_signers"], 2);

        clear_delegate_env();
        std::env::remove_var("BLOCKCHAIN_HTTP_RPS");
        std::env::remove_var("BLOCKCHAIN_HTTP_BURST");
    }

    #[tokio::test]
    async fn delegated_route_rejects_tampered_threshold_payload() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCKCHAIN_HTTP_RPS", "1000");
        std::env::set_var("BLOCKCHAIN_HTTP_BURST", "1000");
        clear_delegate_env();

        let filter = routes(Arc::new(Mutex::new(Blockchain::new())), None);
        let remote: std::net::SocketAddr = "127.0.0.1:4569".parse().unwrap();

        let origin = SigningKey::generate(&mut OsRng);
        let message_hash = [0xCD; 32];
        let receiver_commitment = hex::encode(blake3::hash(b"receiver").as_bytes());
        let timestamp = 1_700_000_200u64;

        let signed_threshold = 1u8;
        let tampered_threshold = 2u8;
        let payload = delegated_signing_payload(
            timestamp,
            &origin.verifying_key().to_bytes(),
            &receiver_commitment,
            &message_hash,
            signed_threshold,
        );
        let origin_sig = origin.sign(&payload).to_bytes();

        let request_body = serde_json::json!({
            "origin_signer_id": hex::encode(origin.verifying_key().to_bytes()),
            "message_hash": hex::encode(message_hash),
            "origin_signature": hex::encode(origin_sig),
            "timestamp": timestamp,
            "receiver_commitment": receiver_commitment,
            "auth_threshold": tampered_threshold,
            "co_signatures": []
        });

        let response = warp::test::request()
            .method("POST")
            .path("/delegate/commitment")
            .remote_addr(remote)
            .header("content-type", "application/json")
            .json(&request_body)
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        clear_delegate_env();
        std::env::remove_var("BLOCKCHAIN_HTTP_RPS");
        std::env::remove_var("BLOCKCHAIN_HTTP_BURST");
    }

    #[tokio::test]
    async fn delegated_route_enforces_signer_allowlist() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCKCHAIN_HTTP_RPS", "1000");
        std::env::set_var("BLOCKCHAIN_HTTP_BURST", "1000");
        clear_delegate_env();
        std::env::set_var("BLOCKCHAIN_DELEGATE_AUTH_THRESHOLD", "2");

        let origin = SigningKey::generate(&mut OsRng);
        let co_signer = SigningKey::generate(&mut OsRng);

        std::env::set_var(
            "BLOCKCHAIN_DELEGATE_ALLOWED_SIGNERS",
            hex::encode(origin.verifying_key().to_bytes()),
        );

        let filter = routes(Arc::new(Mutex::new(Blockchain::new())), None);
        let remote: std::net::SocketAddr = "127.0.0.1:4570".parse().unwrap();

        let message_hash = [0xEF; 32];
        let receiver_commitment = hex::encode(blake3::hash(b"receiver").as_bytes());
        let timestamp = 1_700_000_300u64;
        let auth_threshold = 2u8;

        let payload = delegated_signing_payload(
            timestamp,
            &origin.verifying_key().to_bytes(),
            &receiver_commitment,
            &message_hash,
            auth_threshold,
        );
        let origin_sig = origin.sign(&payload).to_bytes();
        let co_sig = co_signer.sign(&payload).to_bytes();

        let request_body = serde_json::json!({
            "origin_signer_id": hex::encode(origin.verifying_key().to_bytes()),
            "message_hash": hex::encode(message_hash),
            "origin_signature": hex::encode(origin_sig),
            "timestamp": timestamp,
            "receiver_commitment": receiver_commitment,
            "auth_threshold": auth_threshold,
            "co_signatures": [{
                "signer_id": hex::encode(co_signer.verifying_key().to_bytes()),
                "signature": hex::encode(co_sig),
            }]
        });

        let response = warp::test::request()
            .method("POST")
            .path("/delegate/commitment")
            .remote_addr(remote)
            .header("content-type", "application/json")
            .json(&request_body)
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        clear_delegate_env();
        std::env::remove_var("BLOCKCHAIN_HTTP_RPS");
        std::env::remove_var("BLOCKCHAIN_HTTP_BURST");
    }
}
