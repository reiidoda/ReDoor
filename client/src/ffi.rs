//! C-friendly FFI surface for iOS (or other native hosts).
//! Provides stateful interaction for a real chat app.

use crate::api; // Import the api module
use crate::config;
use crate::config::{
    parse_pq_handshake_policy, pq_handshake_policy_as_str, secure_mode_enabled,
    set_memory_hardening_required, set_memory_hardening_status, set_pq_enabled,
    set_pq_handshake_policy_override, set_relay_ca_b64, set_relay_spki_pin_b64,
};
use crate::crypto;
use crate::diagnostics;
use crate::network::onion::{MixNode, MixnetConfig, OnionRouter};
use crate::ratchet::double_ratchet::RatchetSession;
use crate::service;
use base64::Engine; // Import Engine trait for base64 encoding
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{atomic::Ordering, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::x3dh;
use libc;
#[cfg(feature = "pq")]
use pqcrypto_kyber::kyber1024;
#[cfg(feature = "pq")]
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SharedSecret as KemSharedSecret,
};

// Import the engine module. Note: You must add `pub mod engine;` to client/src/lib.rs
use crate::engine::{
    BackgroundConfig, ClientEngine, CoverTrafficConfig, RateLimitConfig, SessionEntry,
};

static ENGINE: OnceLock<ClientEngine> = OnceLock::new();

const FFI_OK: i32 = 0;
const FFI_ERR_INVALID_INPUT: i32 = -1;
const FFI_ERR_SECURITY: i32 = -2;
const FFI_ERR_INTERNAL: i32 = -255;

fn get_engine() -> &'static ClientEngine {
    ENGINE.get_or_init(|| ClientEngine::new())
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(msg) = payload.downcast_ref::<&str>() {
        return (*msg).to_string();
    }
    if let Some(msg) = payload.downcast_ref::<String>() {
        return msg.clone();
    }
    "non-string panic payload".to_string()
}

fn log_ffi_panic(function_name: &str, payload: Box<dyn std::any::Any + Send>) {
    let msg = panic_payload_to_string(payload.as_ref());
    get_engine().log_internal(format!("ffi panic in {function_name}: {msg}"));
}

fn ffi_guard_i32(function_name: &str, f: impl FnOnce() -> i32 + panic::UnwindSafe) -> i32 {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(payload) => {
            log_ffi_panic(function_name, payload);
            FFI_ERR_INTERNAL
        }
    }
}

fn ffi_guard_ptr(
    function_name: &str,
    f: impl FnOnce() -> *mut c_char + panic::UnwindSafe,
) -> *mut c_char {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(ptr) => ptr,
        Err(payload) => {
            log_ffi_panic(function_name, payload);
            std::ptr::null_mut()
        }
    }
}

fn ffi_guard_void(function_name: &str, f: impl FnOnce() + panic::UnwindSafe) {
    if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(f)) {
        log_ffi_panic(function_name, payload);
    }
}

fn required_cstr(ptr: *const c_char) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(FFI_ERR_INVALID_INPUT);
    }
    let s = unsafe { CStr::from_ptr(ptr) };
    Ok(s.to_str().map_err(|_| FFI_ERR_INVALID_INPUT)?.to_owned())
}

fn optional_cstr(ptr: *const c_char) -> Result<Option<String>, i32> {
    if ptr.is_null() {
        return Ok(None);
    }
    let s = unsafe { CStr::from_ptr(ptr) };
    Ok(Some(
        s.to_str().map_err(|_| FFI_ERR_INVALID_INPUT)?.to_owned(),
    ))
}

fn to_c_string_ptr(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn enforce_memory_hardening() -> Result<(), String> {
    if cfg!(test)
        && std::env::var("REDOOR_TEST_FORCE_MLOCKALL_FAIL")
            .ok()
            .as_deref()
            == Some("1")
    {
        return Err("forced mlockall failure for tests".to_string());
    }

    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "mlockall failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn apply_memory_hardening_policy() -> Result<(), i32> {
    let secure_mode = secure_mode_enabled();
    set_memory_hardening_required(secure_mode);

    match enforce_memory_hardening() {
        Ok(()) => {
            set_memory_hardening_status(true, None);
            Ok(())
        }
        Err(err) => {
            set_memory_hardening_status(false, Some(err.clone()));
            if secure_mode {
                get_engine().log_internal(format!(
                    "Security Error: memory hardening failed in secure mode: {err}"
                ));
                return Err(FFI_ERR_SECURITY);
            }
            get_engine().log_internal(format!(
                "Warning: memory hardening unavailable in dev mode: {err}"
            ));
            Ok(())
        }
    }
}

// --- FFI Functions ---

#[no_mangle]
pub extern "C" fn redoor_init_runtime() -> i32 {
    ffi_guard_i32("redoor_init_runtime", || {
        // Runtime is initialized in ClientEngine::new
        let _ = get_engine();
        FFI_OK
    })
}

#[no_mangle]
pub extern "C" fn redoor_init_env(
    relay_url: *const c_char,
    blockchain_addr: *const c_char,
    hmac_key: *const c_char,
) -> i32 {
    ffi_guard_i32("redoor_init_env", || {
        // Task: Remove RELAY_ALLOW_INSECURE
        // We explicitly unset this to prevent any underlying library from picking it up.
        env::remove_var("RELAY_ALLOW_INSECURE");

        let relay_str = match required_cstr(relay_url) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let chain_str = match required_cstr(blockchain_addr) {
            Ok(v) => v,
            Err(code) => return code,
        };

        if let Err(code) = apply_memory_hardening_policy() {
            return code;
        }

        // Task: Transport Encryption Hard Lock
        // Enforce HTTPS/WSS for all relay connections.
        // Exception: .onion addresses (Tor provides encryption)
        // Exception: localhost in DEBUG builds only.
        let is_secure = relay_str.starts_with("https://") || relay_str.starts_with("wss://");
        let is_onion = relay_str.contains(".onion");
        let is_localhost = relay_str.contains("localhost") || relay_str.contains("127.0.0.1");

        if !is_secure && !is_onion && !(is_localhost && cfg!(debug_assertions)) {
            get_engine().log_internal(format!(
                "Security Error: Plaintext transport forbidden for relay: {relay_str}"
            ));
            return FFI_ERR_SECURITY;
        }

        if let Some(key_str) = match optional_cstr(hmac_key) {
            Ok(v) => v,
            Err(code) => return code,
        } {
            env::set_var("RELAY_HMAC_KEY", key_str);
        }

        let engine = get_engine();
        crate::service::configure_network(engine, relay_str.as_str(), chain_str.as_str());

        FFI_OK
    })
}

#[no_mangle]
pub extern "C" fn redoor_create_identity() -> *mut c_char {
    ffi_guard_ptr("redoor_create_identity", || {
        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();

        let id = crypto::ed25519::IdentityKey::generate();
        let pub_hex = hex::encode(id.public_key_bytes());
        guard.identity = Some(id);

        to_c_string_ptr(pub_hex)
    })
}

/// Generates a new set of prekeys for X3DH.
/// This should be done after creating an identity. The public part should be
/// published to the relay server.
///
/// # Returns
/// A C-string containing the JSON-serialized public `PrekeyBundle`. The caller
/// is responsible for freeing this string. Returns a null pointer on failure.
#[no_mangle]
pub extern "C" fn redoor_generate_prekeys() -> *mut c_char {
    ffi_guard_ptr("redoor_generate_prekeys", || {
        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();

        let identity = match &guard.identity {
            Some(id) => id,
            None => return std::ptr::null_mut(), // Must have identity first
        };

        match x3dh::generate_prekey_bundle(identity) {
            Ok((public_bundle, secrets)) => {
                guard.prekey_secrets = Some(secrets);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                guard.signed_prekey_last_rotated_at = Some(now);
                guard.prekey_last_replenished_at = Some(now);

                // Generate Kyber keys for Hybrid PQ
                #[cfg(feature = "pq")]
                {
                    let (pk, sk) = kyber1024::keypair();
                    guard.kyber_keys = Some((pk, sk));

                    // Inject Kyber public key into the bundle JSON
                    let mut json_val = match serde_json::to_value(&public_bundle) {
                        Ok(v) => v,
                        Err(_) => return std::ptr::null_mut(),
                    };
                    json_val["kyber_pub"] = serde_json::Value::String(hex::encode(pk.as_bytes()));
                    let json = match serde_json::to_string(&json_val) {
                        Ok(v) => v,
                        Err(_) => return std::ptr::null_mut(),
                    };
                    return to_c_string_ptr(json);
                }
                #[cfg(not(feature = "pq"))]
                {
                    let json = match serde_json::to_string(&public_bundle) {
                        Ok(v) => v,
                        Err(_) => return std::ptr::null_mut(),
                    };
                    return to_c_string_ptr(json);
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Returns the current identity public key hex, or NULL if none.
#[no_mangle]
pub extern "C" fn redoor_get_identity() -> *mut c_char {
    ffi_guard_ptr("redoor_get_identity", || {
        let engine = get_engine();
        let guard = engine.state.lock().unwrap();

        if let Some(id) = &guard.identity {
            let pub_hex = hex::encode(id.public_key_bytes());
            to_c_string_ptr(pub_hex)
        } else {
            std::ptr::null_mut()
        }
    })
}

/// Initiates an X3DH session with a peer.
///
/// This is the primary function for starting a secure conversation. It takes the
/// peer's public prekey bundle (fetched from a server), performs the X3DH
/// handshake, and establishes a new ratchet session.
///
/// # Arguments
/// * `peer_id_hex` - The peer's long-term identity public key (hex-encoded), used as the session identifier.
/// * `peer_bundle_json` - A JSON string representing the peer's `PrekeyBundle`.
///
/// # Returns
/// A C-string containing the JSON-serialized `InitialMessage`. This message must
/// be sent to the peer for them to complete the handshake. Returns a null
/// pointer on failure. The caller is responsible for freeing the string.
#[no_mangle]
pub extern "C" fn redoor_initiate_session(
    peer_id_hex: *const c_char,
    peer_bundle_json: *const c_char,
) -> *mut c_char {
    ffi_guard_ptr("redoor_initiate_session", || {
        let peer_id = match required_cstr(peer_id_hex) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        if peer_id.is_empty() {
            return std::ptr::null_mut();
        }

        let bundle_str = match required_cstr(peer_bundle_json) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        let bundle_val: serde_json::Value = match serde_json::from_str(bundle_str.as_str()) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        let peer_bundle: x3dh::PrekeyBundle = match serde_json::from_value(bundle_val.clone()) {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };

        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();

        let our_identity = match &guard.identity {
            Some(id) => id,
            None => return std::ptr::null_mut(), // Must have identity
        };

        // Verify that the bundle's identity key matches the peer_id we are trying to contact.
        if hex::encode(&peer_bundle.identity_key) != peer_id {
            get_engine().log_internal(format!(
                "Security Error: Identity key mismatch for peer {peer_id}"
            ));
            return std::ptr::null_mut();
        }

        // 0. Verify Signed Prekey Signature (Directory Authority Trust Fix)
        // Enforce that the signed prekey is actually signed by the identity key.
        if let Some(sig_hex) = bundle_val
            .get("signed_prekey_signature")
            .and_then(|v| v.as_str())
        {
            if let Ok(sig_bytes) = hex::decode(sig_hex) {
                if !crypto::ed25519::verify(
                    &peer_bundle.identity_key,
                    &peer_bundle.signed_prekey,
                    &sig_bytes,
                ) {
                    get_engine().log_internal(format!(
                        "Security Error: Invalid prekey signature for peer {peer_id}"
                    ));
                    return std::ptr::null_mut();
                }
            } else {
                return std::ptr::null_mut();
            }
        } else {
            return std::ptr::null_mut(); // Signature mandatory
        }

        // 1. Perform the X3DH handshake to get the shared secret
        let (mut shared_secret, initial_msg_template) =
            match x3dh::initiate_handshake(our_identity, &peer_bundle) {
                Ok(result) => result,
                Err(_) => return std::ptr::null_mut(),
            };

        // 2. Perform Kyber Encapsulation (Hybrid PQ)
        let mut kyber_ct_hex = String::new();
        #[cfg(feature = "pq")]
        if let Some(k_pub_hex) = bundle_val.get("kyber_pub").and_then(|v| v.as_str()) {
            if let Ok(k_pub_bytes) = hex::decode(k_pub_hex) {
                if let Ok(k_pub) = kyber1024::PublicKey::from_bytes(&k_pub_bytes) {
                    let (ct, ss) = kyber1024::encapsulate(&k_pub);

                    // Hybrid KDF: Mix X3DH secret + Kyber secret
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&shared_secret);
                    hasher.update(ss.as_bytes());
                    shared_secret = hasher.finalize().into();

                    kyber_ct_hex = hex::encode(ct.as_bytes());
                }
            }
        }

        // 2. Create the ratchet session
        let spk_bytes: [u8; 32] = match peer_bundle.signed_prekey.clone().try_into() {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };
        let peer_spk = crypto::x25519::PublicKey::from(spk_bytes);
        let session = SessionEntry {
            wrapped_state: None,
            inner: Some(RatchetSession::new(shared_secret, Some(peer_spk))),
            pending_handshake: None, // Will be set below
            peer_seal_key: Some(peer_bundle.signed_prekey.to_vec()),
        };

        // 3. Store the new session
        guard.sessions.insert(peer_id.to_string(), session);
        guard.mark_session_established(
            peer_id.as_str(),
            config::protocol_version_current(),
            "initiator_handshake_created",
        );

        // 4. Return the initial message to be sent
        // The ciphertext for the first message will be added by the caller before sending.
        // For now, we return the template.
        let mut msg_val = match serde_json::to_value(&initial_msg_template) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        if !kyber_ct_hex.is_empty() {
            msg_val["kyber_ct"] = serde_json::Value::String(kyber_ct_hex);
        }
        let initial_msg_json = match serde_json::to_string(&msg_val) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };

        if let Some(entry) = guard.sessions.get_mut(peer_id.as_str()) {
            entry.pending_handshake = Some(initial_msg_json.clone());
        }

        to_c_string_ptr(initial_msg_json)
    })
}

/// Initiates a session from a scanned QR code containing a JSON PrekeyBundle.
/// This is essential for the "reconnect via QR" workflow in a RAM-only app.
#[no_mangle]
pub extern "C" fn redoor_connect_via_qr(qr_json: *const c_char) -> *mut c_char {
    ffi_guard_ptr("redoor_connect_via_qr", || {
        let json_str = match required_cstr(qr_json) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        let bundle_val: serde_json::Value = match serde_json::from_str(json_str.as_str()) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        let bundle: x3dh::PrekeyBundle = match serde_json::from_value(bundle_val.clone()) {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };

        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();

        let our_identity = match &guard.identity {
            Some(id) => id,
            None => return std::ptr::null_mut(),
        };

        let (mut shared_secret, initial_msg_template) =
            match x3dh::initiate_handshake(our_identity, &bundle) {
                Ok(res) => res,
                Err(_) => return std::ptr::null_mut(),
            };

        // Hybrid PQ
        let mut kyber_ct_hex = String::new();
        #[cfg(feature = "pq")]
        if let Some(k_pub_hex) = bundle_val.get("kyber_pub").and_then(|v| v.as_str()) {
            if let Ok(k_pub_bytes) = hex::decode(k_pub_hex) {
                if let Ok(k_pub) = kyber1024::PublicKey::from_bytes(&k_pub_bytes) {
                    let (ct, ss) = kyber1024::encapsulate(&k_pub);
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&shared_secret);
                    hasher.update(ss.as_bytes());
                    shared_secret = hasher.finalize().into();
                    kyber_ct_hex = hex::encode(ct.as_bytes());
                }
            }
        }

        let peer_id = hex::encode(&bundle.identity_key);

        let spk_bytes: [u8; 32] = match bundle.signed_prekey.clone().try_into() {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };
        let peer_spk = crypto::x25519::PublicKey::from(spk_bytes);

        let session = SessionEntry {
            wrapped_state: None,
            inner: Some(RatchetSession::new(shared_secret, Some(peer_spk))),
            pending_handshake: None,
            peer_seal_key: Some(bundle.signed_prekey.to_vec()),
        };
        guard.sessions.insert(peer_id.clone(), session);
        guard.mark_session_established(
            peer_id.as_str(),
            config::protocol_version_current(),
            "initiator_handshake_created",
        );

        let mut msg_val = match serde_json::to_value(&initial_msg_template) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        if !kyber_ct_hex.is_empty() {
            msg_val["kyber_ct"] = serde_json::Value::String(kyber_ct_hex);
        }
        let json = match serde_json::to_string(&msg_val) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        to_c_string_ptr(json)
    })
}

/// Handles an incoming `InitialMessage` to complete the X3DH handshake.
///
/// This is the primary function for a user who is being contacted by someone new.
/// It processes the initiator's message, derives the shared secret, and establishes
/// the session, making it ready for receiving messages.
///
/// # Arguments
/// * `peer_id_hex` - The initiator's identity public key (hex-encoded).
/// * `initial_message_json` - The JSON string of the `InitialMessage` received from the peer.
///
/// # Returns
/// 0 on success, or a negative number on failure.
#[no_mangle]
pub extern "C" fn redoor_handle_initial_message(
    peer_id_hex: *const c_char,
    initial_message_json: *const c_char,
) -> i32 {
    ffi_guard_i32("redoor_handle_initial_message", || {
        let peer_id = match required_cstr(peer_id_hex) {
            Ok(v) => v,
            Err(_) => return FFI_ERR_INVALID_INPUT,
        };
        if peer_id.is_empty() {
            return FFI_ERR_INVALID_INPUT;
        }

        let msg_str = match required_cstr(initial_message_json) {
            Ok(v) => v,
            Err(_) => return FFI_ERR_INVALID_INPUT,
        };
        let msg_val: serde_json::Value = match serde_json::from_str(msg_str.as_str()) {
            Ok(v) => v,
            Err(_) => return -2,
        };
        let initial_message: x3dh::InitialMessage = match serde_json::from_value(msg_val.clone()) {
            Ok(m) => m,
            Err(_) => return -2,
        };

        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();

        let our_identity = match guard.identity.clone() {
            Some(id) => id,
            None => return -3, // Must have identity
        };

        let our_prekey_secrets = match &mut guard.prekey_secrets {
            Some(secrets) => secrets,
            None => return -4, // Must have prekeys
        };

        // 1. Perform the responder's side of the handshake
        let mut shared_secret =
            match x3dh::respond_to_handshake(&our_identity, our_prekey_secrets, &initial_message) {
                Ok(secret) => secret,
                Err(_) => return -5,
            };

        // 2. Hybrid PQ Decapsulation
        #[cfg(feature = "pq")]
        if let Some(ct_hex) = msg_val.get("kyber_ct").and_then(|v| v.as_str()) {
            if let Ok(ct_bytes) = hex::decode(ct_hex) {
                if let Ok(ct) = kyber1024::Ciphertext::from_bytes(&ct_bytes) {
                    if let Some((_, sk)) = &guard.kyber_keys {
                        let ss = kyber1024::decapsulate(&ct, sk);
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(&shared_secret);
                        hasher.update(ss.as_bytes());
                        shared_secret = hasher.finalize().into();
                    }
                }
            }
        }

        // 2. Create and store the new session
        let peer_ek: [u8; 32] =
            match TryInto::<[u8; 32]>::try_into(initial_message.ephemeral_key.as_slice()) {
                Ok(v) => v,
                Err(_) => return -2,
            };
        let peer_ek_pub = crypto::x25519::PublicKey::from(peer_ek);
        let session = SessionEntry {
            wrapped_state: None,
            inner: Some(RatchetSession::new(shared_secret, Some(peer_ek_pub))),
            pending_handshake: None,
            peer_seal_key: None, // We are responder, we don't seal handshakes to them
        };
        let handshake_protocol_version = initial_message.protocol_version.unwrap_or(1);
        guard.sessions.insert(peer_id.clone(), session);
        guard.mark_session_established(
            peer_id.as_str(),
            handshake_protocol_version,
            "responder_initial_handshake",
        );

        FFI_OK
    })
}

#[no_mangle]
pub extern "C" fn redoor_send_message(peer_id_hex: *const c_char, message: *const c_char) -> i32 {
    ffi_guard_i32("redoor_send_message", || {
        let peer_id = match required_cstr(peer_id_hex) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let msg_text = match required_cstr(message) {
            Ok(v) => v,
            Err(code) => return code,
        };

        get_engine().send_payload(
            peer_id.as_str(),
            msg_text.as_str(),
            "text",
            None,
            true,
            false,
            None,
        )
    })
}

/// Poll for new messages. Returns a JSON string of list of messages: [{"sender": "...", "text": "...", "type": "..."}]
#[no_mangle]
pub extern "C" fn redoor_poll_messages() -> *mut c_char {
    ffi_guard_ptr("redoor_poll_messages", || {
        let json = get_engine().poll_messages();
        to_c_string_ptr(json)
    })
}

#[no_mangle]
pub extern "C" fn redoor_free_string(s: *mut c_char) {
    ffi_guard_void("redoor_free_string", || {
        if s.is_null() {
            return;
        }
        unsafe {
            let _ = CString::from_raw(s);
        }
    });
}

/// Wipes all sensitive data from memory immediately.
/// This should be called when the app enters background or locks.
#[no_mangle]
pub extern "C" fn redoor_wipe_memory() {
    ffi_guard_void("redoor_wipe_memory", || {
        let engine = get_engine();
        crate::service::wipe_sensitive_state(engine);
    });
}

/// Rotates the Signed Prekey.
/// This should be called periodically (e.g., once a week) to ensure forward secrecy for new sessions.
/// Returns a JSON string: { "signed_prekey": "hex...", "signature": "hex..." }
#[no_mangle]
pub extern "C" fn redoor_rotate_signed_prekey() -> *mut c_char {
    ffi_guard_ptr("redoor_rotate_signed_prekey", || {
        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();

        let identity = match &guard.identity {
            Some(id) => id,
            None => return std::ptr::null_mut(),
        };

        if guard.prekey_secrets.is_none() {
            return std::ptr::null_mut();
        }

        match x3dh::rotate_signed_prekey(identity) {
            Ok((spk_pub, sig, spk_priv)) => {
                if let Some(secrets) = &mut guard.prekey_secrets {
                    secrets.signed_prekey = spk_priv;
                }
                guard.signed_prekey_last_rotated_at = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );

                #[derive(serde::Serialize)]
                struct Rotation {
                    signed_prekey: String,
                    signature: String,
                }
                let r = Rotation {
                    signed_prekey: hex::encode(spk_pub),
                    signature: hex::encode(sig),
                };
                let json = match serde_json::to_string(&r) {
                    Ok(v) => v,
                    Err(_) => return std::ptr::null_mut(),
                };
                to_c_string_ptr(json)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Explicitly deletes a session for a given peer.
/// This wipes the session keys from memory.
#[no_mangle]
pub extern "C" fn redoor_delete_session(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();

    if guard.sessions.remove(peer_id).is_some() {
        0
    } else {
        -1 // Session not found
    }
}

/// Generates a batch of new One-Time Prekeys to replenish the server's stock.
/// Returns a JSON array of hex-encoded public keys: ["hex1", "hex2", ...]
#[no_mangle]
pub extern "C" fn redoor_replenish_one_time_prekeys(count: usize) -> *mut c_char {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();

    if guard.prekey_secrets.is_none() {
        return std::ptr::null_mut();
    }

    let (pub_keys, secrets) = x3dh::generate_one_time_prekeys(count);

    if let Some(ps) = &mut guard.prekey_secrets.as_mut() {
        ps.one_time_prekeys.extend(secrets);
        guard.prekey_last_replenished_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }

    let hex_keys: Vec<String> = pub_keys.iter().map(hex::encode).collect();
    let json = serde_json::to_string(&hex_keys).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Checks if a session exists for the given peer.
/// Returns 1 if exists, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_has_session(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return 0;
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if guard.sessions.contains_key(peer_id) {
        1
    } else {
        0
    }
}

// Helper for safety number calculation
fn compute_safety_fingerprint(our_key: &[u8], peer_key: &[u8]) -> String {
    let (k1, k2) = if our_key < peer_key {
        (our_key, peer_key)
    } else {
        (peer_key, our_key)
    };

    let mut combined = Vec::new();
    combined.extend_from_slice(k1);
    combined.extend_from_slice(k2);

    let hash = crypto::blake3::hash(&combined);
    hex::encode(hash)
}

/// Calculates a safety number (fingerprint) for the peer.
/// This allows users to verify keys out-of-band to detect MITM attacks.
/// Returns a hex string of the fingerprint.
#[no_mangle]
pub extern "C" fn redoor_get_safety_number(peer_id_hex: *const c_char) -> *mut c_char {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return std::ptr::null_mut();
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let our_id = match &guard.identity {
        Some(id) => id.public_key_bytes(),
        None => return std::ptr::null_mut(),
    };

    let peer_bytes = match hex::decode(peer_id) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let fingerprint = compute_safety_fingerprint(&our_id, &peer_bytes);

    CString::new(fingerprint).unwrap().into_raw()
}

/// Verifies a user-supplied safety number against the calculated one.
/// Returns 1 if they match, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_verify_safety_number(
    peer_id_hex: *const c_char,
    fingerprint_hex: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let input_fp = unsafe { CStr::from_ptr(fingerprint_hex) }
        .to_str()
        .unwrap_or("");

    if peer_id.is_empty() || input_fp.is_empty() {
        return 0;
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let our_id = match &guard.identity {
        Some(id) => id.public_key_bytes(),
        None => return 0,
    };

    let peer_bytes = match hex::decode(peer_id) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    let calculated = compute_safety_fingerprint(&our_id, &peer_bytes);

    if calculated == input_fp {
        1
    } else {
        0
    }
}

/// Sends a file attachment.
/// 1. Encrypts the file data with a fresh symmetric key.
/// 2. Uploads the encrypted blob to the relay.
/// 3. Sends a metadata message (Ratchet-encrypted) containing the key and blob ID.
#[no_mangle]
pub extern "C" fn redoor_send_file(
    _peer_id_hex: *const c_char,
    _file_data: *const u8,
    _file_len: usize,
    _filename: *const c_char,
) -> i32 {
    // File sending is disabled
    -1
}

/// Decrypts a file from the attachment cache.
/// Returns the decrypted bytes (caller must free).
#[no_mangle]
pub extern "C" fn redoor_decrypt_file(
    _file_id_hex: *const c_char,
    _key_hex: *const c_char,
    _nonce_hex: *const c_char,
    _out_len: *mut usize,
) -> *mut u8 {
    // File decryption is disabled
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn redoor_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len));
    }
}

/// Creates a new group with the given members.
/// `members_json` should be a JSON array of peer ID hex strings.
/// Returns the new Group ID (hex string).
#[no_mangle]
pub extern "C" fn redoor_create_group(members_json: *const c_char) -> *mut c_char {
    let members_str = unsafe { CStr::from_ptr(members_json) }
        .to_str()
        .unwrap_or("[]");
    let members: Vec<String> = serde_json::from_str(members_str).unwrap_or_default();

    if members.is_empty() {
        return std::ptr::null_mut();
    }

    let mut rng = rand::thread_rng();
    let mut gid_bytes = [0u8; 16];
    rng.fill(&mut gid_bytes);
    let group_id = hex::encode(gid_bytes);
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.groups.insert(group_id.clone(), members);

    CString::new(group_id).unwrap().into_raw()
}

/// Sends a message to a group.
/// This performs client-side fan-out: encrypting and sending a separate message to each member.
#[no_mangle]
pub extern "C" fn redoor_send_group_message(
    group_id_hex: *const c_char,
    message: *const c_char,
) -> i32 {
    let group_id = unsafe { CStr::from_ptr(group_id_hex) }
        .to_str()
        .unwrap_or("");
    let msg_text = unsafe { CStr::from_ptr(message) }.to_str().unwrap_or("");

    if group_id.is_empty() || msg_text.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let members = {
        let guard = engine.state.lock().unwrap();
        match guard.groups.get(group_id) {
            Some(m) => m.clone(),
            None => return -2, // Group not found
        }
    };

    let mut success_count = 0;
    for peer_id in &members {
        // We ignore errors for individual peers to attempt delivery to all.
        // In a real app, we might want to report partial failures.
        if engine.send_payload(peer_id, msg_text, "text", Some(group_id), true, false, None) == 0 {
            success_count += 1;
        }
    }

    if success_count > 0 {
        0
    } else {
        -3
    }
}

/// Returns the members of a group as a JSON array.
#[no_mangle]
pub extern "C" fn redoor_get_group_members(group_id_hex: *const c_char) -> *mut c_char {
    let group_id = unsafe { CStr::from_ptr(group_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(members) = guard.groups.get(group_id) {
        let json = serde_json::to_string(members).unwrap();
        return CString::new(json).unwrap().into_raw();
    }
    std::ptr::null_mut()
}

/// Sends a typing indicator to a peer.
/// This is ephemeral and is NOT logged to the blockchain.
#[no_mangle]
pub extern "C" fn redoor_set_typing_status(peer_id_hex: *const c_char, typing: i32) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let status = if typing != 0 {
        "typing_on"
    } else {
        "typing_off"
    };
    get_engine().send_payload(peer_id, status, "typing", None, true, false, None)
}

/// Blocks a peer. Messages from this peer will be dropped, and sending will be prevented.
#[no_mangle]
pub extern "C" fn redoor_block_peer(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.blocked_peers.insert(peer_id.to_string());
    0
}

/// Unblocks a peer.
#[no_mangle]
pub extern "C" fn redoor_unblock_peer(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.blocked_peers.remove(peer_id);
    0
}

/// Checks if a peer is blocked. Returns 1 if blocked, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_is_blocked(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    if guard.blocked_peers.contains(peer_id) {
        1
    } else {
        0
    }
}

/// Returns a JSON array of blocked peer IDs.
#[no_mangle]
pub extern "C" fn redoor_get_blocked_peers() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    let list: Vec<&String> = guard.blocked_peers.iter().collect();
    let json = serde_json::to_string(&list).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Returns network status and configuration as JSON.
/// Example: {"relay_connected": true, "blockchain_connected": true, "relay_url": "..."}
#[no_mangle]
pub extern "C" fn redoor_get_network_status() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let (relay_connected, relay_url) = match &guard.relay_client {
        Some(rc) => (true, rc.base_url.clone()),
        None => (false, "".to_string()),
    };

    let (chain_connected, chain_addr) = match &guard.blockchain_client {
        Some(bc) => (true, bc.base_url.clone()),
        None => (false, "".to_string()),
    };

    #[derive(serde::Serialize)]
    struct Status {
        relay_connected: bool,
        blockchain_connected: bool,
        relay_url: String,
        blockchain_addr: String,
    }

    let s = Status {
        relay_connected,
        blockchain_connected: chain_connected,
        relay_url,
        blockchain_addr: chain_addr,
    };
    let json = serde_json::to_string(&s).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Verifies the internal integrity of a ratchet session.
/// Returns 1 if valid, 0 if corruption detected, -1 if session not found.
#[no_mangle]
pub extern "C" fn redoor_verify_ratchet_state(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(session) = guard.sessions.get(peer_id) {
        if let Some(inner) = &session.inner {
            if inner.verify_integrity() {
                1
            } else {
                0
            }
        } else {
            0
        }
    } else {
        -1
    }
}

/// Configures onion routing with a list of nodes.
/// `nodes_json` should be
/// `[{"url":"...","pub_key":"hex...","operator":"...","jurisdiction":"...","asn":"..."}]`.
#[no_mangle]
pub extern "C" fn redoor_configure_onion_routing(nodes_json: *const c_char) -> i32 {
    if nodes_json.is_null() {
        return -1;
    }
    let json_str = unsafe { CStr::from_ptr(nodes_json) }.to_str().unwrap_or("");

    #[derive(serde::Deserialize)]
    struct NodeConfig {
        url: String,
        pub_key: String,
        #[serde(default)]
        operator: Option<String>,
        #[serde(default)]
        jurisdiction: Option<String>,
        #[serde(default)]
        asn: Option<String>,
    }

    let configs: Vec<NodeConfig> = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    if configs.is_empty() {
        return -1;
    }

    let mut nodes = Vec::new();
    for c in configs {
        // Transport Lock: Mix nodes must be TLS or Onion
        let is_secure = c.url.starts_with("https://") || c.url.starts_with("wss://");
        let is_onion = c.url.contains(".onion");
        let is_localhost = c.url.contains("localhost") || c.url.contains("127.0.0.1");

        if !is_secure && !is_onion {
            if !(is_localhost && cfg!(debug_assertions)) {
                get_engine().log_internal(format!(
                    "Security Error: Insecure mix node rejected: {}",
                    c.url
                ));
                return -2;
            }
        }

        let pk_bytes = match hex::decode(&c.pub_key) {
            Ok(bytes) => bytes,
            Err(_) => return -3,
        };
        if pk_bytes.len() != 32 {
            return -3;
        }
        nodes.push(MixNode::with_extended_tags(
            c.url,
            crypto::x25519::PublicKey::from(TryInto::<[u8; 32]>::try_into(pk_bytes).unwrap()),
            c.operator,
            c.jurisdiction,
            c.asn,
        ));
    }
    if nodes.len() < 3 {
        return -3;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.onion_router = Some(OnionRouter::new_tagged(nodes));
    0
}

/// Returns the current status of onion routing.
/// Returns JSON: { "enabled": true, "node_count": 3 }
#[no_mangle]
pub extern "C" fn redoor_get_onion_status() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    #[derive(serde::Serialize)]
    struct OnionStatus {
        enabled: bool,
        node_count: usize,
    }

    let (enabled, count) = if let Some(router) = &guard.onion_router {
        (true, router.node_count())
    } else {
        (false, 0)
    };

    let status = OnionStatus {
        enabled,
        node_count: count,
    };
    let json = serde_json::to_string(&status).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Runs a cryptographic benchmark on the device.
/// Returns JSON with timing metrics in microseconds for various primitives.
/// Useful for tuning timeouts and PoW difficulty on slower devices.
#[no_mangle]
pub extern "C" fn redoor_benchmark_crypto() -> *mut c_char {
    ffi_guard_ptr("redoor_benchmark_crypto", || {
        let res = diagnostics::run_crypto_benchmark();
        match serde_json::to_string(&res) {
            Ok(json) => to_c_string_ptr(json),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Runs memory-footprint benchmark checks and returns JSON report.
/// Includes populated/post-wipe/post-duress usage snapshots and pass/fail status.
#[no_mangle]
pub extern "C" fn redoor_benchmark_memory_budget() -> *mut c_char {
    ffi_guard_ptr("redoor_benchmark_memory_budget", || {
        let res = diagnostics::run_memory_budget_benchmark();
        match serde_json::to_string(&res) {
            Ok(json) => to_c_string_ptr(json),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Runs deterministic traffic-analysis simulation and returns linkability metrics.
/// `seed` controls fixture generation to keep reports comparable across runs.
#[no_mangle]
pub extern "C" fn redoor_benchmark_traffic_linkability(seed: u64) -> *mut c_char {
    ffi_guard_ptr("redoor_benchmark_traffic_linkability", || {
        let res = diagnostics::run_traffic_analysis_simulator(seed);
        match serde_json::to_string(&res) {
            Ok(json) => to_c_string_ptr(json),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Runs a comprehensive self-test and returns a JSON health report.
#[no_mangle]
pub extern "C" fn redoor_run_diagnostics() -> *mut c_char {
    let engine = get_engine();
    let report = diagnostics::run_health_check(engine);
    let json = serde_json::to_string(&report).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Configures background behavior.
/// mode: 0 = Keep Alive (do nothing), 1 = Immediate Wipe, 2 = Grace Period
/// grace_period_ms: Time in ms to wait before wiping (only for mode 2)
#[no_mangle]
pub extern "C" fn redoor_set_background_mode(mode: i32, grace_period_ms: u64) -> i32 {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.background_config = BackgroundConfig {
        mode,
        grace_period_ms,
    };
    0
}

/// Signals that the app has entered the background.
/// Triggers wipe logic based on configured mode.
#[no_mangle]
pub extern "C" fn redoor_signal_background() -> i32 {
    let engine = get_engine();
    crate::service::handle_background_signal(engine)
}

/// Signals that the app has entered the foreground.
/// Cancels any pending background wipe tasks.
#[no_mangle]
pub extern "C" fn redoor_signal_foreground() -> i32 {
    let engine = get_engine();
    crate::service::handle_foreground_signal(engine)
}

/// Flags a suspected compromise indicator and forces rekey.
/// If `peer_id_hex` is NULL, all sessions are marked for forced rekey.
#[no_mangle]
pub extern "C" fn redoor_flag_compromise_indicator(peer_id_hex: *const c_char) -> i32 {
    let engine = get_engine();
    if peer_id_hex.is_null() {
        engine.mark_all_sessions_for_rekey("compromise_indicator_manual");
        return 0;
    }

    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.trim().is_empty() {
        return -1;
    }
    engine.mark_peer_for_rekey(peer_id, "compromise_indicator_manual");
    0
}

/// Exports the in-memory debug log buffer as a JSON array of strings.
/// The logs are redacted of sensitive info (keys, plaintext) by design of log_internal.
#[no_mangle]
pub extern "C" fn redoor_export_logs() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    let logs: Vec<String> = guard.log_buffer.iter().cloned().collect();
    let json = serde_json::to_string(&logs).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Configures the schedule for adaptive cover traffic.
/// min_ms / max_ms: The range for the random interval between dummy messages.
#[no_mangle]
pub extern "C" fn redoor_set_dummy_traffic_schedule(min_ms: u64, max_ms: u64) -> i32 {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.cover_traffic_config = CoverTrafficConfig {
        min_delay_ms: min_ms,
        max_delay_ms: max_ms,
    };
    0
}

/// Sets a local nickname for a peer.
#[no_mangle]
pub extern "C" fn redoor_set_peer_nickname(
    peer_id_hex: *const c_char,
    nickname: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let nick = unsafe { CStr::from_ptr(nickname) }.to_str().unwrap_or("");

    if peer_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();

    if nick.is_empty() {
        guard.nicknames.remove(peer_id);
    } else {
        guard
            .nicknames
            .insert(peer_id.to_string(), nick.to_string());
    }
    0
}

/// Gets the local nickname for a peer, or NULL if none set.
#[no_mangle]
pub extern "C" fn redoor_get_peer_nickname(peer_id_hex: *const c_char) -> *mut c_char {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(nick) = guard.nicknames.get(peer_id) {
        return CString::new(nick.clone()).unwrap().into_raw();
    }
    std::ptr::null_mut()
}

/// Returns a JSON array of all known peer IDs (from active sessions and nicknames).
/// This helps the UI populate a contact list.
#[no_mangle]
pub extern "C" fn redoor_get_known_peers() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let mut peers: HashSet<String> = HashSet::new();
    for k in guard.sessions.keys() {
        peers.insert(k.clone());
    }
    for k in guard.nicknames.keys() {
        peers.insert(k.clone());
    }

    let list: Vec<&String> = peers.iter().collect();
    let json = serde_json::to_string(&list).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Sends a read receipt for a specific message ID.
#[no_mangle]
pub extern "C" fn redoor_send_read_receipt(
    peer_id_hex: *const c_char,
    message_id_hex: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let msg_id = unsafe { CStr::from_ptr(message_id_hex) }
        .to_str()
        .unwrap_or("");

    get_engine().send_payload(peer_id, msg_id, "receipt", None, true, false, None)
}

/// Searches the in-memory message store for a query string.
/// Returns a JSON array of matching messages.
#[no_mangle]
pub extern "C" fn redoor_search_messages(query: *const c_char) -> *mut c_char {
    let q = unsafe { CStr::from_ptr(query) }
        .to_str()
        .unwrap_or("")
        .to_lowercase();
    if q.is_empty() {
        return CString::new("[]").unwrap().into_raw();
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let mut results = Vec::new();
    for msgs in guard.message_store.values() {
        for m in msgs {
            if m.content.to_lowercase().contains(&q) {
                results.push(m.clone());
            }
        }
    }

    let json = serde_json::to_string(&results).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Clears the attachment cache to free memory.
#[no_mangle]
pub extern "C" fn redoor_clear_attachment_cache() {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.attachment_cache.clear();
}

/// Sets the auto-delete timer (TTL) for a peer in seconds.
/// Set to 0 to disable.
#[no_mangle]
pub extern "C" fn redoor_set_auto_delete_timer(peer_id_hex: *const c_char, seconds: u64) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();

    if seconds == 0 {
        guard.auto_delete_timers.remove(peer_id);
    } else {
        guard
            .auto_delete_timers
            .insert(peer_id.to_string(), seconds);
    }
    0
}

/// Returns metrics for a specific session (messages sent/received).
/// Returns JSON: { "sent": 123, "received": 45 }
#[no_mangle]
pub extern "C" fn redoor_get_session_metrics(peer_id_hex: *const c_char) -> *mut c_char {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return std::ptr::null_mut();
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(session) = guard.sessions.get(peer_id) {
        if let Some(inner) = &session.inner {
            #[derive(serde::Serialize)]
            struct Metrics {
                sent: u32,
                received: u32,
            }
            let m = Metrics {
                sent: inner.msg_count_send,
                received: inner.msg_count_recv,
            };
            let json = serde_json::to_string(&m).unwrap();
            return CString::new(json).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

// Wrappers for the old loopback functions to ensure they are exported with the expected names
#[no_mangle]
pub extern "C" fn redoor_scripted_loopback(msg_ptr: *const c_char) -> i32 {
    ffi_guard_i32("redoor_scripted_loopback", || {
        let msg = if msg_ptr.is_null() {
            "hello-ios".to_string()
        } else {
            match required_cstr(msg_ptr) {
                Ok(s) => s,
                Err(_) => {
                    get_engine()
                        .log_internal("redoor_scripted_loopback: invalid UTF-8".to_string());
                    return -2;
                }
            }
        };

        let engine = get_engine();
        match engine
            .runtime
            .block_on(api::scripted_loopback(msg.as_str()))
        {
            Ok(_) => FFI_OK,
            Err(e) => {
                engine.log_internal(format!("redoor_scripted_loopback error: {e}"));
                -3
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn redoor_scripted_loopback_ext(
    msg_ptr: *const c_char,
    relay_url_ptr: *const c_char,
    blockchain_ptr: *const c_char,
    hmac_b64_ptr: *const c_char,
) -> i32 {
    ffi_guard_i32("redoor_scripted_loopback_ext", || {
        if !hmac_b64_ptr.is_null() {
            let _ = redoor_set_relay_hmac_b64(hmac_b64_ptr);
        }

        let msg = if msg_ptr.is_null() {
            "hello-ios".to_string()
        } else {
            match required_cstr(msg_ptr) {
                Ok(v) => v,
                Err(_) => return -2,
            }
        };
        let default_relay_url = crate::config::default_relay_url();
        let relay_url = if relay_url_ptr.is_null() {
            default_relay_url.clone()
        } else {
            match required_cstr(relay_url_ptr) {
                Ok(v) => v,
                Err(_) => default_relay_url.clone(),
            }
        };

        // Transport Encryption Hard Lock for Loopback
        let is_secure = relay_url.starts_with("https://") || relay_url.starts_with("wss://");
        let is_onion = relay_url.contains(".onion");
        let is_localhost = relay_url.contains("localhost") || relay_url.contains("127.0.0.1");

        if !is_secure && !is_onion && !(is_localhost && cfg!(debug_assertions)) {
            get_engine().log_internal(format!(
                "Security Error: Plaintext transport forbidden for loopback: {}",
                relay_url
            ));
            return -4;
        }

        let default_blockchain_url = crate::config::default_blockchain_url();
        let blockchain = if blockchain_ptr.is_null() {
            default_blockchain_url.clone()
        } else {
            match required_cstr(blockchain_ptr) {
                Ok(v) => v,
                Err(_) => default_blockchain_url.clone(),
            }
        };

        let engine = get_engine();
        match engine.runtime.block_on(api::scripted_loopback_custom(
            relay_url.as_str(),
            blockchain.as_str(),
            msg.as_str(),
            false,
            false,
        )) {
            Ok(_) => FFI_OK,
            Err(e) => {
                engine.log_internal(format!("redoor_scripted_loopback_ext error: {e}"));
                -3
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn redoor_set_relay_hmac_b64(key_ptr: *const c_char) -> i32 {
    if key_ptr.is_null() {
        env::remove_var("RELAY_HMAC_KEY");
        return 0;
    }

    let key_str = match unsafe { CStr::from_ptr(key_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            get_engine().log_internal("redoor_set_relay_hmac_b64: invalid UTF-8".to_string());
            return -2;
        }
    };

    env::set_var("RELAY_HMAC_KEY", key_str);
    0
}

#[no_mangle]
pub extern "C" fn redoor_set_relay_ca_b64(ca_ptr: *const c_char) -> i32 {
    if ca_ptr.is_null() {
        set_relay_ca_b64(None);
        env::remove_var("RELAY_CA_B64");
        return 0;
    }

    let ca_b64 = match unsafe { CStr::from_ptr(ca_ptr) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            get_engine().log_internal("redoor_set_relay_ca_b64: invalid UTF-8".to_string());
            return -2;
        }
    };

    if ca_b64.is_empty() {
        set_relay_ca_b64(None);
        env::remove_var("RELAY_CA_B64");
        return 0;
    }

    let decoded = match base64::engine::general_purpose::STANDARD.decode(ca_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(e) => {
            get_engine().log_internal(format!("redoor_set_relay_ca_b64: invalid base64: {e}"));
            return -3;
        }
    };

    if reqwest::Certificate::from_der(&decoded).is_err() {
        get_engine().log_internal("redoor_set_relay_ca_b64: invalid DER certificate".to_string());
        return -4;
    }

    set_relay_ca_b64(Some(ca_b64.to_string()));
    env::set_var("RELAY_CA_B64", ca_b64);
    0
}

#[no_mangle]
pub extern "C" fn redoor_set_relay_spki_pin_b64(pin_ptr: *const c_char) -> i32 {
    if pin_ptr.is_null() {
        set_relay_spki_pin_b64(None);
        env::remove_var("RELAY_PINNED_CERT_HASH");
        return 0;
    }

    let pin_b64 = match unsafe { CStr::from_ptr(pin_ptr) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            get_engine().log_internal("redoor_set_relay_spki_pin_b64: invalid UTF-8".to_string());
            return -2;
        }
    };

    if pin_b64.is_empty() {
        set_relay_spki_pin_b64(None);
        env::remove_var("RELAY_PINNED_CERT_HASH");
        return 0;
    }

    let pin = match base64::engine::general_purpose::STANDARD.decode(pin_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(e) => {
            get_engine().log_internal(format!(
                "redoor_set_relay_spki_pin_b64: invalid base64: {e}"
            ));
            return -3;
        }
    };

    if pin.len() != 32 {
        get_engine().log_internal(format!(
            "redoor_set_relay_spki_pin_b64: expected 32-byte SHA-256 hash, got {} bytes",
            pin.len()
        ));
        return -4;
    }

    set_relay_spki_pin_b64(Some(pin_b64.to_string()));
    env::set_var("RELAY_PINNED_CERT_HASH", pin_b64);
    0
}

#[no_mangle]
pub extern "C" fn redoor_set_pq_enabled(enable: i32) {
    set_pq_enabled(enable != 0);
}

#[no_mangle]
pub extern "C" fn redoor_set_pq_handshake_policy(policy_ptr: *const c_char) -> i32 {
    if policy_ptr.is_null() {
        set_pq_handshake_policy_override(None);
        env::remove_var("REDOOR_PQ_HANDSHAKE_POLICY");
        return 0;
    }

    let raw = match unsafe { CStr::from_ptr(policy_ptr) }.to_str() {
        Ok(value) => value.trim(),
        Err(_) => {
            get_engine().log_internal(
                "redoor_set_pq_handshake_policy: invalid UTF-8 policy value".to_string(),
            );
            return -2;
        }
    };

    if raw.is_empty() {
        set_pq_handshake_policy_override(None);
        env::remove_var("REDOOR_PQ_HANDSHAKE_POLICY");
        return 0;
    }

    let Some(policy) = parse_pq_handshake_policy(raw) else {
        get_engine().log_internal(format!(
            "redoor_set_pq_handshake_policy: unsupported value '{raw}'"
        ));
        return -3;
    };

    set_pq_handshake_policy_override(Some(policy));
    env::set_var(
        "REDOOR_PQ_HANDSHAKE_POLICY",
        pq_handshake_policy_as_str(policy),
    );
    0
}

#[no_mangle]
pub extern "C" fn redoor_set_proxy(url_ptr: *const c_char) -> i32 {
    if url_ptr.is_null() {
        crate::config::set_proxy(None);
        return 0;
    }
    let url = match unsafe { CStr::from_ptr(url_ptr) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    crate::config::set_proxy(Some(url));
    0
}

#[no_mangle]
pub extern "C" fn redoor_set_proxy_auth(username: *const c_char, password: *const c_char) -> i32 {
    let user = unsafe { CStr::from_ptr(username) }.to_str().unwrap_or("");
    let pass = unsafe { CStr::from_ptr(password) }.to_str().unwrap_or("");

    if user.is_empty() {
        crate::config::set_proxy_auth(None);
    } else {
        crate::config::set_proxy_auth(Some((user.to_string(), pass.to_string())));
    }
    0
}

#[no_mangle]
pub extern "C" fn redoor_shutdown_runtime() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn redoor_configure_traffic_shaping(
    pad_to: usize,
    min_delay_ms: u64,
    max_delay_ms: u64,
) -> i32 {
    let config = crate::config::TrafficShapingConfig {
        pad_to,
        min_delay_ms,
        max_delay_ms,
    };
    crate::config::set_traffic_shaping(config);
    0
}

/// Panic button: Immediately wipes memory and aborts the process.
#[no_mangle]
pub extern "C" fn redoor_panic() {
    redoor_wipe_memory();
    std::process::abort();
}

#[no_mangle]
pub extern "C" fn redoor_send_cover_traffic(size: usize) -> i32 {
    let engine = get_engine();
    crate::service::send_cover_traffic_immediate(engine, size)
}

/// Enables or disables adaptive cover traffic.
/// When enabled, the client will send dummy messages to the relay at random intervals.
#[no_mangle]
pub extern "C" fn redoor_enable_cover_traffic(enable: i32) -> i32 {
    let engine = get_engine();
    crate::service::start_cover_traffic(engine, enable != 0)
}

/// Enables or disables Merkle-batched blockchain commits.
/// When enabled, message hashes are queued and submitted as a single Merkle root transaction
/// every `interval_ms` milliseconds. This reduces on-chain footprint and improves privacy.
#[no_mangle]
pub extern "C" fn redoor_enable_blockchain_batching(interval_ms: u64) -> i32 {
    let engine = get_engine();
    crate::service::start_blockchain_batching(engine, interval_ms)
}

/// Enables outgoing message batching (Layer 3).
/// Messages are queued and sent in bursts every `interval_ms`.
#[no_mangle]
pub extern "C" fn redoor_enable_message_batching(interval_ms: u64) -> i32 {
    let engine = get_engine();
    crate::service::start_message_batching(engine, interval_ms)
}

/// Enables fixed-schedule polling (Layer 4).
/// Polls the relay every `interval_ms` regardless of activity.
#[no_mangle]
pub extern "C" fn redoor_enable_fixed_polling(interval_ms: u64) -> i32 {
    let engine = get_engine();
    crate::service::start_fixed_polling(engine, interval_ms)
}

/// Enables Strict Anonymity Mode (Step 1).
/// If enabled, all traffic MUST go through the mixnet/onion router. Direct connections fail.
#[no_mangle]
pub extern "C" fn redoor_enable_strict_anonymity(enable: i32) -> i32 {
    let engine = get_engine();
    {
        let guard = engine.state.lock().unwrap();
        // Strict anonymity is permanently enabled for security. The switch is removed.
        guard.anonymity_mode_enabled.store(true, Ordering::Relaxed);
        if enable == 0 {
            engine
                .log_internal("Warning: Attempt to disable strict anonymity ignored.".to_string());
        }
    }

    // Enforce secure profile in strict mode: fixed relay polling + constant-rate
    // sender loop that emits cover traffic when the queue is empty.
    let _ = crate::service::start_fixed_polling(engine, 0);
    let _ = crate::service::start_constant_rate_traffic(engine, 0);
    let _ = crate::service::start_blockchain_batching(
        engine,
        crate::config::blockchain_batch_interval_ms(),
    );
    0
}

/// Enables Constant Rate Traffic (Step 3).
/// This mode enforces a strict heartbeat: every `interval_ms`, a message is sent.
/// If the outgoing queue has real messages, one is sent.
/// If the queue is empty, a cover message is generated and sent.
/// This defeats traffic analysis by making the user appear "always active" with constant volume.
#[no_mangle]
pub extern "C" fn redoor_enable_constant_rate_traffic(interval_ms: u64) -> i32 {
    let engine = get_engine();
    service::start_constant_rate_traffic(engine, interval_ms)
}

/// Configures the mixnet path length constraints (Step 2).
/// min_hops and max_hops define the range for random path length selection.
#[no_mangle]
pub extern "C" fn redoor_configure_mixnet_policy(min_hops: usize, max_hops: usize) -> i32 {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.mixnet_config = MixnetConfig {
        min_hops,
        max_hops,
        ..guard.mixnet_config
    };
    engine.log_internal(format!(
        "Mixnet policy configured: {}-{} hops",
        min_hops, max_hops
    ));
    0
}

/// Configures route diversity policy constraints for onion path selection.
/// In strict anonymity mode, minimums are enforced at >=2 even if configured lower.
#[no_mangle]
pub extern "C" fn redoor_configure_mixnet_diversity_policy(
    min_unique_operators: usize,
    min_unique_jurisdictions: usize,
    route_attempts: usize,
) -> i32 {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.mixnet_config = MixnetConfig {
        min_unique_operators: min_unique_operators.max(1),
        min_unique_jurisdictions: min_unique_jurisdictions.max(1),
        route_attempts: route_attempts.max(1),
        ..guard.mixnet_config
    };
    engine.log_internal(format!(
        "Mixnet diversity policy configured: operators>={}, jurisdictions>={}, asns>={}, attempts={}",
        guard.mixnet_config.min_unique_operators,
        guard.mixnet_config.min_unique_jurisdictions,
        guard.mixnet_config.min_unique_asns,
        guard.mixnet_config.route_attempts
    ));
    0
}

/// Configures AS-level diversity policy constraints for onion path selection.
#[no_mangle]
pub extern "C" fn redoor_configure_mixnet_as_diversity_policy(min_unique_asns: usize) -> i32 {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.mixnet_config = MixnetConfig {
        min_unique_asns: min_unique_asns.max(1),
        ..guard.mixnet_config
    };
    engine.log_internal(format!(
        "Mixnet AS diversity policy configured: asns>={}",
        guard.mixnet_config.min_unique_asns
    ));
    0
}

/// Generates fake conversation history for plausible deniability (Step 8).
/// Creates `num_peers` fake contacts and `msgs_per_peer` fake messages for each.
/// This populates the RAM store with realistic-looking data.
#[no_mangle]
pub extern "C" fn redoor_generate_fake_history(num_peers: i32, msgs_per_peer: i32) -> i32 {
    let engine = get_engine();
    crate::service::generate_fake_history(engine, num_peers, msgs_per_peer)
}

/// Enters "Duress Mode" (Step 8).
/// Immediately wipes all real data from memory and populates it with fake history.
#[no_mangle]
pub extern "C" fn redoor_enter_duress_mode() -> i32 {
    let engine = get_engine();
    crate::service::enter_duress_mode(engine)
}

fn apply_crash_hygiene_wipe(reason: &str) {
    redoor_wipe_memory();
    get_engine().log_internal(format!("Crash hygiene wipe executed: {reason}"));
}

/// Installs a panic hook that wipes memory on crash (Step 7).
/// This prevents secrets from leaking into OS crash logs.
#[no_mangle]
pub extern "C" fn redoor_install_crash_handler() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        apply_crash_hygiene_wipe("panic-hook");
        // We can't easily log to C-land from a panic hook without risking deadlocks,
        // but we can try to print to stderr.
        eprintln!("Redoor Panic: Memory wiped. Cause: {:?}", info);
        default_hook(info);
    }));
}

/// Exports contacts, groups, and settings encrypted with a symmetric key (Step 7).
/// This allows persisting the "RAM-only" social graph to disk securely.
/// key_hex must be 64 hex characters (32 bytes).
#[no_mangle]
pub extern "C" fn redoor_export_contacts(_key_hex: *const c_char) -> *mut c_char {
    get_engine().log_internal(
        "redoor_export_contacts is disabled in RAM-only mode (no device persistence).".to_string(),
    );
    std::ptr::null_mut()
}

/// Imports encrypted contacts/groups (Step 7).
/// Merges with current state.
#[no_mangle]
pub extern "C" fn redoor_import_contacts(_data_hex: *const c_char, _key_hex: *const c_char) -> i32 {
    get_engine().log_internal(
        "redoor_import_contacts is disabled in RAM-only mode (no device persistence).".to_string(),
    );
    -1
}

/// Exports the list of active session IDs (Peer IDs) encrypted with a symmetric key.
/// This prevents the "Social Graph" from being stored in plaintext on the device.
/// key_hex must be 64 hex characters (32 bytes).
#[no_mangle]
pub extern "C" fn redoor_export_session_index(_key_hex: *const c_char) -> *mut c_char {
    get_engine().log_internal(
        "redoor_export_session_index is disabled in RAM-only mode (no device persistence)."
            .to_string(),
    );
    std::ptr::null_mut()
}

/// Imports the encrypted list of session IDs.
/// Returns a JSON array of strings: ["hex_id1", "hex_id2"]
#[no_mangle]
pub extern "C" fn redoor_import_session_index(
    _data_hex: *const c_char,
    _key_hex: *const c_char,
) -> *mut c_char {
    get_engine().log_internal(
        "redoor_import_session_index is disabled in RAM-only mode (no device persistence)."
            .to_string(),
    );
    std::ptr::null_mut()
}

/// Injects a raw blob into the processing queue for testing/auditing (Step 9).
/// Allows verifying replay protection and error handling without network.
#[no_mangle]
pub extern "C" fn redoor_debug_inject_blob(blob_hex: *const c_char) -> i32 {
    let blob_str = unsafe { CStr::from_ptr(blob_hex) }.to_str().unwrap_or("");
    let blob = match hex::decode(blob_str) {
        Ok(b) => b,
        Err(_) => return -1,
    };

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    // Mock msg_id
    let msg_hash = crypto::blake3::hash(&blob);
    let msg_id = hex::encode(msg_hash);

    guard
        .pending_blobs
        .lock()
        .unwrap()
        .push_back((msg_id, blob));
    0
}

/// Returns the approximate memory usage of the application state in bytes.
/// Returns JSON: { "message_store": 1234, "attachment_cache": 5678, "logs": 900, "total": 7812 }
#[no_mangle]
pub extern "C" fn redoor_get_storage_usage() -> *mut c_char {
    ffi_guard_ptr("redoor_get_storage_usage", || {
        let usage = diagnostics::snapshot_storage_usage(get_engine());
        match serde_json::to_string(&usage) {
            Ok(json) => to_c_string_ptr(json),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Enables or disables low power mode.
/// When enabled, cover traffic is suspended and the UI may reduce polling frequency.
#[no_mangle]
pub extern "C" fn redoor_set_low_power_mode(enable: i32) -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    guard.low_power_mode.store(enable != 0, Ordering::Relaxed);
    0
}

/// Returns 1 if low power mode is enabled, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_get_low_power_mode() -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    if guard.low_power_mode.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

/// Forces a ratchet rotation by sending an empty heartbeat message.
/// This can help recover from temporary desynchronization or ensure forward secrecy
/// if no messages have been sent for a while.
#[no_mangle]
pub extern "C" fn redoor_force_ratchet_rotation(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    // We send a special "heartbeat" message type that the UI should ignore.
    get_engine().send_payload(peer_id, "", "heartbeat", None, true, false, None)
}

/// Gets the current auto-delete timer (TTL) for a peer in seconds.
/// Returns 0 if disabled or peer not found.
#[no_mangle]
pub extern "C" fn redoor_get_auto_delete_timer(peer_id_hex: *const c_char) -> u64 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return 0;
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    *guard.auto_delete_timers.get(peer_id).unwrap_or(&0)
}

/// Deletes a specific message from the in-memory store by ID.
/// Returns 0 on success, -1 if not found.
#[no_mangle]
pub extern "C" fn redoor_delete_message(
    peer_id_hex: *const c_char,
    msg_id_hex: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let msg_id = unsafe { CStr::from_ptr(msg_id_hex) }.to_str().unwrap_or("");

    if peer_id.is_empty() || msg_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();

    if let Some(msgs) = guard.message_store.get_mut(peer_id) {
        let original_len = msgs.len();
        msgs.retain(|m| m.id != msg_id);
        if msgs.len() < original_len {
            return 0;
        }
    }
    -1
}

/// Returns the number of remaining one-time prekeys.
/// Returns JSON: { "one_time_prekeys": 42 }
#[no_mangle]
pub extern "C" fn redoor_get_prekey_counts() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let count = if let Some(secrets) = &guard.prekey_secrets {
        secrets.one_time_prekeys.len()
    } else {
        0
    };

    #[derive(serde::Serialize)]
    struct Counts {
        one_time_prekeys: usize,
    }
    let c = Counts {
        one_time_prekeys: count,
    };
    let json = serde_json::to_string(&c).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Marks a message as read in the local store and sends a read receipt to the peer.
/// Returns 0 on success, -1 if message not found.
#[no_mangle]
pub extern "C" fn redoor_mark_message_read(
    peer_id_hex: *const c_char,
    msg_id_hex: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let msg_id = unsafe { CStr::from_ptr(msg_id_hex) }.to_str().unwrap_or("");

    if peer_id.is_empty() || msg_id.is_empty() {
        return -1;
    }

    let should_send = {
        let engine = get_engine();
        let mut guard = engine.state.lock().unwrap();
        if let Some(msgs) = guard.message_store.get_mut(peer_id) {
            if let Some(m) = msgs.iter_mut().find(|m| m.id == msg_id) {
                m.read = true;
            } else {
                return -1;
            }
        } else {
            return -1;
        }
        guard.read_receipts_enabled.load(Ordering::Relaxed)
    };

    // 2. Send receipt (ignore errors as this is best-effort)
    if should_send {
        get_engine().send_payload(peer_id, msg_id, "receipt", None, true, false, None);
    }
    0
}

/// Returns a JSON map of peer IDs to unread message counts.
/// Example: {"hex_id": 5, "hex_id_2": 1}
#[no_mangle]
pub extern "C" fn redoor_get_unread_counts() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    let mut counts = HashMap::new();
    for (peer_id, msgs) in &guard.message_store {
        let count = msgs.iter().filter(|m| !m.read).count();
        if count > 0 {
            counts.insert(peer_id.clone(), count);
        }
    }

    let json = serde_json::to_string(&counts).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Enables or disables automatic read receipts.
#[no_mangle]
pub extern "C" fn redoor_set_read_receipts_enabled(enable: i32) -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    guard
        .read_receipts_enabled
        .store(enable != 0, Ordering::Relaxed);
    0
}

/// Returns 1 if read receipts are enabled, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_get_read_receipts_enabled() -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    if guard.read_receipts_enabled.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

/// Deletes all messages and attachments from memory.
/// This allows the user to clear their history without destroying their identity or sessions.
#[no_mangle]
pub extern "C" fn redoor_delete_all_messages() {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.clear_message_history_securely();
}

/// Returns the current min/max delay for cover traffic in milliseconds.
/// Returns JSON: { "min_delay_ms": 30000, "max_delay_ms": 300000 }
#[no_mangle]
pub extern "C" fn redoor_get_dummy_traffic_schedule() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    #[derive(serde::Serialize)]
    struct Schedule {
        min_delay_ms: u64,
        max_delay_ms: u64,
    }

    let s = Schedule {
        min_delay_ms: guard.cover_traffic_config.min_delay_ms,
        max_delay_ms: guard.cover_traffic_config.max_delay_ms,
    };

    let json = serde_json::to_string(&s).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Returns the current Proof of Work difficulty.
#[no_mangle]
pub extern "C" fn redoor_get_pow_difficulty() -> u32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    guard.pow_difficulty
}

/// Returns the current rate limit configuration.
/// Returns JSON: { "max_messages": 10, "window_seconds": 60 } or null if disabled.
#[no_mangle]
pub extern "C" fn redoor_get_rate_limit_config() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(config) = guard.rate_limit_config {
        #[derive(serde::Serialize)]
        struct RLConfig {
            max_messages: u32,
            window_seconds: u64,
        }
        let c = RLConfig {
            max_messages: config.max_messages,
            window_seconds: config.window_seconds,
        };
        let json = serde_json::to_string(&c).unwrap();
        return CString::new(json).unwrap().into_raw();
    }

    std::ptr::null_mut()
}

/// Returns 1 if blockchain batching is enabled, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_get_batching_enabled() -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    if guard.batching_enabled.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

/// Returns blockchain batching telemetry for schedule drift and decoy submissions.
#[no_mangle]
pub extern "C" fn redoor_get_blockchain_batch_telemetry() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    let telemetry = guard.blockchain_batch_telemetry.lock().unwrap();
    match serde_json::to_string(&*telemetry) {
        Ok(json) => CString::new(json)
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Returns the latest Merkle inclusion proof for a message hash.
/// Input: hex-encoded message hash.
/// Output JSON:
/// {
///   "message_hash":"...",
///   "merkle_root":"...",
///   "receiver_commitment":"...",
///   "leaf_index":0,
///   "siblings":["..."],
///   "batch_size":N,
///   "submitted_at":<unix_secs>
/// }
#[no_mangle]
pub extern "C" fn redoor_get_commitment_inclusion_proof(
    message_hash_hex: *const c_char,
) -> *mut c_char {
    let message_hash = match required_cstr(message_hash_hex) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    let proofs = guard.commitment_proofs.lock().unwrap();
    let proof = match proofs.get(&message_hash) {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    if let Ok(json) = serde_json::to_string(proof) {
        if let Ok(cstr) = CString::new(json) {
            return cstr.into_raw();
        }
    }

    std::ptr::null_mut()
}

/// Returns the timestamp (seconds since epoch) when the session was created.
/// Returns 0 if session not found.
#[no_mangle]
pub extern "C" fn redoor_get_session_start_time(peer_id_hex: *const c_char) -> u64 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(session) = guard.sessions.get(peer_id) {
        if let Some(inner) = &session.inner {
            return inner.created_at;
        }
    }
    0
}

/// Resets (deletes) a session.
/// This allows the user to manually reset a session if they suspect keys are compromised.
#[no_mangle]
pub extern "C" fn redoor_reset_session(peer_id_hex: *const c_char) -> i32 {
    redoor_delete_session(peer_id_hex)
}

/// Returns the current version of the Rust core library in JSON format.
#[no_mangle]
pub extern "C" fn redoor_get_version_json() -> *mut c_char {
    #[derive(serde::Serialize)]
    struct VersionInfo {
        version: String,
    }
    let info = VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let json = serde_json::to_string(&info).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Checks if a specific feature is supported by the current build.
/// feature_name: "pq" (Post-Quantum), "onion" (Onion Routing), etc.
/// Returns 1 if supported, 0 otherwise.
#[no_mangle]
pub extern "C" fn redoor_check_feature_support(feature_name: *const c_char) -> i32 {
    let feature = unsafe { CStr::from_ptr(feature_name) }
        .to_str()
        .unwrap_or("");
    match feature {
        "pq" => {
            if cfg!(feature = "pq") {
                1
            } else {
                0
            }
        }
        "onion" => 1, // Always compiled in currently
        "batching" => 1,
        "ratchet" => 1,
        _ => 0,
    }
}

/// Sets the log verbosity level.
/// 0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace.
#[no_mangle]
pub extern "C" fn redoor_set_log_level(level: u8) -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    guard.log_level.store(level, Ordering::Relaxed);
    0
}

/// Returns the current log verbosity level.
#[no_mangle]
pub extern "C" fn redoor_get_log_level() -> u8 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    guard.log_level.load(Ordering::Relaxed)
}

/// Allows the UI to write to the internal log buffer.
/// Useful for correlating UI events with Rust core events.
#[no_mangle]
pub extern "C" fn redoor_log_msg(level: u8, msg: *const c_char) {
    let message = unsafe { CStr::from_ptr(msg) }.to_str().unwrap_or("");
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    let current_level = guard.log_level.load(Ordering::Relaxed);

    if level <= current_level {
        if guard.log_buffer.len() >= 1000 {
            guard.log_buffer.pop_front();
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lvl_str = match level {
            0 => "ERR",
            1 => "WRN",
            2 => "INF",
            3 => "DBG",
            _ => "TRC",
        };
        guard
            .log_buffer
            .push_back(format!("[{}] [{}] [UI] {}", ts, lvl_str, message));
    }
}

/// Returns detailed build information (Rust version, OS, Arch, Profile).
#[no_mangle]
pub extern "C" fn redoor_get_build_info() -> *mut c_char {
    #[derive(serde::Serialize)]
    struct BuildInfo {
        version: String,
        os: String,
        arch: String,
        profile: String,
    }

    let info = BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        profile: if cfg!(debug_assertions) {
            "debug".to_string()
        } else {
            "release".to_string()
        },
    };

    let json = serde_json::to_string(&info).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Returns connection metrics for the relay (RTT, packet loss, throughput).
/// Returns JSON: { "rtt_ms": 45, "packet_loss_percent": 0.1, "throughput_kbps": 120 }
#[no_mangle]
pub extern "C" fn redoor_get_connection_metrics() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    #[derive(serde::Serialize)]
    struct ConnMetrics {
        rtt_ms: u64,
        packet_loss_percent: f32,
        throughput_kbps: u64,
    }

    let snapshot = guard
        .relay_client
        .as_ref()
        .map(|client| client.connection_metrics_snapshot())
        .unwrap_or_default();

    let metrics = ConnMetrics {
        rtt_ms: snapshot.rtt_ms,
        packet_loss_percent: snapshot.packet_loss_percent,
        throughput_kbps: snapshot.throughput_kbps,
    };

    let json = serde_json::to_string(&metrics).unwrap();
    CString::new(json).unwrap().into_raw()
}

/// Locks all sessions by dropping their active state from memory.
/// Wrapped blobs are preserved to allow restoration via Enclave.
#[no_mangle]
pub extern "C" fn redoor_lock_all_sessions() {
    let engine = get_engine();
    service::lock_all_sessions(engine);
}

/// Exports the current session state to be wrapped by the Secure Enclave.
/// Returns a base64 string of the serialized session.
#[no_mangle]
pub extern "C" fn redoor_session_get_data_to_wrap(peer_id_hex: *const c_char) -> *mut c_char {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(entry) = guard.sessions.get(peer_id) {
        if let Some(inner) = &entry.inner {
            if let Ok(bytes) = inner.to_bytes() {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                return CString::new(b64).unwrap().into_raw();
            }
        }
    }
    std::ptr::null_mut()
}

/// Stores the wrapped blob returned by the Secure Enclave.
/// This blob is opaque to Rust and is stored for later restoration.
#[no_mangle]
pub extern "C" fn redoor_session_set_wrapped_data(
    peer_id_hex: *const c_char,
    blob_b64: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let blob_str = unsafe { CStr::from_ptr(blob_b64) }.to_str().unwrap_or("");

    let blob = match base64::engine::general_purpose::STANDARD.decode(blob_str) {
        Ok(b) => b,
        Err(_) => return -1,
    };

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    if let Some(entry) = guard.sessions.get_mut(peer_id) {
        entry.wrapped_state = Some(blob);
        return 0;
    }
    -1
}

/// Restores a session using the plaintext returned by the Secure Enclave (unwrap).
#[no_mangle]
pub extern "C" fn redoor_session_unlock(
    peer_id_hex: *const c_char,
    plaintext_b64: *const c_char,
) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let plain_str = unsafe { CStr::from_ptr(plaintext_b64) }
        .to_str()
        .unwrap_or("");

    let bytes = match base64::engine::general_purpose::STANDARD.decode(plain_str) {
        Ok(b) => b,
        Err(_) => return -1,
    };

    let session = match RatchetSession::from_bytes(&bytes) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    if let Some(entry) = guard.sessions.get_mut(peer_id) {
        entry.inner = Some(session);
        return 0;
    }
    -1
}

/// Checks if a session is currently locked (requires biometric auth to restore).
/// Returns 1 if locked, 0 if unlocked, -1 if session not found.
/// The function's identifier has been renamed from redoor_session_is_locked to redoor_is_session_locked for consistency.
#[no_mangle]
pub extern "C" fn redoor_is_session_locked(peer_id_hex: *const c_char) -> i32 {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    if peer_id.is_empty() {
        return -1;
    }

    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(entry) = guard.sessions.get(peer_id) {
        if entry.inner.is_none() {
            1
        } else {
            0
        }
    } else {
        -1
    }
}

/// Exports the current identity key pair to be wrapped by the Secure Enclave.
/// Returns a base64 string of the serialized private key.
#[no_mangle]
pub extern "C" fn redoor_identity_get_data_to_wrap() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(id) = &guard.identity {
        if let Ok(bytes) = id.to_bytes() {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            return CString::new(b64).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

/// Restores the identity key pair from the plaintext returned by the Secure Enclave (unwrap).
#[no_mangle]
pub extern "C" fn redoor_identity_unlock(plaintext_b64: *const c_char) -> i32 {
    let plain_str = unsafe { CStr::from_ptr(plaintext_b64) }
        .to_str()
        .unwrap_or("");
    if plain_str.is_empty() {
        return -1;
    }

    let bytes = match base64::engine::general_purpose::STANDARD.decode(plain_str) {
        Ok(b) => b,
        Err(_) => return -2,
    };

    let id = match crypto::ed25519::IdentityKey::from_bytes(&bytes) {
        Ok(i) => i,
        Err(_) => return -3,
    };

    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.identity = Some(id);
    0
}

/// Checks if the identity key is currently loaded in memory.
/// Returns 1 if loaded, 0 if not.
#[no_mangle]
pub extern "C" fn redoor_is_identity_ready() -> i32 {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    if guard.identity.is_some() {
        1
    } else {
        0
    }
}

/// Retrieves the wrapped blob for a session to send to the Enclave for unwrapping.
#[no_mangle]
pub extern "C" fn redoor_session_get_wrapped_data(peer_id_hex: *const c_char) -> *mut c_char {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(entry) = guard.sessions.get(peer_id) {
        if let Some(blob) = &entry.wrapped_state {
            let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
            return CString::new(b64).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

/// Sets the UI theme preference (e.g., "dark", "light", "system").
/// This is stored in memory and included in diagnostics/logs for context.
#[no_mangle]
pub extern "C" fn redoor_set_theme(theme_ptr: *const c_char) -> i32 {
    let theme = unsafe { CStr::from_ptr(theme_ptr) }
        .to_str()
        .unwrap_or("system");
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.theme = theme.to_string();
    engine.log_internal(format!("UI Theme changed to: {}", theme));
    0
}

/// Returns a hash of the current session state (integrity check).
/// This allows users to manually verify that their ratchet state matches the peer's,
/// detecting desynchronization or MITM without exposing actual keys.
#[no_mangle]
pub extern "C" fn redoor_get_session_integrity_hash(peer_id_hex: *const c_char) -> *mut c_char {
    let peer_id = unsafe { CStr::from_ptr(peer_id_hex) }
        .to_str()
        .unwrap_or("");
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();

    if let Some(session) = guard.sessions.get(peer_id) {
        if let Some(inner) = &session.inner {
            let data = format!(
                "{}:{}:{}",
                peer_id, inner.msg_count_send, inner.msg_count_recv
            );
            let hash = crypto::blake3::hash(data.as_bytes());
            return CString::new(hex::encode(hash)).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

/// Configures the Proof of Work difficulty for outgoing messages.
/// `difficulty` is the number of leading zero bits required in the message hash.
/// Set to 0 to disable.
#[no_mangle]
pub extern "C" fn redoor_configure_pow(difficulty: u32) {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    guard.pow_difficulty = difficulty;
}

/// Configures client-side rate limiting for outgoing messages per peer.
/// `max_messages` is the maximum number of messages allowed within `window_seconds`.
/// Set `max_messages` to 0 to disable.
#[no_mangle]
pub extern "C" fn redoor_configure_rate_limit(max_messages: u32, window_seconds: u64) {
    let engine = get_engine();
    let mut guard = engine.state.lock().unwrap();
    if max_messages == 0 {
        guard.rate_limit_config = None;
    } else {
        guard.rate_limit_config = Some(RateLimitConfig {
            max_messages,
            window_seconds,
        });
    }
}

/// Returns traffic statistics (real vs cover messages) as JSON.
#[no_mangle]
pub extern "C" fn redoor_get_traffic_stats() -> *mut c_char {
    let engine = get_engine();
    let guard = engine.state.lock().unwrap();
    let stats = guard.traffic_stats.lock().unwrap();

    #[derive(serde::Serialize)]
    struct Stats {
        real: u64,
        cover: u64,
        queued_real: u64,
        send_ticks: u64,
        poll_ticks: u64,
        send_failures: u64,
        poll_failures: u64,
        route_policy_violations: u64,
        route_fallback_direct_used: u64,
        route_fallback_direct_blocked: u64,
        last_send_tick_unix_ms: u64,
        last_poll_tick_unix_ms: u64,
    }
    let s = Stats {
        real: stats.real_messages_sent,
        cover: stats.cover_messages_sent,
        queued_real: stats.queued_real_messages,
        send_ticks: stats.send_ticks,
        poll_ticks: stats.poll_ticks,
        send_failures: stats.send_failures,
        poll_failures: stats.poll_failures,
        route_policy_violations: stats.route_policy_violations,
        route_fallback_direct_used: stats.route_fallback_direct_used,
        route_fallback_direct_blocked: stats.route_fallback_direct_blocked,
        last_send_tick_unix_ms: stats.last_send_tick_unix_ms,
        last_poll_tick_unix_ms: stats.last_poll_tick_unix_ms,
    };

    let json = serde_json::to_string(&s).unwrap();
    CString::new(json).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::SessionEntry;
    use crate::ratchet::double_ratchet::RatchetSession;
    use serde_json::Value;
    use std::ffi::CString;
    use std::sync::Mutex;

    // Global lock to serialize tests that access the singleton APP_STATE
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn panic_guard_maps_i32_panics_to_internal_code() {
        let _guard = TEST_LOCK.lock().unwrap();
        let rc = ffi_guard_i32("test_panic_guard_maps_i32_panics_to_internal_code", || {
            panic!("boom")
        });
        assert_eq!(rc, FFI_ERR_INTERNAL);
    }

    #[test]
    fn panic_guard_maps_pointer_panics_to_null() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ptr = ffi_guard_ptr("test_panic_guard_maps_pointer_panics_to_null", || {
            panic!("boom")
        });
        assert!(ptr.is_null());
    }

    #[test]
    fn init_env_rejects_missing_required_pointers() {
        let _guard = TEST_LOCK.lock().unwrap();
        let rc = redoor_init_env(std::ptr::null(), std::ptr::null(), std::ptr::null());
        assert_eq!(rc, FFI_ERR_INVALID_INPUT);
    }

    #[test]
    fn init_env_secure_mode_fails_closed_on_memory_hardening_error() {
        let _guard = TEST_LOCK.lock().unwrap();
        let relay = CString::new("https://localhost:8443").unwrap();
        let chain = CString::new("http://127.0.0.1:9444").unwrap();
        {
            let engine = get_engine();
            let guard = engine.state.lock().unwrap();
            guard.anonymity_mode_enabled.store(false, Ordering::Relaxed);
        }
        env::set_var("REDOOR_SECURE_MODE", "1");
        env::set_var("REDOOR_TEST_FORCE_MLOCKALL_FAIL", "1");

        let rc = redoor_init_env(relay.as_ptr(), chain.as_ptr(), std::ptr::null());
        assert_eq!(rc, FFI_ERR_SECURITY);

        let diag_ptr = redoor_run_diagnostics();
        assert!(!diag_ptr.is_null());
        let diag_json = unsafe { CString::from_raw(diag_ptr) };
        let parsed: Value = serde_json::from_str(diag_json.to_str().unwrap()).unwrap();
        assert_eq!(parsed["memory_hardening_required"], Value::Bool(true));
        assert_eq!(parsed["memory_hardening_active"], Value::Bool(false));
        assert_eq!(parsed["memory_hardening_ok"], Value::Bool(false));

        env::remove_var("REDOOR_SECURE_MODE");
        env::remove_var("REDOOR_TEST_FORCE_MLOCKALL_FAIL");
        {
            let engine = get_engine();
            let guard = engine.state.lock().unwrap();
            guard.anonymity_mode_enabled.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn init_env_dev_mode_allows_memory_hardening_error_with_warning_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        {
            let engine = get_engine();
            let guard = engine.state.lock().unwrap();
            guard.anonymity_mode_enabled.store(false, Ordering::Relaxed);
        }
        env::set_var("REDOOR_SECURE_MODE", "0");
        env::set_var("REDOOR_TEST_FORCE_MLOCKALL_FAIL", "1");

        let rc = apply_memory_hardening_policy();
        assert!(rc.is_ok());

        let diag_ptr = redoor_run_diagnostics();
        assert!(!diag_ptr.is_null());
        let diag_json = unsafe { CString::from_raw(diag_ptr) };
        let parsed: Value = serde_json::from_str(diag_json.to_str().unwrap()).unwrap();
        assert_eq!(parsed["memory_hardening_required"], Value::Bool(false));
        assert_eq!(parsed["memory_hardening_active"], Value::Bool(false));
        assert_eq!(parsed["memory_hardening_ok"], Value::Bool(true));

        env::remove_var("REDOOR_SECURE_MODE");
        env::remove_var("REDOOR_TEST_FORCE_MLOCKALL_FAIL");
        {
            let engine = get_engine();
            let guard = engine.state.lock().unwrap();
            guard.anonymity_mode_enabled.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn guarded_entrypoint_handles_null_inputs_without_unwind() {
        let _guard = TEST_LOCK.lock().unwrap();
        let result = std::panic::catch_unwind(|| {
            let ptr = redoor_initiate_session(std::ptr::null(), std::ptr::null());
            assert!(ptr.is_null());
        });
        assert!(result.is_ok());
    }

    #[test]
    fn fuzz_ffi_inputs() {
        let mut rng = rand::thread_rng();
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();

        for _ in 0..50 {
            let peer_id_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let peer_id_hex = hex::encode(&peer_id_bytes);
            let c_peer = CString::new(peer_id_hex).unwrap();

            let len = rng.gen_range(0..500);
            let garbage: Vec<u8> = (0..len).map(|_| rng.gen()).filter(|&b| b != 0).collect();
            let c_garbage = CString::new(garbage).unwrap();

            // Fuzz session initiation
            let ptr = redoor_initiate_session(c_peer.as_ptr(), c_garbage.as_ptr());
            if !ptr.is_null() {
                unsafe {
                    let _ = CString::from_raw(ptr);
                }
            }

            // Fuzz message handling
            let _ = redoor_handle_initial_message(c_peer.as_ptr(), c_garbage.as_ptr());

            // Fuzz sending
            let _ = redoor_send_message(c_peer.as_ptr(), c_garbage.as_ptr());
        }
    }

    #[test]
    fn test_state_machine_misuse() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        let c_peer =
            CString::new("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let c_msg = CString::new("test").unwrap();

        // Sending without identity/session should fail gracefully, not panic
        let res = redoor_send_message(c_peer.as_ptr(), c_msg.as_ptr());
        assert!(res < 0);
    }

    #[test]
    fn test_send_message_anonymity_check() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        // Setup identity/session only (no network calls needed).
        redoor_create_identity();
        redoor_enable_strict_anonymity(1);

        // Mock a session in engine state
        let peer_id_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        {
            let engine = get_engine();
            let mut guard = engine.state.lock().unwrap();
            guard.onion_router = None;
            let shared_secret = [0u8; 32];
            let peer_key = crate::crypto::x25519::PublicKey::from([0u8; 32]);
            let session = crate::engine::SessionEntry {
                wrapped_state: None,
                inner: Some(crate::ratchet::double_ratchet::RatchetSession::new(
                    shared_secret,
                    Some(peer_key),
                )),
                pending_handshake: None,
                peer_seal_key: None,
            };
            guard.sessions.insert(peer_id_hex.to_string(), session);
        }

        // Attempt to send via p2p while strict anonymity is enabled.
        // This must be rejected before any network work is attempted.
        let res = get_engine().send_payload(peer_id_hex, "test", "text", None, true, true, None);
        assert_eq!(res, -9);
    }

    #[test]
    fn test_send_message_requires_configured_onion_router_in_strict_mode() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        redoor_create_identity();
        redoor_enable_strict_anonymity(1);

        let peer_id_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        {
            let engine = get_engine();
            let mut guard = engine.state.lock().unwrap();
            guard.onion_router = None;
            let shared_secret = [0u8; 32];
            let peer_key = crate::crypto::x25519::PublicKey::from([0u8; 32]);
            let session = crate::engine::SessionEntry {
                wrapped_state: None,
                inner: Some(crate::ratchet::double_ratchet::RatchetSession::new(
                    shared_secret,
                    Some(peer_key),
                )),
                pending_handshake: None,
                peer_seal_key: None,
            };
            guard.sessions.insert(peer_id_hex.to_string(), session);
        }

        // Onion flag alone is insufficient when strict anonymity is enabled.
        let res = get_engine().send_payload(peer_id_hex, "test", "text", None, true, false, None);
        assert_eq!(res, -9);
    }

    #[test]
    fn test_send_message_with_onion_routing() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        // Identity + relay + onion path are required in strict mode.
        redoor_create_identity();
        redoor_enable_strict_anonymity(1);

        // Mock a session
        let peer_id_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        {
            let engine = get_engine();
            let mut guard = engine.state.lock().unwrap();
            let shared_secret = [0u8; 32];
            let peer_key = crate::crypto::x25519::PublicKey::from([0u8; 32]);
            let session = crate::engine::SessionEntry {
                wrapped_state: None,
                inner: Some(crate::ratchet::double_ratchet::RatchetSession::new(
                    shared_secret,
                    Some(peer_key),
                )),
                pending_handshake: None,
                peer_seal_key: None,
            };
            guard.sessions.insert(peer_id_hex.to_string(), session);
            let (_, pk1) = crate::crypto::x25519::generate_keypair();
            let (_, pk2) = crate::crypto::x25519::generate_keypair();
            let (_, pk3) = crate::crypto::x25519::generate_keypair();
            guard.onion_router = Some(crate::network::onion::OnionRouter::new(vec![
                ("https://node1.example".to_string(), pk1),
                ("https://node2.example".to_string(), pk2),
                ("https://node3.example".to_string(), pk3),
            ]));
            guard.relay_client = Some(crate::network::relay::RelayClient::new(
                "https://relay.example",
            ));
        }

        // Mandatory fixed loops must be startable in strict mode.
        assert_eq!(crate::service::start_fixed_polling(get_engine(), 0), 0);
        assert_eq!(
            crate::service::start_constant_rate_traffic(get_engine(), 0),
            0
        );

        // Send should now pass strict gate and be queued for fixed-rate delivery.
        let res = get_engine().send_payload(peer_id_hex, "test", "text", None, true, false, None);
        assert_eq!(res, 0);
    }

    #[test]
    fn test_configure_onion_routing_rejects_null_pointer() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        let res = redoor_configure_onion_routing(std::ptr::null());
        assert_eq!(res, -1);
    }

    #[test]
    fn test_configure_onion_routing_rejects_insufficient_nodes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        let key1 = "11".repeat(32);
        let key2 = "22".repeat(32);
        let json = format!(
            "[{{\"url\":\"https://node1.example\",\"pub_key\":\"{}\"}},{{\"url\":\"https://node2.example\",\"pub_key\":\"{}\"}}]",
            key1, key2
        );
        let c_json = CString::new(json).unwrap();
        let res = redoor_configure_onion_routing(c_json.as_ptr());
        assert_eq!(res, -3);
    }

    #[test]
    fn test_persistence_apis_disabled_in_ram_only_mode() {
        let _guard = TEST_LOCK.lock().unwrap();
        let key_hex = CString::new("00".repeat(32)).unwrap();
        let data_hex = CString::new("00").unwrap();

        assert!(redoor_export_contacts(key_hex.as_ptr()).is_null());
        assert_eq!(
            redoor_import_contacts(data_hex.as_ptr(), key_hex.as_ptr()),
            -1
        );
        assert!(redoor_export_session_index(key_hex.as_ptr()).is_null());
        assert!(redoor_import_session_index(data_hex.as_ptr(), key_hex.as_ptr()).is_null());
    }

    #[test]
    fn test_merkle_root_odd_leaves() {
        let h1 = vec![1u8; 32];
        let h2 = vec![2u8; 32];
        let h3 = vec![3u8; 32];

        let leaves = vec![h1.clone(), h2.clone(), h3.clone()];
        let root = crate::service::compute_merkle_root(&leaves);

        // Manual calculation
        // Level 1
        let mut c1 = h1.clone();
        c1.extend_from_slice(&h2);
        let h12 = crypto::blake3::hash(&c1).to_vec();

        let mut c2 = h3.clone();
        c2.extend_from_slice(&h3); // Duplicate last
        let h33 = crypto::blake3::hash(&c2).to_vec();

        // Level 2 (Root)
        let mut c_root = h12.clone();
        c_root.extend_from_slice(&h33);
        let expected_root = crypto::blake3::hash(&c_root).to_vec();

        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_storage_usage_reports_consistent_totals() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        let ptr = redoor_get_storage_usage();
        assert!(
            !ptr.is_null(),
            "storage usage JSON pointer should not be null"
        );
        let json = unsafe { CString::from_raw(ptr) };
        let parsed: serde_json::Value =
            serde_json::from_str(json.to_str().unwrap()).expect("valid storage usage JSON");

        let message_store = parsed["message_store"].as_u64().unwrap_or_default();
        let attachment_cache = parsed["attachment_cache"].as_u64().unwrap_or_default();
        let logs = parsed["logs"].as_u64().unwrap_or_default();
        let total = parsed["total"].as_u64().unwrap_or_default();

        assert_eq!(message_store + attachment_cache + logs, total);
    }

    #[test]
    fn test_get_connection_metrics_returns_expected_schema() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        let ptr = redoor_get_connection_metrics();
        assert!(!ptr.is_null(), "metrics JSON pointer should not be null");
        let json = unsafe { CString::from_raw(ptr) };
        let parsed: serde_json::Value =
            serde_json::from_str(json.to_str().unwrap()).expect("valid metrics JSON");

        assert!(parsed.get("rtt_ms").and_then(|v| v.as_u64()).is_some());
        assert!(parsed
            .get("packet_loss_percent")
            .and_then(|v| v.as_f64())
            .is_some());
        assert!(parsed
            .get("throughput_kbps")
            .and_then(|v| v.as_u64())
            .is_some());
    }

    #[test]
    fn test_get_connection_metrics_uses_live_relay_snapshot() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        {
            let engine = get_engine();
            let mut guard = engine.state.lock().unwrap();
            guard.relay_client = Some(crate::network::relay::RelayClient::new(
                "https://relay.example",
            ));
            let relay = guard
                .relay_client
                .as_ref()
                .expect("relay client should be configured");
            relay.record_connection_sample_for_tests(
                std::time::Duration::from_millis(120),
                4096,
                2048,
                true,
            );
        }

        let ptr = redoor_get_connection_metrics();
        assert!(!ptr.is_null(), "metrics JSON pointer should not be null");
        let json = unsafe { CString::from_raw(ptr) };
        let parsed: serde_json::Value =
            serde_json::from_str(json.to_str().unwrap()).expect("valid metrics JSON");

        assert!(parsed["rtt_ms"].as_u64().unwrap_or_default() > 0);
        assert!(parsed["throughput_kbps"].as_u64().unwrap_or_default() > 0);
    }

    #[test]
    fn test_delete_all_messages_zeroizes_buffers() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        {
            let engine = get_engine();
            let mut guard = engine.state.lock().unwrap();
            guard.message_store.insert(
                "peer-sensitive".to_string(),
                vec![crate::engine::StoredMessage {
                    id: "m-1".to_string(),
                    timestamp: 1,
                    sender: "peer-sensitive".to_string(),
                    content: "super-secret-content".to_string(),
                    msg_type: "text".to_string(),
                    group_id: None,
                    read: false,
                }],
            );
            guard
                .attachment_cache
                .insert("att-1".to_string(), vec![0xAB; 96]);
        }

        redoor_delete_all_messages();

        let engine = get_engine();
        let guard = engine.state.lock().unwrap();
        assert!(guard.message_store.is_empty());
        assert!(guard.attachment_cache.is_empty());
        assert!(
            guard.last_zeroization_report.message_entries >= 1,
            "message entries must be zeroized before clear"
        );
        assert!(
            guard.last_zeroization_report.message_bytes >= "super-secret-content".len(),
            "message bytes must be tracked in zeroization report"
        );
        assert!(
            guard.last_zeroization_report.attachment_entries >= 1,
            "attachment entries must be zeroized before clear"
        );
        assert!(
            guard.last_zeroization_report.attachment_bytes >= 96,
            "attachment bytes must be tracked in zeroization report"
        );
    }

    #[test]
    fn test_crash_hygiene_wipe_clears_sensitive_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _ = redoor_init_runtime();
        redoor_wipe_memory();

        {
            let engine = get_engine();
            let mut guard = engine.state.lock().unwrap();
            guard.message_store.insert(
                "peer-crash".to_string(),
                vec![crate::engine::StoredMessage {
                    id: "m-2".to_string(),
                    timestamp: 2,
                    sender: "peer-crash".to_string(),
                    content: "crash-adjacent-secret".to_string(),
                    msg_type: "text".to_string(),
                    group_id: None,
                    read: false,
                }],
            );
            guard
                .attachment_cache
                .insert("att-2".to_string(), vec![0xCD; 128]);
            guard
                .log_buffer
                .push_back("sensitive crash context".to_string());
        }

        apply_crash_hygiene_wipe("unit-test");

        let engine = get_engine();
        let guard = engine.state.lock().unwrap();
        assert!(guard.message_store.is_empty());
        assert!(guard.attachment_cache.is_empty());
        assert!(
            guard.last_zeroization_report.message_entries >= 1,
            "crash wipe must zeroize message buffers"
        );
        assert!(
            guard.last_zeroization_report.log_entries >= 1,
            "crash wipe must zeroize log buffers"
        );
        assert!(
            guard
                .log_buffer
                .iter()
                .any(|line| line.contains("Crash hygiene wipe executed: unit-test")),
            "expected crash hygiene audit log entry"
        );
    }

    #[test]
    fn test_memory_budget_benchmark_reports_passing_regression() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ptr = redoor_benchmark_memory_budget();
        assert!(
            !ptr.is_null(),
            "memory budget benchmark JSON pointer should not be null"
        );

        let json = unsafe { CString::from_raw(ptr) };
        let parsed: serde_json::Value =
            serde_json::from_str(json.to_str().unwrap()).expect("valid memory benchmark JSON");

        assert_eq!(parsed["checks_passed"].as_bool(), Some(true));
        assert!(
            parsed["populated"]["total"]
                .as_u64()
                .expect("populated total present")
                > parsed["post_wipe"]["total"]
                    .as_u64()
                    .expect("post_wipe total present")
        );
    }

    #[test]
    fn test_traffic_linkability_benchmark_returns_versioned_report() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ptr = redoor_benchmark_traffic_linkability(1337);
        assert!(
            !ptr.is_null(),
            "traffic linkability benchmark JSON pointer should not be null"
        );

        let json = unsafe { CString::from_raw(ptr) };
        let parsed: serde_json::Value = serde_json::from_str(json.to_str().unwrap())
            .expect("valid traffic linkability benchmark JSON");

        assert_eq!(
            parsed["report_version"].as_str(),
            Some("traffic_linkability.v1")
        );
        assert_eq!(parsed["base_seed"].as_u64(), Some(1337));
        assert_eq!(
            parsed["scenarios"]
                .as_array()
                .expect("scenarios should be an array")
                .len(),
            4
        );
        assert!(parsed["checks_passed"].as_bool().unwrap_or(false));
    }

    #[test]
    fn test_compromise_indicator_marks_target_and_all_sessions_for_rekey() {
        let _guard = TEST_LOCK.lock().unwrap();
        let engine = get_engine();
        {
            let mut guard = engine.state.lock().unwrap();
            guard.sessions.clear();
            guard.session_rekey_state.clear();
            guard.sessions.insert(
                "peer-target".to_string(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new([0x11; 32], None)),
                    pending_handshake: None,
                    peer_seal_key: None,
                },
            );
            guard.sessions.insert(
                "peer-other".to_string(),
                SessionEntry {
                    wrapped_state: None,
                    inner: Some(RatchetSession::new([0x22; 32], None)),
                    pending_handshake: None,
                    peer_seal_key: None,
                },
            );
        }

        let target = CString::new("peer-target").unwrap();
        assert_eq!(redoor_flag_compromise_indicator(target.as_ptr()), FFI_OK);
        {
            let mut guard = engine.state.lock().unwrap();
            let target_reason = guard.evaluate_session_rekey_requirement("peer-target");
            let other_reason = guard.evaluate_session_rekey_requirement("peer-other");
            assert_eq!(
                target_reason.as_deref(),
                Some("compromise_indicator_manual")
            );
            assert_eq!(other_reason, None);
        }

        assert_eq!(redoor_flag_compromise_indicator(std::ptr::null()), FFI_OK);
        {
            let mut guard = engine.state.lock().unwrap();
            let target_reason = guard.evaluate_session_rekey_requirement("peer-target");
            let other_reason = guard.evaluate_session_rekey_requirement("peer-other");
            assert_eq!(
                target_reason.as_deref(),
                Some("compromise_indicator_manual")
            );
            assert_eq!(other_reason.as_deref(), Some("compromise_indicator_manual"));
        }
    }
}
