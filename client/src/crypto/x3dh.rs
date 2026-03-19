//! Implementation of the X3DH (Extended Triple Diffie-Hellman) key agreement protocol.

use crate::config::{self, PqHandshakePolicy};
use crate::crypto::ed25519::ToX25519;
#[cfg(feature = "pq")]
use crate::crypto::pq;
use crate::crypto::{ed25519, x25519};
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
#[cfg(feature = "pq")]
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertextTrait, PublicKey as PqPublicKeyTrait, SecretKey as PqSecretKeyTrait,
    SharedSecret as PqSharedSecretTrait,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const HANDSHAKE_MODE_CLASSIC: &str = "classic";
#[cfg(feature = "pq")]
const HANDSHAKE_MODE_HYBRID: &str = "hybrid_kyber1024";
const LEGACY_PROTOCOL_VERSION: u16 = 1;

/// A public prekey bundle that a user publishes to the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct PrekeyBundle {
    /// The user's long-term identity public key (Ed25519).
    pub identity_key: Vec<u8>,
    /// The user's signed prekey (X25519 public key).
    pub signed_prekey: Vec<u8>,
    /// The signature on the signed prekey, created with the identity key.
    pub prekey_signature: Vec<u8>,
    /// An optional one-time prekey (X25519 public key).
    pub one_time_prekey: Option<Vec<u8>>,
    /// An optional post-quantum public key (Kyber).
    #[cfg(feature = "pq")]
    #[serde(default)]
    pub pq_public_key: Option<Vec<u8>>,
}

/// The initial message sent from an initiator (Alice) to a responder (Bob).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct InitialMessage {
    /// Alice's identity public key (Ed25519).
    pub identity_key: Vec<u8>,
    /// Alice's ephemeral public key (X25519).
    pub ephemeral_key: Vec<u8>,
    /// The ID of the one-time prekey Bob should use (if any).
    pub one_time_prekey_id: Option<Vec<u8>>,
    /// The actual encrypted message.
    pub ciphertext: Vec<u8>,
    /// Negotiated handshake mode for downgrade detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_mode: Option<String>,
    /// Protocol version tag for transition and compatibility enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u16>,
    /// An optional post-quantum ciphertext (Kyber).
    #[cfg(feature = "pq")]
    #[serde(default)]
    pub pq_ciphertext: Option<Vec<u8>>,
}

fn handshake_context_info(
    mode: &str,
    one_time_prekey_used: bool,
    pq_used: bool,
    protocol_version: u16,
) -> Vec<u8> {
    format!(
        "X3DH-v3|mode={mode}|opk={}|pq={}|version={}",
        u8::from(one_time_prekey_used),
        u8::from(pq_used),
        protocol_version
    )
    .into_bytes()
}

/// A simple HKDF implementation using HMAC-SHA256, following RFC 5869.
/// This is a simplified version for our specific needs.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    // Step 1: Extract
    let mut hmac_salt =
        Hmac::<Sha256>::new_from_slice(salt).map_err(|_| anyhow!("HMAC init failed"))?;
    hmac_salt.update(ikm);
    let prk = hmac_salt.finalize().into_bytes();

    // Step 2: Expand
    let mut hmac_prk =
        Hmac::<Sha256>::new_from_slice(&prk).map_err(|_| anyhow!("HMAC init failed"))?;
    hmac_prk.update(info);
    hmac_prk.update(&[1]); // Counter
    let okm_bytes = hmac_prk.finalize().into_bytes();

    okm.copy_from_slice(&okm_bytes[..okm.len()]);

    Ok(())
}

/// Performs the initiator's side of the X3DH handshake.
///
/// This is a hybrid handshake if the `pq` feature is enabled and the peer
/// provides a post-quantum public key.
pub fn initiate_handshake(
    our_identity_key: &ed25519::IdentityKey,
    peer_bundle: &PrekeyBundle,
) -> Result<([u8; 32], InitialMessage)> {
    initiate_handshake_with_policy(
        our_identity_key,
        peer_bundle,
        config::pq_handshake_policy(),
        config::pq_enabled(),
    )
}

fn initiate_handshake_with_policy(
    our_identity_key: &ed25519::IdentityKey,
    peer_bundle: &PrekeyBundle,
    pq_policy: PqHandshakePolicy,
    pq_runtime_enabled: bool,
) -> Result<([u8; 32], InitialMessage)> {
    // 1. Verify peer's signed prekey
    let peer_ik_pub =
        ed25519::PublicKey::from_bytes(peer_bundle.identity_key.as_slice().try_into().unwrap())?;
    let signature = ed25519_dalek::Signature::from_bytes(
        peer_bundle.prekey_signature.as_slice().try_into().unwrap(),
    );
    peer_ik_pub.verify_strict(&peer_bundle.signed_prekey, &signature)?;

    // 2. Generate our ephemeral key
    let (our_ek_priv, our_ek_pub) = x25519::generate_keypair();

    // 3. Convert keys for DH operations
    let our_ik_priv_x = our_identity_key.to_x25519_private();
    let peer_spk_pub_x = PublicKey::from(
        TryInto::<[u8; 32]>::try_into(peer_bundle.signed_prekey.as_slice()).unwrap(),
    );
    let peer_ik_pub_x =
        ed25519::PublicKey::from_bytes(peer_bundle.identity_key.as_slice().try_into().unwrap())?
            .to_x25519_public()?;

    // 4. Perform classical DH calculations
    let dh1 = x25519::diffie_hellman(&our_ik_priv_x, &peer_spk_pub_x);
    let dh2 = x25519::diffie_hellman(&our_ek_priv, &peer_ik_pub_x);
    let dh3 = x25519::diffie_hellman(&our_ek_priv, &peer_spk_pub_x);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let mut one_time_prekey_id = None;

    if let Some(opk_bytes) = &peer_bundle.one_time_prekey {
        let peer_opk_pub_x =
            PublicKey::from(TryInto::<[u8; 32]>::try_into(opk_bytes.as_slice()).unwrap());
        let dh4 = x25519::diffie_hellman(&our_ek_priv, &peer_opk_pub_x);
        ikm.extend_from_slice(&dh4);
        one_time_prekey_id = Some(opk_bytes.clone());
    }

    let mut handshake_mode = HANDSHAKE_MODE_CLASSIC.to_string();
    let mut used_hybrid = false;

    // 5. Perform post-quantum KEM if available and allowed by policy
    let mut pq_ciphertext = None;
    #[cfg(feature = "pq")]
    {
        if pq_policy == PqHandshakePolicy::Required && !pq_runtime_enabled {
            return Err(anyhow!(
                "PQ handshake policy is required but REDOOR_PQ runtime toggle is disabled"
            ));
        }
        if pq_policy != PqHandshakePolicy::Disabled
            && pq_runtime_enabled
            && peer_bundle.pq_public_key.is_some()
        {
            let pq_pk_bytes = peer_bundle
                .pq_public_key
                .as_ref()
                .ok_or_else(|| anyhow!("missing peer post-quantum public key"))?;
            let pq_pk = pq::PqPublicKey::from_bytes(pq_pk_bytes)?;
            let (ct, ss) = pq::encapsulate(&pq_pk);
            ikm.extend_from_slice(ss.as_bytes());
            pq_ciphertext = Some(ct.as_bytes().to_vec());
            handshake_mode = HANDSHAKE_MODE_HYBRID.to_string();
            used_hybrid = true;
        }
        if pq_policy == PqHandshakePolicy::Required && pq_ciphertext.is_none() {
            return Err(anyhow!(
                "PQ handshake policy is required but peer bundle does not support hybrid handshake"
            ));
        }
    }
    #[cfg(not(feature = "pq"))]
    if pq_policy == PqHandshakePolicy::Required {
        return Err(anyhow!(
            "PQ handshake policy is required but binary was built without pq feature"
        ));
    }

    // 6. Derive the master secret
    let mut shared_secret = [0u8; 32];
    let protocol_version = config::protocol_version_current();
    let info = handshake_context_info(
        handshake_mode.as_str(),
        one_time_prekey_id.is_some(),
        used_hybrid,
        protocol_version,
    );
    hkdf(&[], &ikm, info.as_slice(), &mut shared_secret)?;

    // 7. Create the initial message
    let initial_message = InitialMessage {
        identity_key: our_identity_key.public_key_bytes().to_vec(),
        ephemeral_key: our_ek_pub.to_bytes().to_vec(),
        one_time_prekey_id,
        ciphertext: Vec::new(),
        handshake_mode: Some(handshake_mode),
        protocol_version: Some(protocol_version),
        #[cfg(feature = "pq")]
        pq_ciphertext,
    };

    // our_ek_priv.zeroize(); // StaticSecret zeroizes on drop

    Ok((shared_secret, initial_message))
}

/// Holds the private components of a user's prekey bundle.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PrekeySecrets {
    pub signed_prekey: StaticSecret,
    pub one_time_prekeys: Vec<StaticSecret>,
    /// Optional Kyber secret key bytes; bytes are zeroized on drop.
    pub pq_secret_key: Option<Vec<u8>>,
}

impl Clone for PrekeySecrets {
    fn clone(&self) -> Self {
        let signed_prekey = StaticSecret::from(self.signed_prekey.to_bytes());
        let one_time_prekeys = self
            .one_time_prekeys
            .iter()
            .map(|k| StaticSecret::from(k.to_bytes()))
            .collect();

        let pq_secret_key = self.pq_secret_key.clone();

        PrekeySecrets {
            signed_prekey,
            one_time_prekeys,
            pq_secret_key,
        }
    }
}

impl PrekeySecrets {
    pub fn generate() -> Self {
        let (spk_priv, _spk_pub) = x25519::generate_keypair();
        let (opk_priv, _opk_pub) = x25519::generate_keypair();

        #[cfg(feature = "pq")]
        let pq_secret_key = {
            let (_pk, sk) = pq::generate_pq_keypair();
            Some(sk.as_bytes().to_vec())
        };
        #[cfg(not(feature = "pq"))]
        let pq_secret_key = None;

        PrekeySecrets {
            signed_prekey: spk_priv,
            one_time_prekeys: vec![opk_priv],
            pq_secret_key,
        }
    }
}

/// Generates a fresh prekey bundle for a user.
pub fn generate_prekey_bundle(
    identity_key: &ed25519::IdentityKey,
) -> Result<(PrekeyBundle, PrekeySecrets)> {
    let (spk_priv, spk_pub) = x25519::generate_keypair();
    let spk_pub_bytes = spk_pub.to_bytes();
    let signature = identity_key.sign(&spk_pub_bytes);
    let (opk_priv, opk_pub) = x25519::generate_keypair();
    let opk_pub_bytes = opk_pub.to_bytes();

    #[cfg(feature = "pq")]
    let (pq_pub_key_bytes, pq_sec_key) = {
        let (pk, sk) = pq::generate_pq_keypair();
        (Some(pk.as_bytes().to_vec()), Some(sk.as_bytes().to_vec()))
    };
    #[cfg(not(feature = "pq"))]
    let (pq_pub_key_bytes, pq_sec_key): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);

    let public_bundle = PrekeyBundle {
        identity_key: identity_key.public_key_bytes().to_vec(),
        signed_prekey: spk_pub_bytes.to_vec(),
        prekey_signature: signature,
        one_time_prekey: Some(opk_pub_bytes.to_vec()),
        #[cfg(feature = "pq")]
        pq_public_key: pq_pub_key_bytes,
    };

    let secrets = PrekeySecrets {
        signed_prekey: spk_priv,
        one_time_prekeys: vec![opk_priv],
        #[cfg(feature = "pq")]
        pq_secret_key: pq_sec_key,
        #[cfg(not(feature = "pq"))]
        pq_secret_key: None,
    };

    Ok((public_bundle, secrets))
}

/// Performs the responder's side of the X3DH handshake.
pub fn respond_to_handshake(
    our_identity_key: &ed25519::IdentityKey,
    our_prekey_secrets: &mut PrekeySecrets,
    initial_message: &InitialMessage,
) -> Result<[u8; 32]> {
    respond_to_handshake_with_policy(
        our_identity_key,
        our_prekey_secrets,
        initial_message,
        config::pq_handshake_policy(),
        config::pq_enabled(),
    )
}

fn respond_to_handshake_with_policy(
    our_identity_key: &ed25519::IdentityKey,
    our_prekey_secrets: &mut PrekeySecrets,
    initial_message: &InitialMessage,
    pq_policy: PqHandshakePolicy,
    pq_runtime_enabled: bool,
) -> Result<[u8; 32]> {
    let protocol_version = initial_message
        .protocol_version
        .unwrap_or(LEGACY_PROTOCOL_VERSION);
    let min_version = config::protocol_min_accepted_version();
    let current_version = config::protocol_version_current();
    if protocol_version < min_version {
        return Err(anyhow!(
            "protocol version {} below minimum accepted version {}",
            protocol_version,
            min_version
        ));
    }
    if protocol_version > current_version {
        return Err(anyhow!(
            "protocol version {} exceeds current supported version {}",
            protocol_version,
            current_version
        ));
    }

    let negotiated_mode = initial_message
        .handshake_mode
        .as_deref()
        .unwrap_or_else(|| {
            #[cfg(feature = "pq")]
            {
                if initial_message.pq_ciphertext.is_some() {
                    HANDSHAKE_MODE_HYBRID
                } else {
                    HANDSHAKE_MODE_CLASSIC
                }
            }
            #[cfg(not(feature = "pq"))]
            {
                HANDSHAKE_MODE_CLASSIC
            }
        });
    match pq_policy {
        PqHandshakePolicy::Disabled if negotiated_mode != HANDSHAKE_MODE_CLASSIC => {
            return Err(anyhow!(
                "received non-classic handshake while PQ policy is disabled"
            ));
        }
        PqHandshakePolicy::Required => {
            #[cfg(feature = "pq")]
            {
                if !pq_runtime_enabled {
                    return Err(anyhow!(
                        "PQ handshake policy is required but REDOOR_PQ runtime toggle is disabled"
                    ));
                }
                if negotiated_mode != HANDSHAKE_MODE_HYBRID {
                    return Err(anyhow!(
                        "received non-hybrid handshake while PQ policy is required"
                    ));
                }
            }
            #[cfg(not(feature = "pq"))]
            {
                return Err(anyhow!(
                    "PQ handshake policy is required but binary was built without pq feature"
                ));
            }
        }
        _ => {}
    }
    if negotiated_mode != HANDSHAKE_MODE_CLASSIC && {
        #[cfg(feature = "pq")]
        {
            negotiated_mode != HANDSHAKE_MODE_HYBRID
        }
        #[cfg(not(feature = "pq"))]
        {
            false
        }
    } {
        return Err(anyhow!("unsupported handshake mode: {negotiated_mode}"));
    }

    let peer_ik_pub = ed25519::PublicKey::from_bytes(
        initial_message.identity_key.as_slice().try_into().unwrap(),
    )?;
    let peer_ek_pub = PublicKey::from(
        TryInto::<[u8; 32]>::try_into(initial_message.ephemeral_key.as_slice()).unwrap(),
    );
    let our_ik_priv_x = our_identity_key.to_x25519_private();
    let our_spk_priv = &our_prekey_secrets.signed_prekey;

    let dh1 = x25519::diffie_hellman(our_spk_priv, &peer_ik_pub.to_x25519_public()?);
    let dh2 = x25519::diffie_hellman(&our_ik_priv_x, &peer_ek_pub);
    let dh3 = x25519::diffie_hellman(our_spk_priv, &peer_ek_pub);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    let mut used_one_time_prekey = false;

    if let Some(opk_id) = &initial_message.one_time_prekey_id {
        if let Some(index) = our_prekey_secrets
            .one_time_prekeys
            .iter()
            .position(|k| PublicKey::from(k).as_bytes() == opk_id.as_slice())
        {
            let opk_priv = our_prekey_secrets.one_time_prekeys.remove(index);
            let dh4 = x25519::diffie_hellman(&opk_priv, &peer_ek_pub);
            ikm.extend_from_slice(&dh4);
            used_one_time_prekey = true;
            // opk_priv.zeroize(); // StaticSecret zeroizes on drop
        } else {
            return Err(anyhow!("one-time prekey id not found"));
        }
    }

    let mut used_hybrid = false;
    #[cfg(feature = "pq")]
    {
        if negotiated_mode == HANDSHAKE_MODE_HYBRID {
            let ct_bytes = initial_message
                .pq_ciphertext
                .as_ref()
                .ok_or_else(|| anyhow!("hybrid handshake missing pq ciphertext"))?;
            let sk_bytes = our_prekey_secrets
                .pq_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("hybrid handshake missing local pq secret key"))?;
            let ct = pq::PqCiphertext::from_bytes(ct_bytes)?;
            let sk = pq::PqSecretKey::from_bytes(sk_bytes)?;
            let ss = pq::decapsulate(&ct, &sk);
            ikm.extend_from_slice(ss.as_bytes());
            used_hybrid = true;
        } else if initial_message.pq_ciphertext.is_some() {
            return Err(anyhow!(
                "classic handshake mode cannot include pq ciphertext"
            ));
        }
    }
    #[cfg(not(feature = "pq"))]
    if negotiated_mode != HANDSHAKE_MODE_CLASSIC {
        return Err(anyhow!(
            "received non-classic handshake but binary was built without pq feature"
        ));
    }
    #[cfg(feature = "pq")]
    if pq_policy == PqHandshakePolicy::Disabled && used_hybrid {
        return Err(anyhow!(
            "received hybrid handshake while PQ policy is disabled"
        ));
    }
    #[cfg(feature = "pq")]
    if pq_policy == PqHandshakePolicy::Required && !used_hybrid {
        return Err(anyhow!(
            "received non-hybrid handshake while PQ policy is required"
        ));
    }

    let mut shared_secret = [0u8; 32];
    let info = handshake_context_info(
        negotiated_mode,
        used_one_time_prekey,
        used_hybrid,
        protocol_version,
    );
    hkdf(&[], &ikm, info.as_slice(), &mut shared_secret)?;

    // our_ik_priv_x.zeroize(); // StaticSecret zeroizes on drop

    Ok(shared_secret)
}

/// Rotates the signed prekey.
/// Returns (public_key, signature, private_key).
pub fn rotate_signed_prekey(
    identity_key: &ed25519::IdentityKey,
) -> Result<(Vec<u8>, Vec<u8>, StaticSecret)> {
    let (spk_priv, spk_pub) = x25519::generate_keypair();
    let spk_pub_bytes = spk_pub.to_bytes();
    let signature = identity_key.sign(&spk_pub_bytes);
    Ok((spk_pub_bytes.to_vec(), signature, spk_priv))
}

/// Generates a batch of one-time prekeys.
/// Returns (public_keys_bytes, private_keys).
pub fn generate_one_time_prekeys(count: usize) -> (Vec<Vec<u8>>, Vec<StaticSecret>) {
    let mut public_keys = Vec::with_capacity(count);
    let mut secrets = Vec::with_capacity(count);

    for _ in 0..count {
        let (priv_key, pub_key) = x25519::generate_keypair();
        public_keys.push(pub_key.to_bytes().to_vec());
        secrets.push(priv_key);
    }

    (public_keys, secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn initiate_handshake_policy_disabled_stays_classic() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, _secrets) = generate_prekey_bundle(&bob).expect("bundle");
        let (_secret, initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Disabled, true)
                .expect("init handshake");

        assert_eq!(
            initial.handshake_mode.as_deref(),
            Some(HANDSHAKE_MODE_CLASSIC)
        );
        #[cfg(feature = "pq")]
        assert!(
            initial.pq_ciphertext.is_none(),
            "disabled policy must not emit pq ciphertext"
        );
    }

    #[cfg(feature = "pq")]
    #[test]
    fn initiate_handshake_policy_required_rejects_non_pq_bundle() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (mut bundle, _secrets) = generate_prekey_bundle(&bob).expect("bundle");
        bundle.pq_public_key = None;

        let err =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Required, true)
                .expect_err("required policy should reject non-pq bundle");
        assert!(err.to_string().contains("required"));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn required_policy_hybrid_roundtrip_derives_same_secret() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, mut bob_secrets) = generate_prekey_bundle(&bob).expect("bundle");

        let (alice_secret, initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Required, true)
                .expect("init handshake");
        assert_eq!(
            initial.handshake_mode.as_deref(),
            Some(HANDSHAKE_MODE_HYBRID)
        );
        assert!(
            initial.pq_ciphertext.is_some(),
            "hybrid handshake must include pq ciphertext"
        );

        let bob_secret = respond_to_handshake_with_policy(
            &bob,
            &mut bob_secrets,
            &initial,
            PqHandshakePolicy::Required,
            true,
        )
        .expect("respond handshake");
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn responder_rejects_unknown_one_time_prekey_id() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, mut bob_secrets) = generate_prekey_bundle(&bob).expect("bundle");

        let (_alice_secret, mut initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Prefer, true)
                .expect("init handshake");
        initial.one_time_prekey_id = Some(vec![0x42; 32]);

        let err = respond_to_handshake_with_policy(
            &bob,
            &mut bob_secrets,
            &initial,
            PqHandshakePolicy::Prefer,
            true,
        )
        .expect_err("responder should reject unknown one-time prekey id");
        assert!(err.to_string().contains("one-time prekey id not found"));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn required_policy_rejects_downgraded_hybrid_message() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, mut bob_secrets) = generate_prekey_bundle(&bob).expect("bundle");

        let (_alice_secret, mut initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Required, true)
                .expect("hybrid initiation");
        initial.handshake_mode = Some(HANDSHAKE_MODE_CLASSIC.to_string());
        initial.pq_ciphertext = None;

        let err = respond_to_handshake_with_policy(
            &bob,
            &mut bob_secrets,
            &initial,
            PqHandshakePolicy::Required,
            true,
        )
        .expect_err("required policy must reject downgraded handshake");
        assert!(err.to_string().contains("required"));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn handshake_policy_matrix_interop() {
        let policies = [
            PqHandshakePolicy::Prefer,
            PqHandshakePolicy::Required,
            PqHandshakePolicy::Disabled,
        ];

        for initiator_policy in policies {
            for responder_policy in policies {
                for peer_supports_pq in [false, true] {
                    let alice = ed25519::IdentityKey::generate();
                    let bob = ed25519::IdentityKey::generate();
                    let (mut bundle, mut bob_secrets) =
                        generate_prekey_bundle(&bob).expect("bundle");

                    if !peer_supports_pq {
                        bundle.pq_public_key = None;
                        bob_secrets.pq_secret_key = None;
                    }

                    let initiated =
                        initiate_handshake_with_policy(&alice, &bundle, initiator_policy, true);
                    let initiator_should_succeed =
                        !matches!(initiator_policy, PqHandshakePolicy::Required)
                            || peer_supports_pq;
                    assert_eq!(
                        initiated.is_ok(),
                        initiator_should_succeed,
                        "initiator policy={initiator_policy:?} peer_supports_pq={peer_supports_pq}"
                    );

                    if let Ok((alice_secret, initial)) = initiated {
                        let mode = initial
                            .handshake_mode
                            .as_deref()
                            .unwrap_or(HANDSHAKE_MODE_CLASSIC);
                        let responder_should_succeed = match responder_policy {
                            PqHandshakePolicy::Prefer => true,
                            PqHandshakePolicy::Required => mode == HANDSHAKE_MODE_HYBRID,
                            PqHandshakePolicy::Disabled => mode == HANDSHAKE_MODE_CLASSIC,
                        };

                        let responded = respond_to_handshake_with_policy(
                            &bob,
                            &mut bob_secrets,
                            &initial,
                            responder_policy,
                            true,
                        );
                        assert_eq!(
                            responded.is_ok(),
                            responder_should_succeed,
                            "responder policy={responder_policy:?} mode={mode}"
                        );

                        if let Ok(bob_secret) = responded {
                            assert_eq!(
                                alice_secret, bob_secret,
                                "shared secret mismatch for policy pair {:?}/{:?} in mode {mode}",
                                initiator_policy, responder_policy
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn protocol_version_is_tagged_on_new_handshake() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, _secrets) = generate_prekey_bundle(&bob).expect("bundle");
        let (_secret, initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Prefer, true)
                .expect("init handshake");

        assert_eq!(
            initial.protocol_version,
            Some(config::protocol_version_current())
        );
    }

    #[test]
    fn responder_rejects_protocol_version_below_minimum() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, mut bob_secrets) = generate_prekey_bundle(&bob).expect("bundle");

        let (_alice_secret, mut initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Prefer, true)
                .expect("init handshake");
        initial.protocol_version = Some(1);

        config::set_protocol_version_override(Some(2));
        config::set_protocol_min_accepted_version_override(Some(2));
        let err = respond_to_handshake_with_policy(
            &bob,
            &mut bob_secrets,
            &initial,
            PqHandshakePolicy::Prefer,
            true,
        )
        .expect_err("protocol below minimum must be rejected");
        assert!(err.to_string().contains("below minimum"));
        config::set_protocol_version_override(None);
        config::set_protocol_min_accepted_version_override(None);
    }

    #[test]
    fn legacy_protocol_is_allowed_when_minimum_is_legacy() {
        let alice = ed25519::IdentityKey::generate();
        let bob = ed25519::IdentityKey::generate();
        let (bundle, mut bob_secrets) = generate_prekey_bundle(&bob).expect("bundle");

        // Simulate a true legacy sender by initiating while current protocol is v1.
        config::set_protocol_version_override(Some(1));
        config::set_protocol_min_accepted_version_override(Some(1));
        let (alice_secret, mut initial) =
            initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Prefer, true)
                .expect("init handshake");
        config::set_protocol_version_override(None);
        config::set_protocol_min_accepted_version_override(None);
        initial.protocol_version = None;

        config::set_protocol_version_override(Some(2));
        config::set_protocol_min_accepted_version_override(Some(1));
        let bob_secret = respond_to_handshake_with_policy(
            &bob,
            &mut bob_secrets,
            &initial,
            PqHandshakePolicy::Prefer,
            true,
        )
        .expect("legacy compatible handshake");
        assert_eq!(alice_secret, bob_secret);
        config::set_protocol_version_override(None);
        config::set_protocol_min_accepted_version_override(None);
    }

    #[test]
    fn protocol_version_interop_matrix_enforces_compatibility() {
        struct Case {
            name: &'static str,
            sender_version: u16,
            include_version_field: bool,
            receiver_current: u16,
            receiver_min: u16,
            expect_ok: bool,
        }

        let cases = [
            Case {
                name: "legacy_sender_accepted_when_minimum_allows",
                sender_version: 1,
                include_version_field: false,
                receiver_current: 2,
                receiver_min: 1,
                expect_ok: true,
            },
            Case {
                name: "current_sender_matches_current_receiver",
                sender_version: 2,
                include_version_field: true,
                receiver_current: 2,
                receiver_min: 1,
                expect_ok: true,
            },
            Case {
                name: "sender_above_receiver_current_is_rejected",
                sender_version: 2,
                include_version_field: true,
                receiver_current: 1,
                receiver_min: 1,
                expect_ok: false,
            },
            Case {
                name: "sender_below_receiver_minimum_is_rejected",
                sender_version: 1,
                include_version_field: true,
                receiver_current: 2,
                receiver_min: 2,
                expect_ok: false,
            },
        ];

        for case in cases {
            let alice = ed25519::IdentityKey::generate();
            let bob = ed25519::IdentityKey::generate();
            let (bundle, mut bob_secrets) = generate_prekey_bundle(&bob).expect("bundle");

            config::set_protocol_version_override(Some(case.sender_version));
            config::set_protocol_min_accepted_version_override(Some(1));
            let (alice_secret, mut initial) =
                initiate_handshake_with_policy(&alice, &bundle, PqHandshakePolicy::Prefer, true)
                    .expect("init handshake");
            if !case.include_version_field {
                initial.protocol_version = None;
            } else {
                initial.protocol_version = Some(case.sender_version);
            }

            config::set_protocol_version_override(Some(case.receiver_current));
            config::set_protocol_min_accepted_version_override(Some(case.receiver_min));
            let result = respond_to_handshake_with_policy(
                &bob,
                &mut bob_secrets,
                &initial,
                PqHandshakePolicy::Prefer,
                true,
            );

            assert_eq!(
                result.is_ok(),
                case.expect_ok,
                "protocol interop case failed: {}",
                case.name
            );
            if let Ok(bob_secret) = result {
                assert_eq!(
                    alice_secret, bob_secret,
                    "shared secret mismatch in case {}",
                    case.name
                );
            }

            config::set_protocol_version_override(None);
            config::set_protocol_min_accepted_version_override(None);
        }
    }
}
