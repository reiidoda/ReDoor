#![no_main]
use libfuzzer_sys::fuzz_target;
use redoor_client::crypto::{blake3, chacha20poly1305, ed25519};
use redoor_client::ratchet::double_ratchet::RatchetSession;

const HDR_LEN: usize = 4;
const SIG_LEN: usize = 64;

fn sig_matches(id: &ed25519::IdentityKey, msg: &[u8], sig: &[u8]) -> bool {
    let recomputed = id.sign(msg);
    recomputed.as_slice() == sig
}

#[derive(Clone)]
struct Envelope {
    header: [u8; HDR_LEN],
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

impl Envelope {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header.len() + self.ciphertext.len() + self.signature.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.signature);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Envelope> {
        if bytes.len() < HDR_LEN + SIG_LEN {
            return None;
        }
        let mut header = [0u8; HDR_LEN];
        header.copy_from_slice(&bytes[..HDR_LEN]);
        let sig_start = bytes.len().saturating_sub(SIG_LEN);
        let ciphertext = bytes[HDR_LEN..sig_start].to_vec();
        let signature = bytes[sig_start..].to_vec();
        Some(Envelope { header, ciphertext, signature })
    }
}

fuzz_target!(|data: &[u8]| {
    // Expect at least key material + payload
    if data.len() < 96 {
        return;
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data[..32]);
    let payload = &data[32..];

    // Derive a small header from payload (first 4 bytes or zeros)
    let mut hdr = [0u8; HDR_LEN];
    if payload.len() >= HDR_LEN {
        hdr.copy_from_slice(&payload[..HDR_LEN]);
    }

    // Build a ratchet session
    let mut sess = RatchetSession::new(secret, None);

    // Encrypt payload
    if let Ok(ct) = sess.ratchet_encrypt(payload) {
        debug_assert_ne!(ct.as_slice(), payload, "Ciphertext should differ from plaintext");
        // Sign header || ciphertext
        let id = ed25519::IdentityKey::generate();
        let mut signed_msg = Vec::with_capacity(hdr.len() + ct.len());
        signed_msg.extend_from_slice(&hdr);
        signed_msg.extend_from_slice(&ct);
        let sig = id.sign(&signed_msg);
        debug_assert!(sig_matches(&id, &signed_msg, &sig), "Signature should verify for original message");

        let env_struct = Envelope { header: hdr, ciphertext: ct.clone(), signature: sig.clone() };
        debug_assert!(ct.len() > 0, "Ciphertext should be non-empty");
        debug_assert!(sig.iter().any(|&b| b != 0), "Signature should not be all zeros");
        let orig_hash = blake3::hash(&env_struct.to_bytes());

        // Envelope serialization invariants and hash length
        let bytes_once = env_struct.to_bytes();
        let bytes_twice = env_struct.to_bytes();
        debug_assert_eq!(bytes_once, bytes_twice, "Envelope serialization should be deterministic");
        debug_assert_eq!(bytes_once.len(), hdr.len() + ct.len() + sig.len(), "Envelope byte length mismatch");
        debug_assert_eq!(orig_hash.as_bytes().len(), 32, "BLAKE3 default hash length should be 32 bytes");
        // Invariants linking envelope bytes with components
        debug_assert_eq!(HDR_LEN, hdr.len(), "HDR_LEN constant mismatch");
        debug_assert_eq!(SIG_LEN, sig.len(), "SIG_LEN constant mismatch");
        debug_assert_eq!(&bytes_once[..HDR_LEN], &hdr, "Envelope prefix should be header");
        debug_assert_eq!(&bytes_once[bytes_once.len()-SIG_LEN..], &sig[..], "Envelope suffix should be signature");
        debug_assert_eq!(&bytes_once[HDR_LEN..bytes_once.len()-SIG_LEN], &ct[..], "Envelope middle should be ciphertext");
        debug_assert_eq!(&signed_msg[..], &bytes_once[..bytes_once.len()-SIG_LEN], "Signed message should be envelope without signature");
        debug_assert_eq!(blake3::hash(&bytes_twice), orig_hash, "Hash should match bytes");

        // Minimal envelope (empty ciphertext) parse should succeed
        let mut min_env_bytes = Vec::with_capacity(HDR_LEN + SIG_LEN);
        min_env_bytes.extend_from_slice(&hdr);
        min_env_bytes.extend_from_slice(&sig);
        if let Some(parsed_min) = Envelope::from_bytes(&min_env_bytes) {
            debug_assert_eq!(parsed_min.header, hdr, "Parsed minimal header mismatch");
            debug_assert!(parsed_min.ciphertext.is_empty(), "Parsed minimal ciphertext should be empty");
            debug_assert_eq!(parsed_min.signature, sig, "Parsed minimal signature mismatch");
        } else {
            debug_assert!(false, "Parsing minimal envelope should succeed");
        }

        // Parsing truncated envelope should fail only if signature bytes are missing
        let min_env_len = HDR_LEN + SIG_LEN;
        if bytes_once.len() > min_env_len {
            let parsed_trunc_fail = Envelope::from_bytes(&bytes_once[..min_env_len - 1]);
            debug_assert!(parsed_trunc_fail.is_none(), "Parsing envelope missing signature bytes should fail");
        }

        // Parsing with one fewer ciphertext byte (but full signature) should still succeed
        if ct.len() > 0 {
            let mut bytes_ct_trunc = Vec::with_capacity(HDR_LEN + ct.len().saturating_sub(1) + SIG_LEN);
            bytes_ct_trunc.extend_from_slice(&hdr);
            bytes_ct_trunc.extend_from_slice(&ct[..ct.len()-1]);
            bytes_ct_trunc.extend_from_slice(&sig);
            if let Some(parsed_ct_trunc) = Envelope::from_bytes(&bytes_ct_trunc) {
                debug_assert_eq!(parsed_ct_trunc.header, hdr, "Parsed truncated-ciphertext header mismatch");
                debug_assert_eq!(parsed_ct_trunc.ciphertext, ct[..ct.len()-1], "Parsed truncated-ciphertext payload mismatch");
                debug_assert_eq!(parsed_ct_trunc.signature, sig, "Parsed truncated-ciphertext signature mismatch");
            } else {
                debug_assert!(false, "Parsing envelope with truncated ciphertext (but full signature) should succeed");
            }
        }

        // Parsing with one extra ciphertext byte (but same signature) should still succeed
        {
            let mut ct_ext = ct.clone();
            ct_ext.push(0u8);
            let mut bytes_ct_ext = Vec::with_capacity(HDR_LEN + ct_ext.len() + SIG_LEN);
            bytes_ct_ext.extend_from_slice(&hdr);
            bytes_ct_ext.extend_from_slice(&ct_ext);
            bytes_ct_ext.extend_from_slice(&sig);
            if let Some(parsed_ct_ext) = Envelope::from_bytes(&bytes_ct_ext) {
                debug_assert_eq!(parsed_ct_ext.header, hdr, "Parsed extended-ciphertext header mismatch");
                debug_assert_eq!(parsed_ct_ext.ciphertext, ct_ext, "Parsed extended-ciphertext payload mismatch");
                debug_assert_eq!(parsed_ct_ext.signature, sig, "Parsed extended-ciphertext signature mismatch");
            } else {
                debug_assert!(false, "Parsing envelope with extended ciphertext (but full signature) should succeed");
            }
        }

        // Signature determinism: signing the same message twice should yield the same signature
        let sig2 = id.sign(&signed_msg);
        debug_assert_eq!(sig, sig2, "Ed25519 should be deterministic for identical message/signing key");

        // Different keys must produce different signatures for the same message
        let id_other = ed25519::IdentityKey::generate();
        let sig_other = id_other.sign(&signed_msg);
        debug_assert_ne!(sig, sig_other, "Different keys must yield different signatures for the same message");

        // Envelope with different signature should differ in bytes and hash
        let env_other_sig = Envelope { header: hdr, ciphertext: ct.clone(), signature: sig_other.clone() };
        debug_assert_ne!(env_other_sig.to_bytes(), bytes_once, "Envelope bytes should differ with different signature");
        debug_assert_ne!(blake3::hash(&env_other_sig.to_bytes()), orig_hash, "Envelope hash should differ with different signature");

        // Decrypt back and assert equality when possible
        if let Ok(pt) = sess.ratchet_decrypt(&ct) {
            debug_assert_eq!(pt.as_slice(), payload, "Decrypted plaintext mismatch");

            // Replay should fail (message keys are single-use)
            let replay = sess.ratchet_decrypt(&ct);
            debug_assert!(replay.is_err(), "Replaying the same ciphertext should not decrypt twice");
        }

        // Truncation and extension tamper tests
        if ct.len() > 1 {
            let truncated = ct[..ct.len()-1].to_vec();
            let dec_trunc = sess.ratchet_decrypt(&truncated);
            debug_assert!(dec_trunc.is_err(), "Truncated ciphertext should not decrypt");
        }
        {
            let mut extended = ct.clone();
            extended.push(0u8);
            let dec_ext = sess.ratchet_decrypt(&extended);
            debug_assert!(dec_ext.is_err(), "Extended ciphertext should not decrypt");
        }

        // Tamper with ciphertext to ensure decryption fails
        if !ct.is_empty() {
            let mut tampered = ct.clone();
            tampered[0] ^= 0x01;
            let dec = sess.ratchet_decrypt(&tampered);
            debug_assert!(dec.is_err(), "Tampered ciphertext should not decrypt");

            // Signature must change when message changes
            let mut signed_msg_tampered = Vec::with_capacity(hdr.len() + tampered.len());
            signed_msg_tampered.extend_from_slice(&hdr);
            signed_msg_tampered.extend_from_slice(&tampered);
            let sig_tampered = id.sign(&signed_msg_tampered);
            debug_assert_eq!(sig_tampered.len(), SIG_LEN, "Tampered signature length should remain 64 bytes");
            debug_assert!(!sig_matches(&id, &signed_msg_tampered, &sig), "Original signature must not verify tampered message");
            debug_assert!(sig_matches(&id, &signed_msg_tampered, &sig_tampered), "Recomputed signature should verify tampered message");

            // Hash must change when envelope changes
            let env_tampered_struct = Envelope { header: hdr, ciphertext: tampered.clone(), signature: sig.clone() };
            let tam_hash = blake3::hash(&env_tampered_struct.to_bytes());
            debug_assert_ne!(tam_hash, orig_hash, "BLAKE3 hash should change for modified envelope");

            // Parse tampered envelope and validate fields
            if let Some(parsed_tam) = Envelope::from_bytes(&env_tampered_struct.to_bytes()) {
                debug_assert_eq!(parsed_tam.header, hdr, "Parsed tampered header mismatch");
                debug_assert_eq!(parsed_tam.ciphertext, tampered, "Parsed tampered ciphertext mismatch");
                debug_assert_eq!(parsed_tam.signature, sig, "Parsed tampered signature mismatch");
            } else {
                debug_assert!(false, "Parsing tampered envelope bytes should still succeed (structure-wise)");
            }

            // Also tamper the last byte if available
            if tampered.len() > 1 {
                let mut tampered_last = ct.clone();
                let last = tampered_last.len() - 1;
                tampered_last[last] ^= 0x80;
                let dec_last = sess.ratchet_decrypt(&tampered_last);
                debug_assert!(dec_last.is_err(), "Tampered (last byte) ciphertext should not decrypt");

                // Tamper at a pseudo-random index derived from payload
                if !payload.is_empty() {
                    let mut tampered_idx = ct.clone();
                    let idx = (payload[0] as usize) % tampered_idx.len();
                    tampered_idx[idx] ^= 0xFF;
                    let dec_idx = sess.ratchet_decrypt(&tampered_idx);
                    debug_assert!(dec_idx.is_err(), "Tampered (random index) ciphertext should not decrypt");
                    let mut signed_msg_idx = Vec::with_capacity(hdr.len() + tampered_idx.len());
                    signed_msg_idx.extend_from_slice(&hdr);
                    signed_msg_idx.extend_from_slice(&tampered_idx);
                    debug_assert!(!sig_matches(&id, &signed_msg_idx, &sig), "Original signature must not verify index-tampered message");
                }
            }
        }

        // Tamper with header and ensure signature/hash differ
        let mut hdr_tampered = hdr;
        hdr_tampered[0] ^= 0x01;
        let mut signed_msg_hdr_tampered = Vec::with_capacity(hdr_tampered.len() + ct.len());
        signed_msg_hdr_tampered.extend_from_slice(&hdr_tampered);
        signed_msg_hdr_tampered.extend_from_slice(&ct);
        let sig_hdr_tampered = id.sign(&signed_msg_hdr_tampered);
        debug_assert!(!sig_matches(&id, &signed_msg_hdr_tampered, &sig), "Original signature must not verify header-tampered message");
        debug_assert!(sig_matches(&id, &signed_msg_hdr_tampered, &sig_hdr_tampered), "Recomputed signature should verify header-tampered message");
        debug_assert_eq!(sig_hdr_tampered.len(), SIG_LEN, "Header-tampered signature length should be 64 bytes");
        debug_assert_ne!(hdr_tampered, hdr, "Tampered header should differ from original");
        debug_assert_ne!(sig_hdr_tampered, sig, "Signature must change when header changes");

        let env_hdr_tampered_struct = Envelope { header: hdr_tampered, ciphertext: ct.clone(), signature: sig.clone() };
        let tam_hdr_hash = blake3::hash(&env_hdr_tampered_struct.to_bytes());
        debug_assert_ne!(tam_hdr_hash, orig_hash, "BLAKE3 hash should change for modified header");

        // Parse header-tampered envelope and validate fields
        if let Some(parsed_hdr_tam) = Envelope::from_bytes(&env_hdr_tampered_struct.to_bytes()) {
            debug_assert_eq!(parsed_hdr_tam.header, hdr_tampered, "Parsed header-tampered header mismatch");
            debug_assert_eq!(parsed_hdr_tam.ciphertext, ct, "Parsed header-tampered ciphertext mismatch");
            debug_assert_eq!(parsed_hdr_tam.signature, sig, "Parsed header-tampered signature mismatch");
        } else {
            debug_assert!(false, "Parsing header-tampered envelope bytes should still succeed (structure-wise)");
        }

        // Tamper signature and ensure hash differs
        let mut sig_corrupt = sig.clone();
        debug_assert!(!sig_matches(&id, &signed_msg, &sig_corrupt), "Corrupted signature must not verify original message");
        debug_assert_eq!(sig_corrupt.len(), SIG_LEN, "Corrupted signature length should remain 64 bytes");
        sig_corrupt[0] ^= 0x01;
        let env_sig_tampered = Envelope { header: hdr, ciphertext: ct.clone(), signature: sig_corrupt };
        let hash_sig_tampered = blake3::hash(&env_sig_tampered.to_bytes());
        debug_assert_ne!(hash_sig_tampered, orig_hash, "Hash should change when signature changes");

        // Parse signature-tampered envelope and validate fields
        if let Some(parsed_sig_tam) = Envelope::from_bytes(&env_sig_tampered.to_bytes()) {
            debug_assert_eq!(parsed_sig_tam.header, hdr, "Parsed signature-tampered header mismatch");
            debug_assert_eq!(parsed_sig_tam.ciphertext, ct, "Parsed signature-tampered ciphertext mismatch");
            debug_assert_ne!(parsed_sig_tam.signature, sig, "Parsed signature-tampered signature should differ from original");
        } else {
            debug_assert!(false, "Parsing signature-tampered envelope bytes should still succeed (structure-wise)");
        }

        // Combine header and ciphertext tamper and ensure hash differs
        if !ct.is_empty() {
            let mut ct_both = ct.clone();
            ct_both[0] ^= 0x02;
            let env_both = Envelope { header: hdr_tampered, ciphertext: ct_both, signature: sig.clone() };
            debug_assert_ne!(blake3::hash(&env_both.to_bytes()), orig_hash, "Hash should change when header and ciphertext change");

            // Parse combined tampered envelope and validate fields
            if let Some(parsed_both) = Envelope::from_bytes(&env_both.to_bytes()) {
                debug_assert_eq!(parsed_both.header, hdr_tampered, "Parsed combined-tampered header mismatch");
                debug_assert_ne!(parsed_both.ciphertext, ct, "Parsed combined-tampered ciphertext should differ from original");
                debug_assert_eq!(parsed_both.signature, sig, "Parsed combined-tampered signature mismatch");
            } else {
                debug_assert!(false, "Parsing combined tampered envelope bytes should still succeed (structure-wise)");
            }
        }

        // Decryption with a fresh session should fail
        let mut fresh = RatchetSession::new(secret, None);
        let wrong = fresh.ratchet_decrypt(&ct);
        debug_assert!(wrong.is_err(), "Decrypting with a fresh session should fail");

        // Ratchet progression: encrypt and decrypt a second message
        if let Ok(ct2) = sess.ratchet_encrypt(payload) {
            let mut signed_msg2 = Vec::with_capacity(hdr.len() + ct2.len());
            signed_msg2.extend_from_slice(&hdr);
            signed_msg2.extend_from_slice(&ct2);
            let sig_ct2 = id.sign(&signed_msg2);
            debug_assert!(sig_matches(&id, &signed_msg2, &sig_ct2), "Signature should verify for second message");
            debug_assert_eq!(sig_ct2.len(), SIG_LEN, "Second signature length should be 64 bytes");
            debug_assert_ne!(sig_ct2, sig, "Signatures should differ for different messages");
            let env2_struct = Envelope { header: hdr, ciphertext: ct2.clone(), signature: sig_ct2.clone() };
            let bytes2 = env2_struct.to_bytes();
            debug_assert_eq!(&bytes2[..HDR_LEN], &hdr, "Second envelope prefix should be header");
            debug_assert_eq!(&bytes2[bytes2.len()-SIG_LEN..], &sig_ct2[..], "Second envelope suffix should be signature");
            debug_assert_eq!(&bytes2[HDR_LEN..bytes2.len()-SIG_LEN], &ct2[..], "Second envelope middle should be ciphertext");
            debug_assert_eq!(&signed_msg2[..], &bytes2[..bytes2.len()-SIG_LEN], "Second signed message should be envelope without signature");

            // Parse second envelope and validate fields
            if let Some(parsed2) = Envelope::from_bytes(&env2_struct.to_bytes()) {
                debug_assert_eq!(parsed2.header, hdr, "Parsed second header mismatch");
                debug_assert_eq!(parsed2.ciphertext, ct2, "Parsed second ciphertext mismatch");
                debug_assert_eq!(parsed2.signature, sig_ct2, "Parsed second signature mismatch");
            } else {
                debug_assert!(false, "Parsing second envelope should succeed");
            }

            if let Ok(pt2) = sess.ratchet_decrypt(&ct2) {
                debug_assert_eq!(pt2.as_slice(), payload, "Second round decryption mismatch");
            }

            // Replaying ct2 should fail
            let replay2 = sess.ratchet_decrypt(&ct2);
            debug_assert!(replay2.is_err(), "Replaying second ciphertext should not decrypt twice");

            // Old ciphertext should still not decrypt after progression
            let old_again = sess.ratchet_decrypt(&ct);
            debug_assert!(old_again.is_err(), "Old ciphertext should not decrypt after ratchet progressed");

            // Decryption of ct2 with a fresh session should fail
            let mut fresh2 = RatchetSession::new(secret, None);
            let wrong2 = fresh2.ratchet_decrypt(&ct2);
            debug_assert!(wrong2.is_err(), "Decrypting second ciphertext with a fresh session should fail");

            // Third ratchet step to validate continued progression
            if let Ok(ct3) = sess.ratchet_encrypt(payload) {
                debug_assert_ne!(ct3, ct2, "Ciphertexts across ratchet steps should differ (ct3 vs ct2)");
                debug_assert_ne!(ct3, ct, "Ciphertexts across ratchet steps should differ (ct3 vs ct)");
                let mut signed_msg3 = Vec::with_capacity(hdr.len() + ct3.len());
                signed_msg3.extend_from_slice(&hdr);
                signed_msg3.extend_from_slice(&ct3);
                let sig_ct3 = id.sign(&signed_msg3);
                debug_assert!(sig_matches(&id, &signed_msg3, &sig_ct3), "Signature should verify for third message");
                debug_assert_eq!(sig_ct3.len(), SIG_LEN, "Third signature length should be 64 bytes");
                let env3_struct = Envelope { header: hdr, ciphertext: ct3.clone(), signature: sig_ct3.clone() };
                let bytes3 = env3_struct.to_bytes();
                debug_assert_eq!(&bytes3[..HDR_LEN], &hdr, "Third envelope prefix should be header");
                debug_assert_eq!(&bytes3[bytes3.len()-SIG_LEN..], &sig_ct3[..], "Third envelope suffix should be signature");
                debug_assert_eq!(&bytes3[HDR_LEN..bytes3.len()-SIG_LEN], &ct3[..], "Third envelope middle should be ciphertext");
                debug_assert_eq!(&signed_msg3[..], &bytes3[..bytes3.len()-SIG_LEN], "Third signed message should be envelope without signature");
                debug_assert_ne!(blake3::hash(&env3_struct.to_bytes()), blake3::hash(&env2_struct.to_bytes()), "Hash should change across subsequent envelopes");

                // Parse third envelope and validate fields
                if let Some(parsed3) = Envelope::from_bytes(&env3_struct.to_bytes()) {
                    debug_assert_eq!(parsed3.header, hdr, "Parsed third header mismatch");
                    debug_assert_eq!(parsed3.ciphertext, ct3, "Parsed third ciphertext mismatch");
                    debug_assert_eq!(parsed3.signature, sig_ct3, "Parsed third signature mismatch");
                } else {
                    debug_assert!(false, "Parsing third envelope should succeed");
                }

                if let Ok(pt3) = sess.ratchet_decrypt(&ct3) {
                    debug_assert_eq!(pt3.as_slice(), payload, "Third round decryption mismatch");
                    let replay3 = sess.ratchet_decrypt(&ct3);
                    debug_assert!(replay3.is_err(), "Replaying third ciphertext should not decrypt twice");
                }
            }
        }

        // Best-effort zeroize secret for hygiene in fuzzing context
        secret = [0u8; 32];
    }
});

