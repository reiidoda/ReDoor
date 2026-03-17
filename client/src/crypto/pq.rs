#[cfg(feature = "pq")]
use pqcrypto_kyber::kyber1024;
#[cfg(feature = "pq")]
#[cfg(feature = "pq")]
pub type PqPublicKey = kyber1024::PublicKey;
#[cfg(feature = "pq")]
pub type PqSecretKey = kyber1024::SecretKey;
#[cfg(feature = "pq")]
pub type PqCiphertext = kyber1024::Ciphertext;

#[cfg(feature = "pq")]
pub fn generate_pq_keypair() -> (PqPublicKey, PqSecretKey) {
    kyber1024::keypair()
}

#[cfg(feature = "pq")]
pub fn encapsulate(pk: &PqPublicKey) -> (PqCiphertext, kyber1024::SharedSecret) {
    let (ss, ct) = kyber1024::encapsulate(pk);
    (ct, ss)
}

#[cfg(feature = "pq")]
pub fn decapsulate(ct: &PqCiphertext, sk: &PqSecretKey) -> kyber1024::SharedSecret {
    kyber1024::decapsulate(ct, sk)
}

// Stub types for when PQ feature is disabled to satisfy struct definitions
#[cfg(not(feature = "pq"))]
pub type PqPublicKey = Vec<u8>;
#[cfg(not(feature = "pq"))]
pub type PqSecretKey = Vec<u8>;
#[cfg(not(feature = "pq"))]
pub type PqCiphertext = Vec<u8>;
