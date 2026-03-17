use blake3::Hasher;

// Verify block hashes
pub fn verify_hash(data: &[u8], expected_hash: &[u8]) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let computed_hash = hasher.finalize();
    computed_hash.as_bytes() == expected_hash
}
