/// Hashes data using BLAKE3. Returns a 32-byte hash.
/// Used for blockchain message integrity checks.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}
