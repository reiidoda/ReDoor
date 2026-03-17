use crate::config::pq_enabled;

// This module previously contained logic for combining classical and post-quantum
// shared secrets. That logic has been moved into the X3DH handshake implementation
// in `x3dh.rs` to ensure a cryptographically sound hybrid key agreement.

pub fn pq_active() -> bool {
    #[cfg(feature = "pq")]
    {
        pq_enabled()
    }
    #[cfg(not(feature = "pq"))]
    {
        false
    }
}
