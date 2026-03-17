//! Consensus module for the blockchain node.
//!
//! This crate contains lightweight consensus helpers used by the blockchain
//! node. For now we provide a simple Proof-of-Authority (PoA) style helper
//! via the `authority` submodule. The module also exposes a small enum and
//! a convenience wrapper so callers can ask the current consensus engine to
//! validate a block signer.

pub mod authority;

// Re-export the common authority functions so callers can use them directly
// via `consensus::init_validators` / `consensus::validate_authority`.
pub use authority::{init_validators, validate_authority};

/// Consensus engines supported by this node.
///
/// Keep this small for now; additional engines (e.g. PBFT) can be added
/// later and routed through `validate_signer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusEngine {
    /// Lightweight proof-of-authority used for small/private networks.
    Authority,
}

/// Validate that a given public key is authorized to sign under the selected
/// consensus engine.
///
/// Currently this delegates to the `authority` module when `ConsensusEngine::Authority`
/// is selected. New engines should be added here.
pub fn validate_signer(engine: ConsensusEngine, public_key: &[u8]) -> bool {
    match engine {
        ConsensusEngine::Authority => validate_authority(public_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn default_validator_allows_when_uninitialized() {
        let _guard = TEST_LOCK.lock().unwrap();
        crate::consensus::authority::clear_validators_for_tests();

        // If validators are not initialized, current authority implementation
        // returns true (dev mode). This test ensures the wrapper delegates
        // correctly.
        let fake_key = b"not-a-real-key";
        assert!(validate_signer(ConsensusEngine::Authority, fake_key));
    }

    #[test]
    fn init_validators_restricts_access() {
        let _guard = TEST_LOCK.lock().unwrap();
        crate::consensus::authority::clear_validators_for_tests();

        // Initialize a single trusted validator and ensure others are rejected.
        let trusted = vec![b"trusted-key".to_vec()];
        init_validators(trusted);

        assert!(validate_signer(ConsensusEngine::Authority, b"trusted-key"));
        assert!(!validate_signer(ConsensusEngine::Authority, b"other-key"));
    }

    #[test]
    fn init_validators_supports_multiple_keys() {
        let _guard = TEST_LOCK.lock().unwrap();
        crate::consensus::authority::clear_validators_for_tests();

        let validators = vec![b"validator-1".to_vec(), b"validator-2".to_vec()];
        init_validators(validators);

        assert!(validate_signer(ConsensusEngine::Authority, b"validator-1"));
        assert!(validate_signer(ConsensusEngine::Authority, b"validator-2"));
        assert!(!validate_signer(ConsensusEngine::Authority, b"validator-3"));
    }

    #[test]
    fn init_validators_overwrites_previous_set() {
        let _guard = TEST_LOCK.lock().unwrap();
        crate::consensus::authority::clear_validators_for_tests();

        // Initial set
        init_validators(vec![b"old-validator".to_vec()]);
        assert!(validate_signer(
            ConsensusEngine::Authority,
            b"old-validator"
        ));

        // New set
        init_validators(vec![b"new-validator".to_vec()]);
        assert!(
            !validate_signer(ConsensusEngine::Authority, b"old-validator"),
            "Old validator should be removed"
        );
        assert!(
            validate_signer(ConsensusEngine::Authority, b"new-validator"),
            "New validator should be accepted"
        );
    }
}
