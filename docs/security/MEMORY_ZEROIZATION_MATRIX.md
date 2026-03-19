# Memory Zeroization and Forensics Resistance Matrix

This matrix tracks where sensitive data exists, how wipe is enforced, and what regression checks guard it.

## Coverage Matrix

| Surface | Data at Risk | Zeroization/Wipe Path | Regression Coverage | CI Gate |
|---|---|---|---|---|
| Rust `message_store` | plaintext message content and peer metadata | `AppState::wipe_message_store` + `StoredMessage::zeroize` | `engine::tests::secure_wipe_zeroizes_sensitive_collections_and_tracks_report`, `ffi::tests::test_delete_all_messages_zeroizes_buffers` | `scripts/ci-memory-hygiene.sh` |
| Rust `attachment_cache` | raw attachment bytes | `AppState::wipe_attachment_cache` (`Vec<u8>::zeroize`) | `engine::tests::secure_wipe_zeroizes_sensitive_collections_and_tracks_report`, `ffi::tests::test_delete_all_messages_zeroizes_buffers` | `scripts/ci-memory-hygiene.sh` |
| Rust sessions and handshake state | ratchet/session keys, pending handshake artifacts | `AppState::wipe_sessions` (`SessionEntry::zeroize`) | `service::tests::test_wipe_sensitive_state_clears_memory_structures`, `engine::tests::secure_wipe_zeroizes_sensitive_collections_and_tracks_report` | `scripts/ci-memory-hygiene.sh` |
| Rust crash-adjacent path | all in-memory sensitive buffers before panic report propagation | `apply_crash_hygiene_wipe` (invoked by panic hook) | `ffi::tests::test_crash_hygiene_wipe_clears_sensitive_state` | `scripts/ci-memory-hygiene.sh` |
| Rust pending/outgoing/proof queues | in-flight encrypted blobs + identifiers | `AppState::wipe_pending_blobs`, `AppState::wipe_outgoing_queue`, `AppState::wipe_blockchain_queues` | `engine::tests::secure_wipe_zeroizes_sensitive_collections_and_tracks_report` | `scripts/ci-memory-hygiene.sh` |
| Swift volatile secure storage | HMAC and volatile secret values | `SecureStorage.wipeAndRemove`, `SecureStorage.clearAll` via `ZeroizableSecureBuffer.wipe` | `testSecureStorageDeleteZeroizesBuffer`, `testSecureStorageClearAllZeroizesBuffers`, `testLockWipesHMACSecureBuffer`, `testBackgroundTransitionWipesHMACSecureBuffer`, `testDuressWipesHMACSecureBuffer` | `scripts/ci-memory-hygiene.sh` (policy + test presence checks) |
| Swift lifecycle transitions | secrets while app backgrounds/resigns/terminates | `ChatService` observers + `RedoorService.lock()` | `testBackgroundTransitionWipesHMACSecureBuffer` + lifecycle observer checks | `scripts/ci-memory-hygiene.sh` |

## Residual Forensics Risk and Limits

- Process-memory snapshots from a fully compromised OS/kernel or rooted/jailbroken device can still observe plaintext before wipe executes.
- Compiler/allocator behavior can keep transient copies outside explicit buffers; zeroization reduces risk but cannot guarantee total eradication of every copy.
- Crash dumps created before panic-hook execution may retain fragments, depending on platform crash timing and OS policy.
- Hardware DMA, baseband, and malicious hypervisor-level observers are out of scope for app-layer zeroization controls.

## Mitigation Direction

- Keep sensitive payload lifetime short (already enforced with fast purge/wipe flows).
- Prefer minimal parsing/logging of untrusted payloads before authentication/decryption.
- Maintain periodic external memory-forensics review and red-team crash-path drills.
- Keep panic/lifecycle wipe paths deterministic and continuously regression-tested in CI.
