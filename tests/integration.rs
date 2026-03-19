// Integration tests
#[tokio::test]
#[ignore]
async fn test_end_to_end_message() {
    // This test performs a full cycle:
    // 1. Generate Identity
    // 2. Establish Session (Loopback)
    // 3. Encrypt & Sign Message
    // 4. Send to Relay
    // 5. Log to Blockchain
    // 6. Fetch from Relay
    // 7. Decrypt & Verify

    let result = redoor_client::api::scripted_loopback("Integration Test Payload").await;
    assert!(result.is_ok(), "End-to-end loopback failed: {:?}", result.err());
}

#[tokio::test]
#[ignore]
async fn test_end_to_end_custom_endpoints() {
    // Verify we can configure endpoints
    let result = redoor_client::api::scripted_loopback_custom("http://localhost:8080", "127.0.0.1:9000", "Custom Endpoint Test").await;
    assert!(result.is_ok(), "Custom endpoint loopback failed: {:?}", result.err());
}

#[test]
#[ignore]
fn test_alice_bob_conversation() {
    // Simulates a conversation between two distinct ClientEngine instances
    let result = redoor_client::simulation::simulate_conversation("http://localhost:8080", "127.0.0.1:9000");
    assert!(result.is_ok(), "Alice-Bob conversation failed: {:?}", result.err());
}

#[test]
fn test_duress_mode_simulation() {
    let result = redoor_client::simulation::verify_duress_mode();
    assert!(result.is_ok(), "Duress mode verification failed: {:?}", result.err());
}

#[test]
#[ignore]
fn test_benchmark_simulation() {
    let result = redoor_client::simulation::benchmark_handshake_and_messaging("http://localhost:8080", "127.0.0.1:9000");
    match result {
        Ok(report) => println!("{}", report),
        Err(e) => panic!("Benchmark failed: {}", e),
    }
}