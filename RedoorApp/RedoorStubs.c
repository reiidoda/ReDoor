#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Stubs to satisfy the linker for missing Rust FFI symbols.
// These allow the iOS app to build and run.
// To enable real functionality, these must be implemented in the Rust 'client' library and exported.

static int g_stub_has_session = 0;

// --- Missing Stubs Added for Compilation ---

int32_t redoor_init_runtime(void) {
    printf("[RedoorStub] redoor_init_runtime called\n");
    return 0; // Success
}

int32_t redoor_scripted_loopback_ext(const char *msg, const char *relay, const char *chain, const char *hmac) {
    printf("[RedoorStub] redoor_scripted_loopback_ext called\n");
    return 0; // Success
}

int32_t redoor_set_relay_hmac_b64(const char *key) {
    printf("[RedoorStub] redoor_set_relay_hmac_b64 called\n");
    return 0; // Success
}

int32_t redoor_set_proxy(const char *url) {
    printf("[RedoorStub] redoor_set_proxy called. URL: %s\n", url ? url : "NULL");
    return 0; // Success
}

int32_t redoor_identity_unlock(const char *plaintext_b64) {
    printf("[RedoorStub] redoor_identity_unlock called\n");
    return 0; // Success
}

char *redoor_identity_get_data_to_wrap(void) {
    printf("[RedoorStub] redoor_identity_get_data_to_wrap called\n");
    return strdup("stub_identity_private_key_data_12345");
}

// --- Legacy Stubs (kept just in case) ---

int redoor_connect_peer(const char *peer_multiaddr) {
    printf("[RedoorStub] redoor_connect_peer called: %s\n", peer_multiaddr ? peer_multiaddr : "NULL");
    g_stub_has_session = 1;
    return 0; // Success
}

const char *redoor_get_private_key(void) {
    return "stub_private_key_example";
}

int redoor_restore_identity(const char *seed_phrase) {
    printf("[RedoorStub] redoor_restore_identity called\n");
    return 0; // Success
}

int redoor_send_image(const char *peer_id, const uint8_t *data, long len) {
    printf("[RedoorStub] redoor_send_image called. Peer: %s, Len: %ld\n", peer_id ? peer_id : "NULL", len);
    return 0; // Success
}

// --- New Stubs matching RedoorService.swift ---

int32_t redoor_init_env(const char *relay, const char *chain, const char *hmac) {
    printf("[RedoorStub] redoor_init_env called. Relay: %s, Chain: %s\n", relay ? relay : "NULL", chain ? chain : "NULL");
    return 0; // Success
}

char *redoor_create_identity(void) {
    printf("[RedoorStub] redoor_create_identity called\n");
    g_stub_has_session = 0;
    return strdup("stub_identity_new_12345");
}

char *redoor_get_identity(void) {
    // printf("[RedoorStub] redoor_get_identity called\n"); // Commented out to avoid spamming logs
    return strdup("stub_identity_current_12345");
}

int32_t redoor_send_message(const char *peer, const char *msg) {
    printf("[RedoorStub] redoor_send_message called. Peer: %s, Msg: %s\n", peer ? peer : "NULL", msg ? msg : "NULL");
    return g_stub_has_session ? 0 : -1;
}

char *redoor_poll_messages(void) {
    // Return empty JSON array or a mock message occasionally
    // For now, just empty array
    return strdup("[]");
}

void redoor_free_string(char *ptr) {
    if (ptr) free(ptr);
}

void redoor_wipe_memory(void) {
    printf("[RedoorStub] redoor_wipe_memory called\n");
    g_stub_has_session = 0;
}

int32_t redoor_enter_duress_mode(void) {
    printf("[RedoorStub] redoor_enter_duress_mode called\n");
    return 0;
}

char *redoor_initiate_session(const char *peer, const char *bundle) {
    printf("[RedoorStub] redoor_initiate_session called\n");
    g_stub_has_session = 1;
    return strdup("stub_session_id");
}

char *redoor_connect_via_qr(const char *qr_json) {
    printf("[RedoorStub] redoor_connect_via_qr called\n");
    g_stub_has_session = 1;
    return strdup("stub_initial_message");
}

int32_t redoor_handle_initial_message(const char *peer, const char *msg) {
    printf("[RedoorStub] redoor_handle_initial_message called\n");
    g_stub_has_session = 1;
    return 0;
}

char *redoor_generate_prekeys(void) {
    printf("[RedoorStub] redoor_generate_prekeys called\n");
    return strdup("{\"stub\":true}");
}

int32_t redoor_has_session(const char *peer) {
    (void)peer;
    return g_stub_has_session ? 1 : 0;
}

char *redoor_get_safety_number(const char *peer) {
    (void)peer;
    return strdup("stub_safety_number_12345");
}

char *redoor_get_network_status(void) {
    // Return JSON for RedoorNetworkStatus
    return strdup("{\"relay_connected\": true, \"blockchain_connected\": true}");
}
