#include <stdint.h>

int32_t redoor_init_runtime(void);
int32_t redoor_scripted_loopback(const char *msg);
int32_t redoor_scripted_loopback_ext(const char *msg, const char *relay_url, const char *blockchain_addr, const char *hmac_b64);
int32_t redoor_set_relay_hmac_b64(const char *key);
int32_t redoor_set_relay_ca_b64(const char *ca_b64);
int32_t redoor_set_relay_spki_pin_b64(const char *pin_b64);
void redoor_set_pq_enabled(int32_t enable);
int32_t redoor_set_pq_handshake_policy(const char *policy);
int32_t redoor_shutdown_runtime(void);

// New FFI bindings
int32_t redoor_init_env(const char *relay, const char *chain, const char *hmac);
char *redoor_create_identity(void);
char *redoor_get_identity(void);
char *redoor_generate_prekeys(void);
int32_t redoor_send_message(const char *peer, const char *msg);
char *redoor_poll_messages(void);
void redoor_free_string(char *ptr);
void redoor_wipe_memory(void);
int32_t redoor_enter_duress_mode(void);
int32_t redoor_flag_compromise_indicator(const char *peer_id_hex);
char *redoor_connect_via_qr(const char *qr_json);
int32_t redoor_has_session(const char *peer);
char *redoor_get_safety_number(const char *peer);
char *redoor_get_network_status(void);
