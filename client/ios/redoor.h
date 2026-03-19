#include <stdint.h>
#include <stddef.h>

int32_t redoor_init_runtime(void);
int32_t redoor_scripted_loopback(const char *msg);
int32_t redoor_scripted_loopback_ext(const char *msg, const char *relay_url, const char *blockchain_addr, const char *hmac_b64);
int32_t redoor_set_relay_hmac_b64(const char *key);
void redoor_set_pq_enabled(int32_t enable);
int32_t redoor_set_proxy(const char *url);
int32_t redoor_shutdown_runtime(void);

// Stateful API
int32_t redoor_init_env(const char *relay_url, const char *blockchain_addr, const char *hmac_key);
char* redoor_create_identity(void);
int32_t redoor_restore_identity(const char *priv_key_hex);
char* redoor_get_private_key(void);
char* redoor_get_identity(void);
int32_t redoor_connect_peer(const char *peer_id_hex);
int32_t redoor_send_message(const char *peer_id_hex, const char *message);
int32_t redoor_send_image(const char *peer_id_hex, const uint8_t *image_data, size_t image_len);
char* redoor_poll_messages(void);
void redoor_free_string(char *s);
