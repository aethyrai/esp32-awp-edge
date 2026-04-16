/**
 * AWP Crypto — post-quantum key exchange and authenticated encryption
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "api.h"  /* ML-KEM-768 (Kyber) */

#ifdef __cplusplus
extern "C" {
#endif

/* KEM sizes */
#define AWP_KEM_PK_SIZE   pqcrystals_kyber768_PUBLICKEYBYTES
#define AWP_KEM_SK_SIZE   pqcrystals_kyber768_SECRETKEYBYTES
#define AWP_KEM_CT_SIZE   pqcrystals_kyber768_CIPHERTEXTBYTES
#define AWP_KEM_SS_SIZE   pqcrystals_kyber768_BYTES

/* AEAD sizes */
#define AWP_XCNONCE_SIZE  24
#define AWP_TAG_SIZE      16
#define AWP_KEY_SIZE      32
#define AWP_ENCRYPT_OVERHEAD  (AWP_XCNONCE_SIZE + AWP_TAG_SIZE)

#define AWP_PSK_MAX_SIZE      64
#define AWP_REPLAY_WINDOW     4096
#define AWP_RATCHET_INTERVAL  256   /* derive new key every 256 frames */
#define AWP_NONCE_BOOT_GAP    1000  /* nonce jump across reboots */
#define AWP_NONCE_PERSIST_EVERY 500 /* persist counter to NVS every N frames */

/* Nonce-reuse safety (audit F-06): on reboot we jump by AWP_NONCE_BOOT_GAP,
 * and we only persist every AWP_NONCE_PERSIST_EVERY frames. The gap MUST
 * exceed the persist interval, otherwise a crash between persists can
 * reuse nonces within the same key_epoch. Verified by the TLA+ model in
 * docs/audits/formal/tlaplus/ReplayWindow.tla. */
_Static_assert(AWP_NONCE_BOOT_GAP > AWP_NONCE_PERSIST_EVERY,
               "AWP_NONCE_BOOT_GAP must exceed persist interval; see audit F-06");

/* ========================================================================= */
/* Crypto State                                                              */
/* ========================================================================= */

typedef struct {
    uint8_t  kem_pk[AWP_KEM_PK_SIZE];
    uint8_t  kem_sk[AWP_KEM_SK_SIZE];
    bool     kem_ready;
    uint8_t  session_key[AWP_KEY_SIZE];
    bool     session_ready;
    uint8_t  psk[AWP_PSK_MAX_SIZE];
    size_t   psk_len;
    uint64_t nonce_counter;
    uint32_t ratchet_count;      /* frames since last key ratchet */
    uint64_t replay_top;
    uint64_t replay_bitmap[AWP_REPLAY_WINDOW / 64];  /* 4096-bit bitmap */
} awp_crypto_t;

/* ========================================================================= */
/* Initialization                                                            */
/* ========================================================================= */

void awp_crypto_init(awp_crypto_t *ctx);
void awp_crypto_set_psk(awp_crypto_t *ctx, const uint8_t *psk, size_t psk_len);
bool awp_crypto_new_keypair(awp_crypto_t *ctx);

/* ========================================================================= */
/* ML-KEM Handshake                                                          */
/* ========================================================================= */

void awp_crypto_get_ek_hex(const awp_crypto_t *ctx, char *out, size_t out_size);
bool awp_crypto_accept_handshake(awp_crypto_t *ctx, const char *ct_hex);
void awp_crypto_auth_token(const awp_crypto_t *ctx, const char *node_id,
                           uint8_t out[32]);

/* ========================================================================= */
/* Payload Encryption / Decryption                                           */
/* ========================================================================= */

bool awp_crypto_encrypt(awp_crypto_t *ctx,
                        const uint8_t *plain, size_t plain_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *out, size_t *out_len);

bool awp_crypto_decrypt(awp_crypto_t *ctx,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *out, size_t *out_len);

static inline bool awp_crypto_has_session(const awp_crypto_t *ctx)
{
    return ctx->session_ready;
}

/**
 * Sliding-window replay check over monotonic counters.
 *
 * WARNING (audit F-04): this function is currently exercised ONLY by
 * the boot self-tests. The production inbound path in
 * awp_edge_node.c:connection_task deliberately does NOT call it
 * because the Python mesh-tier upstream emits XChaCha20 nonces with
 * random high bytes rather than a monotonic counter — feeding those
 * to this check produces spurious rejections.
 *
 * Consequence: frames received from upstream are NOT replay-protected
 * at the AWP layer. Replay resistance relies on (a) fresh per-handshake
 * session keys, and (b) TCP in-order delivery. An adversary with the
 * ability to inject packets into an established TCP session could
 * resubmit a previously observed encrypted frame and have it accepted.
 *
 * TODO: make the upstream emit counter-based nonces so this check can
 * be wired in symmetrically. Until then, do NOT rely on this function
 * for inbound protection in production code paths.
 */
bool awp_crypto_replay_check(awp_crypto_t *ctx, uint64_t counter);

#ifdef __cplusplus
}
#endif
