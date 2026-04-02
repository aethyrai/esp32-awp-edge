/**
 * AWP Crypto — post-quantum key exchange and authenticated encryption
 */

#include "awp_crypto.h"

#include <string.h>
#include <stdio.h>

#include "blake3.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"

/* mbedTLS ChaCha20-Poly1305 */
#include "mbedtls/chachapoly.h"

static const char *TAG = "awp_crypto";

/* ========================================================================= */
/* Hex Helpers                                                               */
/* ========================================================================= */

static void bytes_to_hex(const uint8_t *in, size_t in_len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
}

static int hex_to_bytes(const char *hex_str, uint8_t *out, size_t out_size)
{
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len / 2 > out_size) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex_str + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

/* ========================================================================= */
/* Key Derivation                                                            */
/* ========================================================================= */

static void derive_session_key(const uint8_t *shared_secret, size_t ss_len,
                               const uint8_t *psk, size_t psk_len,
                               uint8_t *key_out)
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "awp-session-key");
    blake3_hasher_update(&hasher, shared_secret, ss_len);
    if (psk && psk_len > 0) {
        blake3_hasher_update(&hasher, psk, psk_len);
    }
    blake3_hasher_finalize(&hasher, key_out, AWP_KEY_SIZE);
}

/* ========================================================================= */
/* NVS Nonce Persistence                                                     */
/* ========================================================================= */

#define NVS_NAMESPACE   "awp_crypto"
#define NVS_KEY_NONCE   "nonce_ctr"
#define NONCE_BOOT_GAP  1000

static uint64_t nonce_load_and_advance(void)
{
    nvs_handle_t nvs;
    uint64_t stored = 0;

    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS open failed: %s — nonce starting at %d", esp_err_to_name(err), NONCE_BOOT_GAP);
        return NONCE_BOOT_GAP;
    }

    err = nvs_get_u64(nvs, NVS_KEY_NONCE, &stored);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        stored = 0;
    } else if (err != ESP_OK) {
        ESP_LOGW(TAG, "NVS read failed: %s", esp_err_to_name(err));
        stored = 0;
    }

    /* Jump forward to guarantee no reuse across power loss */
    uint64_t next = stored + NONCE_BOOT_GAP;

    err = nvs_set_u64(nvs, NVS_KEY_NONCE, next);
    if (err == ESP_OK) {
        esp_err_t cerr = nvs_commit(nvs);
        if (cerr != ESP_OK) {
            ESP_LOGW(TAG, "NVS commit failed: %s", esp_err_to_name(cerr));
        }
    } else {
        ESP_LOGE(TAG, "NVS write failed: %s — nonce may reuse after reboot",
                 esp_err_to_name(err));
    }
    nvs_close(nvs);

    ESP_LOGI(TAG, "Nonce counter: loaded=%llu, starting at=%llu (boot gap=%d)",
             (unsigned long long)stored, (unsigned long long)next,
             NONCE_BOOT_GAP);
    return next;
}

static void nonce_persist(uint64_t counter)
{
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) {
        ESP_LOGE("awp_crypto", "nonce_persist: NVS open failed");
        return;
    }
    esp_err_t err = nvs_set_u64(nvs, NVS_KEY_NONCE, counter + NONCE_BOOT_GAP);
    if (err != ESP_OK) {
        ESP_LOGE("awp_crypto", "nonce_persist: NVS write failed: %s",
                 esp_err_to_name(err));
    } else {
        err = nvs_commit(nvs);
        if (err != ESP_OK) {
            ESP_LOGE("awp_crypto", "nonce_persist: NVS commit failed: %s",
                     esp_err_to_name(err));
        }
    }
    nvs_close(nvs);
}

/* ========================================================================= */
/* Initialization                                                            */
/* ========================================================================= */

void awp_crypto_init(awp_crypto_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    /* Load persisted nonce counter */
    ctx->nonce_counter = nonce_load_and_advance();

    ESP_LOGI(TAG, "Crypto initialized (nonce=%llu). Call awp_crypto_new_keypair() before handshake.",
             (unsigned long long)ctx->nonce_counter);
}

void awp_crypto_set_psk(awp_crypto_t *ctx, const uint8_t *psk, size_t psk_len)
{
    if (psk_len > AWP_PSK_MAX_SIZE) psk_len = AWP_PSK_MAX_SIZE;
    memcpy(ctx->psk, psk, psk_len);
    ctx->psk_len = psk_len;
    ESP_LOGI(TAG, "PSK set (%zu bytes)", psk_len);
}

bool awp_crypto_new_keypair(awp_crypto_t *ctx)
{
    ESP_LOGI(TAG, "Generating ephemeral ML-KEM-768 keypair...");

    int ret = pqcrystals_kyber768_ref_keypair(ctx->kem_pk, ctx->kem_sk);
    if (ret != 0) {
        ESP_LOGE(TAG, "ML-KEM keypair generation failed: %d", ret);
        ctx->kem_ready = false;
        return false;
    }

    ctx->kem_ready = true;
    ESP_LOGI(TAG, "Ephemeral ML-KEM-768 keypair ready");
    return true;
}

/* ========================================================================= */
/* ML-KEM Handshake                                                          */
/* ========================================================================= */

void awp_crypto_get_ek_hex(const awp_crypto_t *ctx, char *out, size_t out_size)
{
    if (!ctx->kem_ready || out_size < AWP_KEM_PK_SIZE * 2 + 1) {
        out[0] = '\0';
        return;
    }
    bytes_to_hex(ctx->kem_pk, AWP_KEM_PK_SIZE, out);
}

bool awp_crypto_accept_handshake(awp_crypto_t *ctx, const char *ct_hex)
{
    if (!ctx->kem_ready || !ct_hex || ct_hex[0] == '\0') {
        ESP_LOGW(TAG, "KEM not ready or no ciphertext");
        return false;
    }

    /* Decode ciphertext from hex */
    uint8_t ct[AWP_KEM_CT_SIZE];
    int ct_len = hex_to_bytes(ct_hex, ct, sizeof(ct));
    if (ct_len != AWP_KEM_CT_SIZE) {
        ESP_LOGW(TAG, "Bad ciphertext length: %d (expected %d)", ct_len, AWP_KEM_CT_SIZE);
        return false;
    }

    /* Decapsulate */
    uint8_t shared_secret[AWP_KEM_SS_SIZE];
    int ret = pqcrystals_kyber768_ref_dec(shared_secret, ct, ctx->kem_sk);

    /* Derive session key */
    uint8_t candidate_key[AWP_KEY_SIZE];
    derive_session_key(shared_secret, AWP_KEM_SS_SIZE,
                       ctx->psk, ctx->psk_len, candidate_key);

    /* Wipe shared secret from stack immediately */
    volatile uint8_t *ss_ptr = shared_secret;
    for (int i = 0; i < AWP_KEM_SS_SIZE; i++) ss_ptr[i] = 0;

    /* Constant-time conditional copy */
    uint8_t mask = (uint8_t)(-(ret == 0));  /* 0xFF or 0x00 */
    for (int i = 0; i < AWP_KEY_SIZE; i++) {
        ctx->session_key[i] = (candidate_key[i] & mask) |
                              (ctx->session_key[i] & ~mask);
    }

    /* Set session state */
    ctx->session_ready = (bool)(mask & 1);

    /* Wipe candidate key */
    volatile uint8_t *ck_ptr = candidate_key;
    for (int i = 0; i < AWP_KEY_SIZE; i++) ck_ptr[i] = 0;

    /* Log after all timing-sensitive work is done */
    if (ctx->session_ready) {
        ESP_LOGI(TAG, "PQC handshake complete");
    } else {
        ESP_LOGW(TAG, "KEM decapsulation failed");
    }

    return ctx->session_ready;
}

/* ========================================================================= */
/* Mutual Authentication                                                     */
/* ========================================================================= */

void awp_crypto_auth_token(const awp_crypto_t *ctx, const char *node_id,
                           uint8_t out[32])
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "awp-node-auth");
    blake3_hasher_update(&hasher, ctx->session_key, AWP_KEY_SIZE);
    blake3_hasher_update(&hasher, (const uint8_t *)node_id, strlen(node_id));
    blake3_hasher_finalize(&hasher, out, 32);
}

/* ========================================================================= */
/* Encryption / Decryption                                                   */
/* ========================================================================= */

#include "mbedtls/chacha20.h"

static void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t subkey[32])
{
    /* ChaCha20 state initialization */
    uint32_t state[16];

    /* "expand 32-byte k" */
    state[ 0] = 0x61707865;
    state[ 1] = 0x3320646e;
    state[ 2] = 0x79622d32;
    state[ 3] = 0x6b206574;

    /* Key */
    for (int i = 0; i < 8; i++) {
        state[4 + i] = (uint32_t)key[i*4]       | ((uint32_t)key[i*4+1] << 8) |
                       ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }

    /* Nonce (replaces counter + nonce in standard ChaCha20) */
    for (int i = 0; i < 4; i++) {
        state[12 + i] = (uint32_t)nonce[i*4]       | ((uint32_t)nonce[i*4+1] << 8) |
                        ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    /* 20 rounds of ChaCha */
    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    #define QR(a, b, c, d) do { \
        a += b; d ^= a; d = (d << 16) | (d >> 16); \
        c += d; b ^= c; b = (b << 12) | (b >> 20); \
        a += b; d ^= a; d = (d <<  8) | (d >> 24); \
        c += d; b ^= c; b = (b <<  7) | (b >> 25); \
    } while (0)

    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    #undef QR

    /* Output */
    for (int i = 0; i < 4; i++) {
        subkey[i*4]     = x[i] & 0xFF;
        subkey[i*4 + 1] = (x[i] >> 8) & 0xFF;
        subkey[i*4 + 2] = (x[i] >> 16) & 0xFF;
        subkey[i*4 + 3] = (x[i] >> 24) & 0xFF;
    }
    for (int i = 0; i < 4; i++) {
        subkey[16 + i*4]     = x[12+i] & 0xFF;
        subkey[16 + i*4 + 1] = (x[12+i] >> 8) & 0xFF;
        subkey[16 + i*4 + 2] = (x[12+i] >> 16) & 0xFF;
        subkey[16 + i*4 + 3] = (x[12+i] >> 24) & 0xFF;
    }
}

bool awp_crypto_encrypt(awp_crypto_t *ctx,
                        const uint8_t *plain, size_t plain_len,
                        uint8_t *out, size_t *out_len)
{
    if (!ctx->session_ready) return false;
    if (ctx->nonce_counter == UINT64_MAX) {
        ESP_LOGE(TAG, "Nonce counter exhausted — refusing to encrypt");
        return false;
    }

    /* Generate nonce */
    uint8_t xcnonce[AWP_XCNONCE_SIZE];
    ctx->nonce_counter++;

    /* Periodic NVS persist */
    if (ctx->nonce_counter % 500 == 0) {
        nonce_persist(ctx->nonce_counter);
    }

    esp_fill_random(xcnonce, AWP_XCNONCE_SIZE);
    /* Embed counter */
    uint64_t ctr = ctx->nonce_counter;
    for (int i = 7; i >= 0; i--) {
        xcnonce[i] = ctr & 0xFF;
        ctr >>= 8;
    }

    uint8_t subkey[32];
    hchacha20(ctx->session_key, xcnonce, subkey);

    uint8_t inner_nonce[12];
    memset(inner_nonce, 0, 4);
    memcpy(inner_nonce + 4, xcnonce + 16, 8);

    memcpy(out, xcnonce, AWP_XCNONCE_SIZE);
    uint8_t *ct_out = out + AWP_XCNONCE_SIZE;
    uint8_t *tag_out = ct_out + plain_len;

    mbedtls_chachapoly_context chachapoly;
    mbedtls_chachapoly_init(&chachapoly);

    int ret = mbedtls_chachapoly_setkey(&chachapoly, subkey);
    if (ret != 0) goto enc_fail;

    ret = mbedtls_chachapoly_encrypt_and_tag(&chachapoly,
        plain_len, inner_nonce,
        (const uint8_t *)"awp", 3,
        plain, ct_out, tag_out);

    mbedtls_chachapoly_free(&chachapoly);
    memset(subkey, 0, sizeof(subkey));

    if (ret != 0) goto enc_fail;

    *out_len = AWP_XCNONCE_SIZE + plain_len + AWP_TAG_SIZE;
    return true;

enc_fail:
    mbedtls_chachapoly_free(&chachapoly);
    memset(subkey, 0, sizeof(subkey));
    ESP_LOGW(TAG, "XChaCha20 encryption failed: %d", ret);
    return false;
}

bool awp_crypto_decrypt(awp_crypto_t *ctx,
                        const uint8_t *enc, size_t enc_len,
                        uint8_t *out, size_t *out_len)
{
    if (!ctx->session_ready) return false;
    if (enc_len < AWP_ENCRYPT_OVERHEAD) return false;

    const uint8_t *xcnonce = enc;
    size_t plain_len = enc_len - AWP_ENCRYPT_OVERHEAD;
    const uint8_t *ct = enc + AWP_XCNONCE_SIZE;
    const uint8_t *tag = ct + plain_len;

    uint8_t subkey[32];
    hchacha20(ctx->session_key, xcnonce, subkey);

    uint8_t inner_nonce[12];
    memset(inner_nonce, 0, 4);
    memcpy(inner_nonce + 4, xcnonce + 16, 8);

    mbedtls_chachapoly_context chachapoly;
    mbedtls_chachapoly_init(&chachapoly);

    int ret = mbedtls_chachapoly_setkey(&chachapoly, subkey);
    if (ret != 0) goto dec_fail;

    ret = mbedtls_chachapoly_auth_decrypt(&chachapoly,
        plain_len, inner_nonce,
        (const uint8_t *)"awp", 3,
        tag, ct, out);

    mbedtls_chachapoly_free(&chachapoly);
    memset(subkey, 0, sizeof(subkey));

    if (ret != 0) goto dec_fail;

    *out_len = plain_len;
    return true;

dec_fail:
    mbedtls_chachapoly_free(&chachapoly);
    memset(subkey, 0, sizeof(subkey));
    ESP_LOGW(TAG, "XChaCha20 decryption failed: %d", ret);
    return false;
}

/* ========================================================================= */
/* Anti-Replay Window                                                        */
/* ========================================================================= */

bool awp_crypto_replay_check(awp_crypto_t *ctx, uint64_t counter)
{
    if (counter == 0) return false;  /* nonce 0 is never valid */

    if (counter > ctx->replay_top) {
        /* New high — shift window forward */
        uint64_t shift = counter - ctx->replay_top;
        if (shift >= AWP_REPLAY_WINDOW) {
            ctx->replay_bitmap = 0;
        } else {
            ctx->replay_bitmap <<= shift;
        }
        ctx->replay_bitmap |= 1;  /* mark current as seen */
        ctx->replay_top = counter;
        return true;
    }

    uint64_t diff = ctx->replay_top - counter;
    if (diff >= AWP_REPLAY_WINDOW) {
        /* Too old — outside window */
        ESP_LOGW(TAG, "Replay: nonce %llu too old (window top=%llu)",
                 (unsigned long long)counter, (unsigned long long)ctx->replay_top);
        return false;
    }

    uint64_t bit = 1ULL << diff;
    if (ctx->replay_bitmap & bit) {
        /* Already seen */
        ESP_LOGW(TAG, "Replay: duplicate nonce %llu", (unsigned long long)counter);
        return false;
    }

    ctx->replay_bitmap |= bit;
    return true;
}
