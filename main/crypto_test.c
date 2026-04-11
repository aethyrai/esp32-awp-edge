/**
 * Crypto self-test suite — runs on every boot
 */

#include "crypto_test.h"
#include "awp_protocol.h"
#include "awp_crypto.h"
#include "blake3.h"
#include "api.h"

#include <string.h>
#include <stdio.h>
#include <math.h>
#include "esp_log.h"
#include "esp_timer.h"

/* Default AAD for test encrypt/decrypt calls */
static const uint8_t TEST_AAD[] = { 'a', 'w', 'p', 0, 0, 0, 0 };
#define TEST_AAD_LEN sizeof(TEST_AAD)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "crypto_test";

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    ESP_LOGI(TAG, "  [%d] %s...", tests_run, name); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    ESP_LOGI(TAG, "      PASS"); \
} while(0)

#define FAIL(reason) do { \
    ESP_LOGE(TAG, "      FAIL: %s", reason); \
} while(0)

static int hex_to_bin(const char *hex, uint8_t *out, size_t max_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%2x", &b);
        out[i] = (uint8_t)b;
    }
    return (int)(hex_len / 2);
}

/* ========================================================================= */
/* BLAKE3 Test Vectors (from official test_vectors.json)                     */
/* ========================================================================= */

static bool test_blake3_empty(void)
{
    TEST("BLAKE3: empty input");

    /* BLAKE3("") — from official test vectors */
    const char *expected_hex =
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    blake3_hasher h;
    blake3_hasher_init(&h);
    uint8_t out[32];
    blake3_hasher_finalize(&h, out, 32);

    uint8_t expected[32];
    hex_to_bin(expected_hex, expected, 32);

    if (memcmp(out, expected, 32) == 0) {
        PASS();
        return true;
    }
    FAIL("hash mismatch");
    return false;
}

static bool test_blake3_251bytes(void)
{
    TEST("BLAKE3: 251 sequential bytes (0x00..0xfa)");

    /* BLAKE3(0x00 0x01 0x02 ... 0xfa) — verified with blake3 Python package */
    const char *expected_hex =
        "2a43e6bf5d7dfe202bf9653c94aacb221a20cd5e449602684d9ffbd38d9a8920";

    uint8_t input[251];
    for (int i = 0; i < 251; i++) input[i] = (uint8_t)i;

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, input, 251);
    uint8_t out[32];
    blake3_hasher_finalize(&h, out, 32);

    uint8_t expected[32];
    hex_to_bin(expected_hex, expected, 32);

    if (memcmp(out, expected, 32) == 0) {
        PASS();
        return true;
    }
    FAIL("hash mismatch");
    return false;
}

static bool test_blake3_kdf(void)
{
    TEST("BLAKE3: derive_key (KDF mode)");

    /* Verify KDF produces deterministic output */
    blake3_hasher h1, h2;
    uint8_t out1[32], out2[32];

    blake3_hasher_init_derive_key(&h1, "awp-session-key");
    blake3_hasher_update(&h1, (const uint8_t *)"test-secret", 11);
    blake3_hasher_finalize(&h1, out1, 32);

    blake3_hasher_init_derive_key(&h2, "awp-session-key");
    blake3_hasher_update(&h2, (const uint8_t *)"test-secret", 11);
    blake3_hasher_finalize(&h2, out2, 32);

    if (memcmp(out1, out2, 32) == 0) {
        /* Verify different context produces different key */
        blake3_hasher_init_derive_key(&h2, "different-context");
        blake3_hasher_update(&h2, (const uint8_t *)"test-secret", 11);
        blake3_hasher_finalize(&h2, out2, 32);

        if (memcmp(out1, out2, 32) != 0) {
            PASS();
            return true;
        }
        FAIL("different contexts produced same key");
        return false;
    }
    FAIL("same input produced different output");
    return false;
}

/* ========================================================================= */
/* HChaCha20 Test Vector (RFC draft-irtf-cfrg-xchacha Sec 2.2.1)           */
/* ========================================================================= */


/* ========================================================================= */
/* XChaCha20-Poly1305 Round-Trip                                             */
/* ========================================================================= */

static bool test_xchacha_roundtrip(void)
{
    TEST("XChaCha20-Poly1305: encrypt/decrypt round-trip");

    awp_crypto_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    /* Set a known session key */
    memset(ctx.session_key, 0x42, AWP_KEY_SIZE);
    ctx.session_ready = true;
    ctx.nonce_counter = 100;

    const char *plaintext = "{\"timestamp\":1234567890,\"load\":0.0}";
    size_t pt_len = strlen(plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;

    if (!awp_crypto_encrypt(&ctx, (const uint8_t *)plaintext, pt_len,
                            TEST_AAD, TEST_AAD_LEN, encrypted, &enc_len)) {
        FAIL("encryption failed");
        return false;
    }

    /* Verify encrypted is different from plaintext */
    if (enc_len <= pt_len) {
        FAIL("encrypted data too short");
        return false;
    }

    /* Verify overhead is correct (24 nonce + 16 tag = 40) */
    if (enc_len != pt_len + AWP_ENCRYPT_OVERHEAD) {
        FAIL("wrong overhead size");
        return false;
    }

    /* Decrypt */
    uint8_t decrypted[256];
    size_t dec_len = 0;

    if (!awp_crypto_decrypt(&ctx, encrypted, enc_len, TEST_AAD, TEST_AAD_LEN, decrypted, &dec_len)) {
        FAIL("decryption failed");
        return false;
    }

    if (dec_len != pt_len) {
        FAIL("decrypted length mismatch");
        return false;
    }

    if (memcmp(decrypted, plaintext, pt_len) != 0) {
        FAIL("decrypted data mismatch");
        return false;
    }

    PASS();
    return true;
}

static bool test_xchacha_tamper_detect(void)
{
    TEST("XChaCha20-Poly1305: tamper detection");

    awp_crypto_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    memset(ctx.session_key, 0x42, AWP_KEY_SIZE);
    ctx.session_ready = true;
    ctx.nonce_counter = 200;

    const char *plaintext = "secret data";
    size_t pt_len = strlen(plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;
    awp_crypto_encrypt(&ctx, (const uint8_t *)plaintext, pt_len,
                       TEST_AAD, TEST_AAD_LEN, encrypted, &enc_len);

    /* Flip one bit in the ciphertext */
    encrypted[AWP_XCNONCE_SIZE + 3] ^= 0x01;

    uint8_t decrypted[256];
    size_t dec_len = 0;
    if (awp_crypto_decrypt(&ctx, encrypted, enc_len, TEST_AAD, TEST_AAD_LEN, decrypted, &dec_len)) {
        FAIL("tampered ciphertext was accepted");
        return false;
    }

    PASS();
    return true;
}

static bool test_xchacha_wrong_key(void)
{
    TEST("XChaCha20-Poly1305: wrong key rejection");

    awp_crypto_t ctx1, ctx2;
    memset(&ctx1, 0, sizeof(ctx1));
    memset(&ctx2, 0, sizeof(ctx2));
    memset(ctx1.session_key, 0x42, AWP_KEY_SIZE);
    memset(ctx2.session_key, 0x43, AWP_KEY_SIZE);  /* Different key */
    ctx1.session_ready = true;
    ctx2.session_ready = true;
    ctx1.nonce_counter = 300;

    const char *plaintext = "secret data";
    size_t pt_len = strlen(plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;
    awp_crypto_encrypt(&ctx1, (const uint8_t *)plaintext, pt_len, TEST_AAD, TEST_AAD_LEN,
                       encrypted, &enc_len);

    uint8_t decrypted[256];
    size_t dec_len = 0;
    if (awp_crypto_decrypt(&ctx2, encrypted, enc_len, TEST_AAD, TEST_AAD_LEN, decrypted, &dec_len)) {
        FAIL("wrong key was accepted");
        return false;
    }

    PASS();
    return true;
}

static bool test_xchacha_nonce_uniqueness(void)
{
    TEST("XChaCha20-Poly1305: nonce uniqueness");

    awp_crypto_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    memset(ctx.session_key, 0x42, AWP_KEY_SIZE);
    ctx.session_ready = true;
    ctx.nonce_counter = 400;

    const char *plaintext = "same data";
    size_t pt_len = strlen(plaintext);

    uint8_t enc1[256], enc2[256];
    size_t len1 = 0, len2 = 0;

    awp_crypto_encrypt(&ctx, (const uint8_t *)plaintext, pt_len, TEST_AAD, TEST_AAD_LEN, enc1, &len1);
    awp_crypto_encrypt(&ctx, (const uint8_t *)plaintext, pt_len, TEST_AAD, TEST_AAD_LEN, enc2, &len2);

    /* Same plaintext, different nonces → different ciphertext */
    if (len1 == len2 && memcmp(enc1, enc2, len1) == 0) {
        FAIL("same plaintext produced identical ciphertext (nonce reuse!)");
        return false;
    }

    PASS();
    return true;
}

/* ========================================================================= */
/* ML-KEM-768 Tests                                                          */
/* ========================================================================= */

static bool test_mlkem_roundtrip(void)
{
    TEST("ML-KEM-768: keygen + encap/decap round-trip");

    static uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
    static uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
    uint8_t ss_enc[pqcrystals_kyber768_BYTES];
    uint8_t ss_dec[pqcrystals_kyber768_BYTES];

    int64_t t0 = esp_timer_get_time();
    int ret = pqcrystals_kyber768_ref_keypair(pk, sk);
    int64_t t_keygen = esp_timer_get_time() - t0;
    vTaskDelay(1); /* yield to prevent interrupt WDT */

    if (ret != 0) {
        FAIL("keypair generation failed");
        return false;
    }

    t0 = esp_timer_get_time();
    ret = pqcrystals_kyber768_ref_enc(ct, ss_enc, pk);
    int64_t t_encap = esp_timer_get_time() - t0;
    vTaskDelay(1);

    if (ret != 0) {
        FAIL("encapsulation failed");
        return false;
    }

    t0 = esp_timer_get_time();
    ret = pqcrystals_kyber768_ref_dec(ss_dec, ct, sk);
    int64_t t_decap = esp_timer_get_time() - t0;

    if (ret != 0) {
        FAIL("decapsulation failed");
        return false;
    }

    if (memcmp(ss_enc, ss_dec, pqcrystals_kyber768_BYTES) != 0) {
        FAIL("shared secrets don't match");
        return false;
    }

    ESP_LOGI(TAG, "      keygen=%lldus encap=%lldus decap=%lldus",
             t_keygen, t_encap, t_decap);
    PASS();
    return true;
}

static bool test_mlkem_wrong_sk(void)
{
    TEST("ML-KEM-768: wrong secret key produces different shared secret");

    /* Static to avoid stack overflow — these are huge */
    static uint8_t pk1[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t sk1[pqcrystals_kyber768_SECRETKEYBYTES];
    static uint8_t pk2[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t sk2[pqcrystals_kyber768_SECRETKEYBYTES];
    static uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
    uint8_t ss_enc[pqcrystals_kyber768_BYTES];
    uint8_t ss_wrong[pqcrystals_kyber768_BYTES];

    pqcrystals_kyber768_ref_keypair(pk1, sk1);
    vTaskDelay(1); /* yield to prevent interrupt WDT */
    pqcrystals_kyber768_ref_keypair(pk2, sk2);
    vTaskDelay(1);

    /* Encapsulate with pk1 */
    pqcrystals_kyber768_ref_enc(ct, ss_enc, pk1);
    vTaskDelay(1);

    /* Decapsulate with sk2 (wrong key) */
    pqcrystals_kyber768_ref_dec(ss_wrong, ct, sk2);

    if (memcmp(ss_enc, ss_wrong, pqcrystals_kyber768_BYTES) == 0) {
        FAIL("wrong secret key produced matching shared secret");
        return false;
    }

    PASS();
    return true;
}

/* ========================================================================= */
/* Cross-Platform Interop Tests                                              */
/* ========================================================================= */

static bool test_interop_python_decrypt(void)
{
    TEST("INTEROP: decrypt Python-produced XChaCha20-Poly1305 ciphertext");

    /* Cross-platform test vector */
    const char *key_hex =
        "4ff678b9addbc0d19aeec97f3da28079484c75789a3807dfce5bf4d66699263c";
    const char *encrypted_hex =
        "00000000000001f500000000000000000000000000000000"
        "f1d3ec7c17bc216854043019f19300c25bc671e4e292ed77"
        "acd20d800ce9d2261b1693ec36c4c6181a";
    const char *expected_plaintext = "{\"test\":\"cross-platform\"}";

    uint8_t key[32], encrypted[128];
    hex_to_bin(key_hex, key, 32);
    int enc_len = hex_to_bin(encrypted_hex, encrypted, sizeof(encrypted));

    awp_crypto_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.session_key, key, 32);
    ctx.session_ready = true;

    uint8_t decrypted[128];
    size_t dec_len = 0;

    /* This test vector was generated with Python using aad=b"awp" (3 bytes).
     * Use the original AAD to verify cross-platform compatibility. */
    static const uint8_t interop_aad[] = { 'a', 'w', 'p' };
    if (!awp_crypto_decrypt(&ctx, encrypted, enc_len, interop_aad, 3, decrypted, &dec_len)) {
        FAIL("decryption of Python ciphertext failed");
        return false;
    }

    if (dec_len != strlen(expected_plaintext)) {
        FAIL("decrypted length mismatch");
        return false;
    }

    if (memcmp(decrypted, expected_plaintext, dec_len) != 0) {
        FAIL("decrypted content mismatch");
        return false;
    }

    PASS();
    return true;
}

static bool test_interop_blake3_kdf_match(void)
{
    TEST("INTEROP: BLAKE3 KDF matches Python blake3.derive_key_context");

    /* Cross-platform KDF test vector */
    const char *expected_hex =
        "4ff678b9addbc0d19aeec97f3da28079484c75789a3807dfce5bf4d66699263c";

    uint8_t shared_secret[32];
    memset(shared_secret, 0xAA, 32);

    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "awp-session-key");
    blake3_hasher_update(&h, shared_secret, 32);
    uint8_t out[32];
    blake3_hasher_finalize(&h, out, 32);

    uint8_t expected[32];
    hex_to_bin(expected_hex, expected, 32);

    if (memcmp(out, expected, 32) != 0) {
        FAIL("KDF output doesn't match Python");
        return false;
    }

    PASS();
    return true;
}

/* ========================================================================= */
/* AWP Frame Encode/Decode Round-Trip                                        */
/* ========================================================================= */

static bool test_awp_frame_roundtrip(void)
{
    TEST("AWP: frame encode/decode round-trip with BLAKE3 checksum");

    awp_frame_t original = {
        .msg_type = 0x01,  /* PING */
        .flags = 0x0004,   /* FLAG_PRIORITY */
        .version = 0x0001,
        .node_id = "test-node-1234",
        .payload = (uint8_t *)"hello awp",
        .payload_len = 9,
        .has_tenant_hv = false,
        .has_session_id = false,
    };
    memset(original.hdc_signature, 0xAB, AWP_HDC_SIG_SIZE);

    uint8_t buf[2048];
    size_t enc_len = 0;

    awp_err_t err = awp_encode_frame(&original, buf, sizeof(buf), &enc_len);
    if (err != AWP_OK) {
        FAIL("encode failed");
        return false;
    }

    awp_frame_t decoded;
    err = awp_decode_frame(buf, enc_len, &decoded);
    if (err != AWP_OK) {
        FAIL("decode failed");
        return false;
    }

    if (decoded.msg_type != original.msg_type) { FAIL("msg_type mismatch"); return false; }
    if (decoded.flags != original.flags) { FAIL("flags mismatch"); return false; }
    if (decoded.version != original.version) { FAIL("version mismatch"); return false; }
    if (strcmp(decoded.node_id, original.node_id) != 0) { FAIL("node_id mismatch"); return false; }
    if (decoded.payload_len != original.payload_len) { FAIL("payload_len mismatch"); return false; }
    if (memcmp(decoded.payload, original.payload, original.payload_len) != 0) { FAIL("payload mismatch"); return false; }
    /* HDC signature is always zeroed on the wire (real sig is in encrypted payload) */
    uint8_t zero_hdc[AWP_HDC_SIG_SIZE] = {0};
    if (memcmp(decoded.hdc_signature, zero_hdc, AWP_HDC_SIG_SIZE) != 0) { FAIL("hdc_sig should be zeroed on wire"); return false; }

    PASS();
    return true;
}

static bool test_awp_frame_checksum_tamper(void)
{
    TEST("AWP: BLAKE3 checksum detects tampering");

    awp_frame_t frame = {
        .msg_type = 0x01,
        .version = 0x0001,
        .node_id = "tamper-test",
        .payload = (uint8_t *)"data",
        .payload_len = 4,
    };

    uint8_t buf[2048];
    size_t enc_len = 0;
    awp_encode_frame(&frame, buf, sizeof(buf), &enc_len);

    /* Flip a byte in the payload area */
    buf[AWP_OFF_PAYLOAD + 1] ^= 0xFF;

    awp_frame_t decoded;
    awp_err_t err = awp_decode_frame(buf, enc_len, &decoded);
    if (err == AWP_OK) {
        FAIL("tampered frame was accepted");
        return false;
    }
    if (err != AWP_ERR_CHECKSUM) {
        FAIL("expected checksum error");
        return false;
    }

    PASS();
    return true;
}

/* ========================================================================= */
/* Stack Profiling Tasks                                                     */
/* ========================================================================= */

static SemaphoreHandle_t s_profile_sem = NULL;
static volatile UBaseType_t s_profile_hwm = 0;

static void profile_keygen_task(void *arg)
{
    (void)arg;
    static uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
    pqcrystals_kyber768_ref_keypair(pk, sk);
    s_profile_hwm = uxTaskGetStackHighWaterMark(NULL);
    xSemaphoreGive(s_profile_sem);
    vTaskDelete(NULL);
}

static void profile_encap_task(void *arg)
{
    (void)arg;
    static uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
    static uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
    uint8_t ss[pqcrystals_kyber768_BYTES];
    pqcrystals_kyber768_ref_keypair(pk, sk);
    vTaskDelay(1);
    pqcrystals_kyber768_ref_enc(ct, ss, pk);
    s_profile_hwm = uxTaskGetStackHighWaterMark(NULL);
    xSemaphoreGive(s_profile_sem);
    vTaskDelete(NULL);
}

static void profile_decap_task(void *arg)
{
    (void)arg;
    static uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
    static uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
    uint8_t ss_enc[pqcrystals_kyber768_BYTES];
    uint8_t ss_dec[pqcrystals_kyber768_BYTES];
    pqcrystals_kyber768_ref_keypair(pk, sk);
    vTaskDelay(1);
    pqcrystals_kyber768_ref_enc(ct, ss_enc, pk);
    vTaskDelay(1);
    pqcrystals_kyber768_ref_dec(ss_dec, ct, sk);
    s_profile_hwm = uxTaskGetStackHighWaterMark(NULL);
    xSemaphoreGive(s_profile_sem);
    vTaskDelete(NULL);
}

static void profile_xchacha_task(void *arg)
{
    (void)arg;
    awp_crypto_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    memset(ctx.session_key, 0x42, AWP_KEY_SIZE);
    ctx.session_ready = true;
    ctx.nonce_counter = 1;

    const char *pt = "{\"timestamp\":1234567890.123,\"load\":0.0}";
    uint8_t enc[256], dec[256];
    size_t enc_len = 0, dec_len = 0;
    awp_crypto_encrypt(&ctx, (const uint8_t *)pt, strlen(pt), TEST_AAD, TEST_AAD_LEN, enc, &enc_len);
    awp_crypto_decrypt(&ctx, enc, enc_len, TEST_AAD, TEST_AAD_LEN, dec, &dec_len);
    s_profile_hwm = uxTaskGetStackHighWaterMark(NULL);
    xSemaphoreGive(s_profile_sem);
    vTaskDelete(NULL);
}

static void profile_blake3_task(void *arg)
{
    (void)arg;
    blake3_hasher h;
    uint8_t data[1024], out[32];
    memset(data, 0xAB, sizeof(data));
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, sizeof(data));
    blake3_hasher_finalize(&h, out, 32);
    s_profile_hwm = uxTaskGetStackHighWaterMark(NULL);
    xSemaphoreGive(s_profile_sem);
    vTaskDelete(NULL);
}

static void run_profile(const char *name, TaskFunction_t fn, uint32_t stack_bytes);

static void profiler_runner(void *arg)
{
    volatile bool *done = (volatile bool *)arg;
    run_profile("BLAKE3 (1KB hash)", profile_blake3_task, 16384);
    run_profile("ML-KEM keygen", profile_keygen_task, 32768);
    run_profile("ML-KEM encap", profile_encap_task, 32768);
    run_profile("ML-KEM full cycle", profile_decap_task, 32768);
    run_profile("XChaCha20 enc+dec", profile_xchacha_task, 16384);
    *done = true;
    vTaskDelete(NULL);
}

static void run_profile(const char *name, TaskFunction_t fn, uint32_t stack_bytes)
{
    s_profile_hwm = 0;
    xTaskCreate(fn, name, stack_bytes / sizeof(StackType_t), NULL, 5, NULL);
    if (xSemaphoreTake(s_profile_sem, pdMS_TO_TICKS(10000)) == pdTRUE) {
        uint32_t free_bytes = s_profile_hwm * sizeof(StackType_t);
        uint32_t peak = stack_bytes - free_bytes;
        ESP_LOGI(TAG, "  %-20s  alloc=%5lu  peak=%5lu  free=%5lu bytes",
                 name, (unsigned long)stack_bytes, (unsigned long)peak, (unsigned long)free_bytes);
    } else {
        ESP_LOGE(TAG, "  %-20s  TIMEOUT (stack overflow?)", name);
    }
}

/* ========================================================================= */
/* Statistical Bench Helper                                                  */
/* ========================================================================= */

static void bench_report(const char *name, float *times, int n)
{
    float sum = 0, sum2 = 0, mn = 1e9f, mx = 0;
    for (int i = 0; i < n; i++) {
        sum += times[i]; sum2 += times[i] * times[i];
        if (times[i] < mn) mn = times[i];
        if (times[i] > mx) mx = times[i];
    }
    float mean = sum / n;
    float var = (sum2 / n) - (mean * mean);
    float sd = (var > 0) ? sqrtf(var) : 0;
    ESP_LOGI(TAG, "  %-20s mean=%7.0fus  sd=%5.0fus  min=%7.0fus  max=%7.0fus",
             name, mean, sd, mn, mx);
}

/* ========================================================================= */
/* Replay Window                                                             */
/* ========================================================================= */

static bool test_replay_window(void)
{
    TEST("Replay window: accept / duplicate / too-old");

    awp_crypto_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Nonce 0 is never valid. */
    if (awp_crypto_replay_check(&ctx, 0)) {
        FAIL("nonce 0 was accepted");
        return false;
    }

    /* Fresh counter 1 accepts, duplicate rejects. */
    if (!awp_crypto_replay_check(&ctx, 1)) {
        FAIL("fresh counter 1 rejected");
        return false;
    }
    if (awp_crypto_replay_check(&ctx, 1)) {
        FAIL("duplicate counter 1 accepted");
        return false;
    }

    /* Jump ahead — shifts the window forward. Counter 5 accepts. */
    if (!awp_crypto_replay_check(&ctx, 5)) {
        FAIL("jump-ahead counter 5 rejected");
        return false;
    }
    if (awp_crypto_replay_check(&ctx, 5)) {
        FAIL("duplicate counter 5 accepted");
        return false;
    }

    /* Out-of-order counter 3 is unseen and in-window — must accept. */
    if (!awp_crypto_replay_check(&ctx, 3)) {
        FAIL("in-window unseen counter 3 rejected");
        return false;
    }
    /* Now 3 is marked seen — duplicate must reject. */
    if (awp_crypto_replay_check(&ctx, 3)) {
        FAIL("duplicate counter 3 accepted after insertion");
        return false;
    }

    /* Counter 2 is also in-window and still unseen — must accept. */
    if (!awp_crypto_replay_check(&ctx, 2)) {
        FAIL("in-window unseen counter 2 rejected");
        return false;
    }

    /* Jump far forward. Old counters become too-old. */
    if (!awp_crypto_replay_check(&ctx, 10000)) {
        FAIL("big jump rejected");
        return false;
    }
    if (awp_crypto_replay_check(&ctx, 5)) {
        FAIL("too-old counter 5 accepted after big jump");
        return false;
    }

    /* Counter just inside the window should still accept. */
    uint64_t inside = 10000 - (AWP_REPLAY_WINDOW - 1);
    if (!awp_crypto_replay_check(&ctx, inside)) {
        FAIL("counter at window edge was rejected");
        return false;
    }
    /* Counter just outside the window must reject. */
    uint64_t outside = 10000 - AWP_REPLAY_WINDOW;
    if (awp_crypto_replay_check(&ctx, outside)) {
        FAIL("counter outside window was accepted");
        return false;
    }

    PASS();
    return true;
}

/* ========================================================================= */
/* Run All Tests                                                             */
/* ========================================================================= */

bool crypto_self_test(void)
{
    tests_run = 0;
    tests_passed = 0;

    int64_t t0 = esp_timer_get_time();

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  Crypto Self-Test Suite");
    ESP_LOGI(TAG, "========================================");

    ESP_LOGI(TAG, "--- BLAKE3 ---");
    test_blake3_empty();
    test_blake3_251bytes();
    test_blake3_kdf();

    ESP_LOGI(TAG, "--- XChaCha20-Poly1305 ---");
    test_xchacha_roundtrip();
    test_xchacha_tamper_detect();
    test_xchacha_wrong_key();
    test_xchacha_nonce_uniqueness();

    ESP_LOGI(TAG, "--- ML-KEM-768 ---");
    test_mlkem_roundtrip();
    test_mlkem_wrong_sk();

    ESP_LOGI(TAG, "--- Cross-Platform Interop ---");
    test_interop_blake3_kdf_match();
    test_interop_python_decrypt();

    ESP_LOGI(TAG, "--- Replay Window ---");
    test_replay_window();

    ESP_LOGI(TAG, "--- AWP Frames ---");
    test_awp_frame_roundtrip();
    test_awp_frame_checksum_tamper();

    int64_t elapsed = (esp_timer_get_time() - t0) / 1000;

    ESP_LOGI(TAG, "========================================");
    if (tests_passed == tests_run) {
        ESP_LOGI(TAG, "  ALL %d TESTS PASSED (%lldms)", tests_run, elapsed);
    } else {
        ESP_LOGE(TAG, "  %d/%d TESTS FAILED (%lldms)",
                 tests_run - tests_passed, tests_run, elapsed);
    }
    ESP_LOGI(TAG, "========================================");

    /* Stack watermark profiling */
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "--- Stack Watermarks ---");

    UBaseType_t main_hwm = uxTaskGetStackHighWaterMark(NULL);
    uint32_t main_alloc = CONFIG_ESP_MAIN_TASK_STACK_SIZE;
    ESP_LOGI(TAG, "  %-20s  alloc=%5lu  peak=%5lu  free=%5lu bytes",
             "main (after tests)", (unsigned long)main_alloc,
             (unsigned long)(main_alloc - (unsigned)(main_hwm * sizeof(StackType_t))),
             (unsigned long)(main_hwm * sizeof(StackType_t)));

    if (!s_profile_sem) s_profile_sem = xSemaphoreCreateBinary();

    run_profile("BLAKE3 (1KB hash)", profile_blake3_task, 16384);
    run_profile("ML-KEM keygen", profile_keygen_task, 32768);
    run_profile("ML-KEM encap", profile_encap_task, 32768);
    run_profile("ML-KEM full cycle", profile_decap_task, 32768);
    run_profile("XChaCha20 enc+dec", profile_xchacha_task, 16384);

    /* ================================================================= */
    /* Statistical Timing (N iterations, mean/stddev/min/max)            */
    /* ================================================================= */

    #define BENCH_N 50

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "--- Statistical Timing (%d iterations) ---", BENCH_N);

    /* Static buffers for ML-KEM ops */
    static uint8_t b_pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    static uint8_t b_sk[pqcrystals_kyber768_SECRETKEYBYTES];
    static uint8_t b_ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
    uint8_t b_ss[pqcrystals_kyber768_BYTES];

    float times[BENCH_N];

    /* BLAKE3 1KB hash */
    for (int i = 0; i < BENCH_N; i++) {
        blake3_hasher h; uint8_t data[1024]; uint8_t out[32];
        memset(data, 0xAB, 1024);
        int64_t t = esp_timer_get_time();
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, data, 1024);
        blake3_hasher_finalize(&h, out, 32);
        times[i] = (float)(esp_timer_get_time() - t);
        vTaskDelay(1);
    }
    bench_report("BLAKE3 (1KB)", times, BENCH_N);

    /* ML-KEM keygen */
    for (int i = 0; i < BENCH_N; i++) {
        int64_t t = esp_timer_get_time();
        pqcrystals_kyber768_ref_keypair(b_pk, b_sk);
        times[i] = (float)(esp_timer_get_time() - t);
        vTaskDelay(1);
    }
    bench_report("ML-KEM keygen", times, BENCH_N);

    /* ML-KEM encap */
    pqcrystals_kyber768_ref_keypair(b_pk, b_sk);
    for (int i = 0; i < BENCH_N; i++) {
        int64_t t = esp_timer_get_time();
        pqcrystals_kyber768_ref_enc(b_ct, b_ss, b_pk);
        times[i] = (float)(esp_timer_get_time() - t);
        vTaskDelay(1);
    }
    bench_report("ML-KEM encap", times, BENCH_N);

    /* ML-KEM decap */
    pqcrystals_kyber768_ref_enc(b_ct, b_ss, b_pk);
    for (int i = 0; i < BENCH_N; i++) {
        int64_t t = esp_timer_get_time();
        pqcrystals_kyber768_ref_dec(b_ss, b_ct, b_sk);
        times[i] = (float)(esp_timer_get_time() - t);
        vTaskDelay(1);
    }
    bench_report("ML-KEM decap", times, BENCH_N);

    /* XChaCha20 encrypt */
    {
        awp_crypto_t cx;
        memset(&cx, 0, sizeof(cx));
        memset(cx.session_key, 0x42, AWP_KEY_SIZE);
        cx.session_ready = true;
        const char *pt = "{\"ts\":12345,\"v\":0.0}";
        for (int i = 0; i < BENCH_N; i++) {
            cx.nonce_counter = i + 1;
            uint8_t enc[128]; size_t elen = 0;
            int64_t t = esp_timer_get_time();
            awp_crypto_encrypt(&cx, (const uint8_t *)pt, strlen(pt), TEST_AAD, TEST_AAD_LEN, enc, &elen);
            times[i] = (float)(esp_timer_get_time() - t);
            vTaskDelay(1);
        }
    }
    bench_report("XChaCha20 enc", times, BENCH_N);

    /* BLAKE3 KDF */
    for (int i = 0; i < BENCH_N; i++) {
        blake3_hasher h; uint8_t in[32]; uint8_t out[32];
        memset(in, 0xAA, 32);
        int64_t t = esp_timer_get_time();
        blake3_hasher_init_derive_key(&h, "awp-session-key");
        blake3_hasher_update(&h, in, 32);
        blake3_hasher_finalize(&h, out, 32);
        times[i] = (float)(esp_timer_get_time() - t);
        vTaskDelay(1);
    }
    bench_report("BLAKE3 KDF", times, BENCH_N);

    /* AWP frame encode+decode */
    for (int i = 0; i < BENCH_N; i++) {
        awp_frame_t f;
        memset(&f, 0, sizeof(f));
        f.msg_type = 0x01; f.version = 0x0001;
        strncpy(f.node_id, "bench", AWP_NODE_ID_SIZE);
        f.payload = (uint8_t *)"test"; f.payload_len = 4;
        memset(f.hdc_signature, 0x42, AWP_HDC_SIG_SIZE);
        uint8_t buf[2048]; size_t len = 0;
        int64_t t = esp_timer_get_time();
        awp_encode_frame(&f, buf, sizeof(buf), &len);
        awp_frame_t d;
        awp_decode_frame(buf, len, &d);
        times[i] = (float)(esp_timer_get_time() - t);
        vTaskDelay(1);
    }
    bench_report("AWP frame enc+dec", times, BENCH_N);

    return tests_passed == tests_run;
}
