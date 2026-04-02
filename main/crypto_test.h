/**
 * Crypto Self-Test — BLAKE3 + XChaCha20-Poly1305 test vectors
 *
 * Runs on boot. If any test fails, logs an error and halts.
 * Proves the ESP32's crypto implementations match the spec.
 */

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run all crypto self-tests. Returns true if all pass.
 * Logs each test result. Intended to run once at boot.
 */
bool crypto_self_test(void);

#ifdef __cplusplus
}
#endif
