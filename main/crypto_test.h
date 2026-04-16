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
 *
 * When CONFIG_AWP_INCLUDE_SELF_TESTS is disabled (audit F-08), this
 * resolves to a stub that returns true — tests are compiled out.
 */
#if CONFIG_AWP_INCLUDE_SELF_TESTS
bool crypto_self_test(void);
#else
static inline bool crypto_self_test(void) { return true; }
#endif

#ifdef __cplusplus
}
#endif
