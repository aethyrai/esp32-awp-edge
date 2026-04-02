/**
 * Compatibility header — maps pqcrystals_kyber768_ref_* to mlkem-native API.
 *
 * mlkem-native (v1.0.0) is formally verified:
 *   - CBMC: memory safety, type safety, no undefined behavior
 *   - HOL-Light: constant-time execution (no timing side channels)
 */

#ifndef API_H
#define API_H

#include <stdint.h>

/* ML-KEM-768 sizes */
#define pqcrystals_kyber768_SECRETKEYBYTES   2400
#define pqcrystals_kyber768_PUBLICKEYBYTES   1184
#define pqcrystals_kyber768_CIPHERTEXTBYTES  1088
#define pqcrystals_kyber768_BYTES            32

/* Symbols exported by mlkem-native SCU build */
int PQCP_MLKEM_NATIVE_MLKEM768_keypair(uint8_t *pk, uint8_t *sk);
int PQCP_MLKEM_NATIVE_MLKEM768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCP_MLKEM_NATIVE_MLKEM768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* Function aliases matching old pqcrystals API */
#define pqcrystals_kyber768_ref_keypair  PQCP_MLKEM_NATIVE_MLKEM768_keypair
#define pqcrystals_kyber768_ref_enc      PQCP_MLKEM_NATIVE_MLKEM768_enc
#define pqcrystals_kyber768_ref_dec      PQCP_MLKEM_NATIVE_MLKEM768_dec

#endif
