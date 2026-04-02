/**
 * randombytes implementation for ESP32 (mlkem-native compatible)
 * Uses ESP32 hardware true random number generator.
 */
#include "src/randombytes.h"
#include "esp_random.h"

void randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
}
