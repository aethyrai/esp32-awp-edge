/**
 * AWP Frame Decoder Fuzzer
 *
 * Compiles natively (not ESP-IDF) and feeds random/malformed data
 * into awp_decode_frame() and awp_stream_feed() to find crashes.
 *
 * Build:
 *   cc -fsanitize=address,undefined -g -O1 \
 *      -I../main -I../components/blake3 \
 *      -DAWP_FUZZ_HOST \
 *      test/fuzz_awp.c ../main/awp_protocol.c ../main/awp_stream.c \
 *      ../components/blake3/blake3.c ../components/blake3/blake3_portable.c \
 *      ../components/blake3/blake3_dispatch.c \
 *      -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_NO_NEON \
 *      -o fuzz_awp && ./fuzz_awp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Stub out ESP-IDF logging for host build */
#define AWP_FUZZ_HOST
#define ESP_LOGE(tag, fmt, ...) ((void)0)
#define ESP_LOGW(tag, fmt, ...) ((void)0)
#define ESP_LOGI(tag, fmt, ...) ((void)0)
#define ESP_LOGD(tag, fmt, ...) ((void)0)

#include "awp_protocol.h"
#include "awp_stream.h"

static uint64_t total_decode_calls = 0;
static uint64_t total_stream_calls = 0;
static uint64_t decode_ok = 0;
static uint64_t decode_err = 0;

/* ========================================================================= */
/* Test 1: Random bytes into decode_frame                                    */
/* ========================================================================= */

static void fuzz_decode_random(int iterations)
{
    printf("[1] Fuzzing awp_decode_frame with random bytes (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Random length: 0 to 2048 */
        size_t len = rand() % 2048;
        uint8_t *data = malloc(len + 1);
        if (!data) continue;

        for (size_t j = 0; j < len; j++)
            data[j] = rand() & 0xFF;

        awp_frame_t frame;
        awp_err_t err = awp_decode_frame(data, len, &frame);
        total_decode_calls++;
        if (err == AWP_OK) decode_ok++;
        else decode_err++;

        free(data);
    }

    printf("    done: %llu ok, %llu err\n", decode_ok, decode_err);
}

/* ========================================================================= */
/* Test 2: Valid header + garbage payload                                     */
/* ========================================================================= */

static void fuzz_decode_valid_header(int iterations)
{
    printf("[2] Fuzzing with valid AWP header + random payload (%d iterations)...\n", iterations);

    uint64_t ok = 0, err = 0;

    for (int i = 0; i < iterations; i++) {
        size_t payload_len = rand() % 1024;
        size_t total = AWP_HEADER_SIZE + payload_len + AWP_CHECKSUM_SIZE;
        uint8_t *data = malloc(total);
        if (!data) continue;

        /* Valid magic */
        data[0] = 0xAE; data[1] = 0x37; data[2] = 0x00; data[3] = 0x00;
        /* Valid version */
        data[4] = 0x00; data[5] = 0x01;
        /* Random flags */
        data[6] = rand() & 0xFF; data[7] = rand() & 0xFF;
        /* Correct length */
        data[8] = (total >> 24) & 0xFF;
        data[9] = (total >> 16) & 0xFF;
        data[10] = (total >> 8) & 0xFF;
        data[11] = total & 0xFF;

        /* Random rest */
        for (size_t j = 12; j < total; j++)
            data[j] = rand() & 0xFF;

        awp_frame_t frame;
        awp_err_t e = awp_decode_frame(data, total, &frame);
        total_decode_calls++;
        if (e == AWP_OK) ok++;
        else err++;

        free(data);
    }

    printf("    done: %llu ok, %llu err (checksum should reject most)\n", ok, err);
}

/* ========================================================================= */
/* Test 3: Random bytes into stream reader                                   */
/* ========================================================================= */

static void fuzz_stream_random(int iterations)
{
    printf("[3] Fuzzing awp_stream_feed with random TCP chunks (%d iterations)...\n", iterations);

    awp_stream_t stream;
    awp_stream_init(&stream);

    awp_frame_t frames[AWP_STREAM_MAX_FRAMES];
    uint64_t frames_decoded = 0;

    for (int i = 0; i < iterations; i++) {
        size_t chunk_len = rand() % 512;
        uint8_t chunk[512];
        for (size_t j = 0; j < chunk_len; j++)
            chunk[j] = rand() & 0xFF;

        size_t count = 0;
        awp_stream_feed(&stream, chunk, chunk_len, frames, AWP_STREAM_MAX_FRAMES, &count);
        total_stream_calls++;
        frames_decoded += count;
    }

    printf("    done: %llu feeds, %llu frames decoded, %u errors\n",
           total_stream_calls, frames_decoded, stream.err_count);
}

/* ========================================================================= */
/* Test 4: Truncated frames                                                  */
/* ========================================================================= */

static void fuzz_truncated_frames(int iterations)
{
    printf("[4] Fuzzing with truncated valid frames (%d iterations)...\n", iterations);

    /* Build a valid frame first */
    awp_frame_t valid = {
        .msg_type = 0x01,
        .flags = 0,
        .version = 0x0001,
        .node_id = "fuzz-node",
        .payload = (uint8_t *)"test payload data",
        .payload_len = 17,
    };
    memset(valid.hdc_signature, 0x42, AWP_HDC_SIG_SIZE);

    uint8_t full_frame[2048];
    size_t full_len = 0;
    awp_encode_frame(&valid, full_frame, sizeof(full_frame), &full_len);

    uint64_t ok = 0, err = 0;

    for (int i = 0; i < iterations; i++) {
        /* Truncate at random point */
        size_t trunc_len = rand() % (full_len + 1);

        awp_frame_t decoded;
        awp_err_t e = awp_decode_frame(full_frame, trunc_len, &decoded);
        total_decode_calls++;
        if (e == AWP_OK) ok++;
        else err++;
    }

    printf("    done: %llu ok, %llu err\n", ok, err);
}

/* ========================================================================= */
/* Test 5: Bit-flip on valid frame                                           */
/* ========================================================================= */

static void fuzz_bitflip(int iterations)
{
    printf("[5] Fuzzing with single bit-flips on valid frame (%d iterations)...\n", iterations);

    awp_frame_t valid = {
        .msg_type = 0x01,
        .flags = 0,
        .version = 0x0001,
        .node_id = "bitflip-node",
        .payload = (uint8_t *)"important data",
        .payload_len = 14,
    };
    memset(valid.hdc_signature, 0x55, AWP_HDC_SIG_SIZE);

    uint8_t original[2048];
    size_t orig_len = 0;
    awp_encode_frame(&valid, original, sizeof(original), &orig_len);

    uint64_t accepted = 0, rejected = 0;

    for (int i = 0; i < iterations; i++) {
        uint8_t flipped[2048];
        memcpy(flipped, original, orig_len);

        /* Flip one random bit */
        size_t byte_pos = rand() % orig_len;
        int bit_pos = rand() % 8;
        flipped[byte_pos] ^= (1 << bit_pos);

        awp_frame_t decoded;
        awp_err_t e = awp_decode_frame(flipped, orig_len, &decoded);
        total_decode_calls++;
        if (e == AWP_OK) accepted++;
        else rejected++;
    }

    printf("    done: %llu accepted (SHOULD BE 0), %llu rejected\n", accepted, rejected);
    if (accepted > 0) {
        printf("    WARNING: %llu bit-flipped frames passed checksum!\n", accepted);
    }
}

/* ========================================================================= */
/* Test 6: Extreme lengths in header                                         */
/* ========================================================================= */

static void fuzz_extreme_lengths(void)
{
    printf("[6] Testing extreme length values in header...\n");

    uint32_t lengths[] = {
        0, 1, 2, 669, 670, 671,  /* around minimum */
        0xFFFF, 0xFFFFFF, 0x01000000,  /* large */
        0x7FFFFFFF, 0xFFFFFFFF,  /* max */
    };

    for (int i = 0; i < (int)(sizeof(lengths)/sizeof(lengths[0])); i++) {
        uint8_t hdr[12] = {
            0xAE, 0x37, 0x00, 0x00,  /* magic */
            0x00, 0x01,              /* version */
            0x00, 0x00,              /* flags */
        };
        uint32_t len = lengths[i];
        hdr[8] = (len >> 24) & 0xFF;
        hdr[9] = (len >> 16) & 0xFF;
        hdr[10] = (len >> 8) & 0xFF;
        hdr[11] = len & 0xFF;

        awp_frame_t frame;
        awp_err_t e = awp_decode_frame(hdr, 12, &frame);
        total_decode_calls++;
        printf("    len=0x%08x → %s\n", len, awp_err_str(e));
    }
}

/* ========================================================================= */
/* Main                                                                      */
/* ========================================================================= */

int main(void)
{
    srand(time(NULL));

    printf("========================================\n");
    printf("  AWP Frame Decoder Fuzz Suite\n");
    printf("  AddressSanitizer + UBSan enabled\n");
    printf("========================================\n\n");

    fuzz_decode_random(100000);
    fuzz_decode_valid_header(100000);
    fuzz_stream_random(100000);
    fuzz_truncated_frames(10000);
    fuzz_bitflip(100000);
    fuzz_extreme_lengths();

    printf("\n========================================\n");
    printf("  FUZZ COMPLETE\n");
    printf("  Total decode calls: %llu\n", total_decode_calls);
    printf("  Total stream calls: %llu\n", total_stream_calls);
    printf("  No crashes. No ASan violations.\n");
    printf("========================================\n");

    return 0;
}
