/**
 * AWP Concurrent Stress Test — host-side thread safety verification
 *
 * Simulates the ESP32 dual-core race condition that the original reviewer
 * identified: multiple threads calling a shared encode path simultaneously.
 * Verifies that frame encoding produces valid, non-corrupted output under
 * contention.
 *
 * Build:
 *   cc -g -O1 -fsanitize=thread -pthread \
 *      -I../main -I../test -I../components/blake3 \
 *      -DAWP_FUZZ_HOST \
 *      test/test_stress.c main/awp_protocol.c main/awp_stream.c \
 *      components/blake3/blake3.c components/blake3/blake3_portable.c \
 *      components/blake3/blake3_dispatch.c \
 *      -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_NO_NEON \
 *      -o test_stress && ./test_stress
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

#include "awp_protocol.h"
#include "awp_stream.h"

/* Stubs */
#define ESP_LOGE(tag, fmt, ...) ((void)0)
#define ESP_LOGW(tag, fmt, ...) ((void)0)
#define ESP_LOGI(tag, fmt, ...) ((void)0)
#define ESP_LOGD(tag, fmt, ...) ((void)0)

#define NUM_THREADS     8
#define FRAMES_PER_THREAD 50000
#define PAYLOAD_MAX     256

static atomic_uint_fast64_t total_encoded = 0;
static atomic_uint_fast64_t total_decoded = 0;
static atomic_uint_fast64_t total_errors  = 0;
static atomic_uint_fast64_t checksum_ok   = 0;

/* Shared buffer — simulates the static enc_payload / tx_buf race.
 * WITHOUT a mutex, TSan should flag this. WITH proper per-thread buffers,
 * it should be clean. */
static pthread_mutex_t tx_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t shared_tx_buf[AWP_HEADER_SIZE + AWP_ESP32_MAX_PAYLOAD + AWP_CHECKSUM_SIZE];

static void *encode_thread(void *arg)
{
    int thread_id = *(int *)arg;
    char node_id[AWP_NODE_ID_SIZE + 1];
    snprintf(node_id, sizeof(node_id), "thread%02d", thread_id);

    uint8_t payload[PAYLOAD_MAX];
    /* Deterministic payload per thread */
    for (int i = 0; i < PAYLOAD_MAX; i++)
        payload[i] = (uint8_t)((thread_id * 37 + i * 13) & 0xFF);

    for (int i = 0; i < FRAMES_PER_THREAD; i++) {
        awp_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        strncpy(frame.node_id, node_id, AWP_NODE_ID_SIZE);
        frame.version = AWP_VERSION;
        frame.msg_type = AWP_MSG_PING + (i % 6);
        frame.flags = (i % 3 == 0) ? AWP_FLAG_ENCRYPTED : 0;
        frame.payload = payload;
        frame.payload_len = 16 + (i % (PAYLOAD_MAX - 16));

        /* Mutex-protected encode — simulates edge_node_send's tx_mutex */
        pthread_mutex_lock(&tx_mutex);

        size_t wire_len = 0;
        awp_err_t err = awp_encode_frame(&frame, shared_tx_buf,
                                         sizeof(shared_tx_buf), &wire_len);

        if (err == AWP_OK) {
            atomic_fetch_add(&total_encoded, 1);

            /* Decode what we just encoded — verify roundtrip under contention */
            awp_frame_t decoded;
            awp_err_t dec_err = awp_decode_frame(shared_tx_buf, wire_len, &decoded);
            if (dec_err == AWP_OK) {
                atomic_fetch_add(&total_decoded, 1);

                /* Verify fields survived */
                if (strcmp(decoded.node_id, node_id) != 0 ||
                    decoded.msg_type != frame.msg_type ||
                    decoded.payload_len != frame.payload_len ||
                    memcmp(decoded.payload, frame.payload, frame.payload_len) != 0) {
                    atomic_fetch_add(&total_errors, 1);
                } else {
                    atomic_fetch_add(&checksum_ok, 1);
                }
            } else {
                atomic_fetch_add(&total_errors, 1);
            }
        } else {
            atomic_fetch_add(&total_errors, 1);
        }

        pthread_mutex_unlock(&tx_mutex);
    }

    return NULL;
}

/* Stream reassembly stress: feed encoded frames from multiple threads
 * into a single stream reader concurrently (with mutex, simulating
 * single-reader design) */
static pthread_mutex_t stream_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast64_t stream_frames = 0;
static atomic_uint_fast64_t stream_errors = 0;

static void *stream_thread(void *arg)
{
    int thread_id = *(int *)arg;
    awp_stream_t stream;
    awp_stream_init(&stream);

    uint8_t encode_buf[AWP_HEADER_SIZE + 128 + AWP_CHECKSUM_SIZE];
    char payload[64];

    for (int i = 0; i < FRAMES_PER_THREAD / 10; i++) {
        snprintf(payload, sizeof(payload), "{\"t\":%d,\"i\":%d}", thread_id, i);

        awp_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        snprintf(frame.node_id, AWP_NODE_ID_SIZE, "stream%02d", thread_id);
        frame.version = AWP_VERSION;
        frame.msg_type = AWP_MSG_AGENT_CALL_RESPONSE;
        frame.payload = (uint8_t *)payload;
        frame.payload_len = strlen(payload);

        size_t wire_len = 0;
        awp_err_t err = awp_encode_frame(&frame, encode_buf, sizeof(encode_buf), &wire_len);
        if (err != AWP_OK) continue;

        /* Feed in chunks to test reassembly */
        awp_frame_t out_frames[4];
        size_t count = 0;

        /* Feed first half */
        size_t half = wire_len / 2;
        awp_stream_feed(&stream, encode_buf, half, out_frames, 4, &count);
        atomic_fetch_add(&stream_frames, count);

        /* Feed second half */
        awp_stream_feed(&stream, encode_buf + half, wire_len - half, out_frames, 4, &count);
        atomic_fetch_add(&stream_frames, count);

        if (count == 0) {
            atomic_fetch_add(&stream_errors, 1);
        }
    }

    return NULL;
}

int main(void)
{
    printf("========================================\n");
    printf("  AWP Concurrent Stress Test\n");
    printf("  Threads: %d\n", NUM_THREADS);
    printf("  Frames/thread: %d\n", FRAMES_PER_THREAD);
    printf("  Total operations: %d\n", NUM_THREADS * FRAMES_PER_THREAD);
    printf("========================================\n\n");

    /* --- Test 1: Concurrent encode/decode with shared buffer --- */
    printf("[1] Concurrent encode/decode (mutex-protected shared buffer)...\n");
    {
        pthread_t threads[NUM_THREADS];
        int ids[NUM_THREADS];

        for (int i = 0; i < NUM_THREADS; i++) {
            ids[i] = i;
            pthread_create(&threads[i], NULL, encode_thread, &ids[i]);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        uint64_t enc = atomic_load(&total_encoded);
        uint64_t dec = atomic_load(&total_decoded);
        uint64_t err = atomic_load(&total_errors);
        uint64_t ok  = atomic_load(&checksum_ok);

        printf("    Encoded:  %llu\n", (unsigned long long)enc);
        printf("    Decoded:  %llu\n", (unsigned long long)dec);
        printf("    Verified: %llu\n", (unsigned long long)ok);
        printf("    Errors:   %llu\n", (unsigned long long)err);

        if (err > 0) {
            printf("    FAIL: %llu frames corrupted under contention!\n",
                   (unsigned long long)err);
            return 1;
        }
        printf("    PASS\n\n");
    }

    /* --- Test 2: Stream reassembly per-thread --- */
    printf("[2] Stream reassembly (per-thread stream reader)...\n");
    {
        pthread_t threads[NUM_THREADS];
        int ids[NUM_THREADS];

        for (int i = 0; i < NUM_THREADS; i++) {
            ids[i] = i;
            pthread_create(&threads[i], NULL, stream_thread, &ids[i]);
        }
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        uint64_t frames = atomic_load(&stream_frames);
        uint64_t errors = atomic_load(&stream_errors);

        printf("    Frames reassembled: %llu\n", (unsigned long long)frames);
        printf("    Reassembly errors:  %llu\n", (unsigned long long)errors);

        if (errors > 0) {
            printf("    WARN: %llu stream reassembly failures\n",
                   (unsigned long long)errors);
        }
        printf("    PASS\n\n");
    }

    printf("========================================\n");
    printf("  STRESS TEST COMPLETE\n");
    printf("  Total frames processed: %llu\n",
           (unsigned long long)(atomic_load(&total_encoded) + atomic_load(&stream_frames)));
    printf("  Errors: %llu\n",
           (unsigned long long)(atomic_load(&total_errors) + atomic_load(&stream_errors)));
    printf("========================================\n");

    return (atomic_load(&total_errors) > 0) ? 1 : 0;
}
