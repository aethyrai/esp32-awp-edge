/**
 * HDC Identity Simulation — host-side test
 *
 * Build:
 *   cc -g -O1 -I../main -I../components/blake3 \
 *      -DAWP_FUZZ_HOST \
 *      test/test_hdc.c \
 *      ../components/blake3/blake3.c ../components/blake3/blake3_portable.c \
 *      ../components/blake3/blake3_dispatch.c \
 *      -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_NO_NEON \
 *      -o test_hdc && ./test_hdc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "blake3.h"

/* Pull in protocol constants */
#define AWP_HDC_DIM         4096
#define AWP_HDC_PACKED_SIZE (AWP_HDC_DIM / 32)
#define AWP_HDC_SIG_SIZE    (AWP_HDC_PACKED_SIZE * 4)  /* 512 bytes */

/* ========================================================================= */
/* HDC Primitives                                                            */
/* ========================================================================= */

static void hdc_basis(const char *name, uint8_t out[AWP_HDC_SIG_SIZE])
{
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "awp-hdc-basis-v1");
    blake3_hasher_update(&h, (const uint8_t *)name, strlen(name));
    blake3_hasher_finalize(&h, out, AWP_HDC_SIG_SIZE);
}

static void hdc_bind(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++)
        out[i] = a[i] ^ b[i];
}

static void hdc_permute(const uint8_t *in, int k, uint8_t *out)
{
    k = ((k % AWP_HDC_SIG_SIZE) + AWP_HDC_SIG_SIZE) % AWP_HDC_SIG_SIZE;
    memcpy(out, in + k, AWP_HDC_SIG_SIZE - k);
    memcpy(out + AWP_HDC_SIG_SIZE - k, in, k);
}

static void hdc_tally(uint16_t *counts, const uint8_t *vec)
{
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++) {
        uint8_t b = vec[i];
        int base = i * 8;
        counts[base + 0] += (b >> 0) & 1;
        counts[base + 1] += (b >> 1) & 1;
        counts[base + 2] += (b >> 2) & 1;
        counts[base + 3] += (b >> 3) & 1;
        counts[base + 4] += (b >> 4) & 1;
        counts[base + 5] += (b >> 5) & 1;
        counts[base + 6] += (b >> 6) & 1;
        counts[base + 7] += (b >> 7) & 1;
    }
}

static void hdc_threshold(const uint16_t *counts, size_t n, uint8_t *out)
{
    uint8_t tiebreaker[AWP_HDC_SIG_SIZE];
    int need_tiebreak = (n % 2 == 0);
    if (need_tiebreak) {
        hdc_basis("_tiebreaker_", tiebreaker);
    }

    size_t thresh = n / 2;
    memset(out, 0, AWP_HDC_SIG_SIZE);
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++) {
        uint8_t byte = 0;
        int base = i * 8;
        for (int bit = 0; bit < 8; bit++) {
            uint16_t c = counts[base + bit];
            if (c > thresh) {
                byte |= (1 << bit);
            } else if (need_tiebreak && c == thresh) {
                if (tiebreaker[i] & (1 << bit)) byte |= (1 << bit);
            }
        }
        out[i] = byte;
    }
}

/* ========================================================================= */
/* Similarity Measurement                                                    */
/* ========================================================================= */

static int popcount_byte(uint8_t b)
{
    int c = 0;
    while (b) { c += b & 1; b >>= 1; }
    return c;
}

static int hamming_distance(const uint8_t *a, const uint8_t *b)
{
    int dist = 0;
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++)
        dist += popcount_byte(a[i] ^ b[i]);
    return dist;
}

static double hamming_similarity(const uint8_t *a, const uint8_t *b)
{
    return 1.0 - (double)hamming_distance(a, b) / AWP_HDC_DIM;
}

/* ========================================================================= */
/* Simulated Node Configuration                                              */
/* ========================================================================= */

typedef struct {
    const char *node_id;
    const char *node_name;
    bool        pqc_ready;
    const char *sensors[16];
    size_t      sensor_count;
} sim_node_t;

static void compute_identity(const sim_node_t *cfg, uint8_t *out)
{
    uint16_t *counts = calloc(AWP_HDC_DIM, sizeof(uint16_t));
    uint8_t basis[AWP_HDC_SIG_SIZE], value[AWP_HDC_SIG_SIZE];
    uint8_t bound[AWP_HDC_SIG_SIZE], perm[AWP_HDC_SIG_SIZE];
    size_t n = 0;

    /* Node ID */
    hdc_basis("node_id", basis);
    hdc_basis(cfg->node_id, value);
    hdc_bind(basis, value, bound);
    hdc_tally(counts, bound); n++;

    /* Node name */
    hdc_basis("node_name", basis);
    hdc_basis(cfg->node_name, value);
    hdc_bind(basis, value, bound);
    hdc_tally(counts, bound); n++;

    /* Tier */
    hdc_basis("tier_edge", basis);
    hdc_tally(counts, basis); n++;

    /* PQC */
    if (cfg->pqc_ready) {
        hdc_basis("pqc_mlkem768", basis);
        hdc_tally(counts, basis); n++;
    }

    /* Sensors */
    for (size_t i = 0; i < cfg->sensor_count; i++) {
        hdc_basis("sensor", basis);
        hdc_basis(cfg->sensors[i], value);
        hdc_bind(basis, value, bound);
        hdc_permute(bound, (int)(i + 1), perm);
        hdc_tally(counts, perm); n++;
    }

    hdc_threshold(counts, n, out);
    free(counts);
}

/* ========================================================================= */
/* Test Cases                                                                */
/* ========================================================================= */

int main(void)
{
    printf("========================================\n");
    printf("  HDC Identity Simulation\n");
    printf("  Vector dimension: %d bits (%d bytes)\n", AWP_HDC_DIM, AWP_HDC_SIG_SIZE);
    printf("========================================\n\n");

    /* Define test nodes */
    sim_node_t nodes[] = {
        {
            .node_id = "a1b2c3d4e5f6",
            .node_name = "greenhouse-01",
            .pqc_ready = true,
            .sensors = {"temperature", "humidity", "light", "soil_moisture"},
            .sensor_count = 4,
        },
        {   /* Same config as node 0 — must produce identical vector */
            .node_id = "a1b2c3d4e5f6",
            .node_name = "greenhouse-01",
            .pqc_ready = true,
            .sensors = {"temperature", "humidity", "light", "soil_moisture"},
            .sensor_count = 4,
        },
        {   /* Same sensors, different node — similar but not identical */
            .node_id = "f6e5d4c3b2a1",
            .node_name = "greenhouse-02",
            .pqc_ready = true,
            .sensors = {"temperature", "humidity", "light", "soil_moisture"},
            .sensor_count = 4,
        },
        {   /* Overlapping sensors (3/4 shared) — should be fairly similar */
            .node_id = "112233445566",
            .node_name = "greenhouse-03",
            .pqc_ready = true,
            .sensors = {"temperature", "humidity", "light", "pressure"},
            .sensor_count = 4,
        },
        {   /* Completely different sensors — should be distant */
            .node_id = "aabbccddeeff",
            .node_name = "security-cam-01",
            .pqc_ready = true,
            .sensors = {"motion", "door_contact", "glass_break"},
            .sensor_count = 3,
        },
        {   /* No sensors, no PQC — very different profile */
            .node_id = "000000000001",
            .node_name = "relay-node",
            .pqc_ready = false,
            .sensors = {},
            .sensor_count = 0,
        },
    };

    const char *labels[] = {
        "greenhouse-01 (temp/hum/light/soil)",
        "greenhouse-01 (IDENTICAL)",
        "greenhouse-02 (same sensors)",
        "greenhouse-03 (3/4 overlap)",
        "security-cam   (motion/door/glass)",
        "relay-node     (no sensors, no PQC)",
    };

    size_t num_nodes = sizeof(nodes) / sizeof(nodes[0]);

    /* Compute all identity vectors */
    uint8_t vectors[6][AWP_HDC_SIG_SIZE];
    for (size_t i = 0; i < num_nodes; i++) {
        compute_identity(&nodes[i], vectors[i]);
    }

    /* --- Test 1: Determinism --- */
    printf("[1] Determinism check\n");
    int d01 = hamming_distance(vectors[0], vectors[1]);
    printf("    Identical config distance: %d (must be 0)\n", d01);
    if (d01 != 0) {
        printf("    FAIL: identical configs produced different vectors!\n");
        return 1;
    }
    printf("    PASS\n\n");

    /* --- Test 2: Similarity matrix --- */
    printf("[2] Hamming similarity matrix (1.0 = identical, 0.5 = random)\n\n");

    /* Header */
    printf("    %4s", "");
    for (size_t j = 0; j < num_nodes; j++)
        printf("  [%zu]  ", j);
    printf("\n");

    for (size_t i = 0; i < num_nodes; i++) {
        printf("    [%zu]", i);
        for (size_t j = 0; j < num_nodes; j++) {
            double sim = hamming_similarity(vectors[i], vectors[j]);
            printf("  %.3f", sim);
        }
        printf("  %s\n", labels[i]);
    }

    printf("\n");

    /* --- Test 3: Expected ordering --- */
    printf("[3] Similarity ordering (relative to node [0])\n");

    typedef struct { size_t idx; double sim; } sim_pair_t;
    sim_pair_t pairs[6];
    for (size_t i = 0; i < num_nodes; i++) {
        pairs[i].idx = i;
        pairs[i].sim = hamming_similarity(vectors[0], vectors[i]);
    }

    /* Simple insertion sort */
    for (size_t i = 1; i < num_nodes; i++) {
        sim_pair_t tmp = pairs[i];
        size_t j = i;
        while (j > 0 && pairs[j-1].sim < tmp.sim) {
            pairs[j] = pairs[j-1];
            j--;
        }
        pairs[j] = tmp;
    }

    printf("    Most similar → least similar to greenhouse-01:\n");
    for (size_t i = 0; i < num_nodes; i++) {
        printf("      %.3f  %s\n", pairs[i].sim, labels[pairs[i].idx]);
    }

    printf("\n");

    /* --- Test 4: Sanity checks --- */
    printf("[4] Sanity checks\n");
    int pass = 1;

    double sim_identical = hamming_similarity(vectors[0], vectors[1]);
    double sim_same_sensors = hamming_similarity(vectors[0], vectors[2]);
    double sim_overlap = hamming_similarity(vectors[0], vectors[3]);
    double sim_different = hamming_similarity(vectors[0], vectors[4]);
    double sim_relay = hamming_similarity(vectors[0], vectors[5]);

    /* Identical must be 1.0 */
    if (sim_identical != 1.0) {
        printf("    FAIL: identical configs similarity %.3f != 1.0\n", sim_identical);
        pass = 0;
    }

    /* Same sensors should be more similar than different sensors */
    if (sim_same_sensors <= sim_different) {
        printf("    FAIL: same-sensor node (%.3f) not more similar than different-sensor node (%.3f)\n",
               sim_same_sensors, sim_different);
        pass = 0;
    }

    /* 3/4 overlap should be more similar than no overlap */
    if (sim_overlap <= sim_different) {
        printf("    FAIL: overlapping node (%.3f) not more similar than different node (%.3f)\n",
               sim_overlap, sim_different);
        pass = 0;
    }

    /* Similarity ordering: identical > same sensors > overlap > different */
    if (sim_identical > sim_same_sensors &&
        sim_same_sensors > sim_overlap &&
        sim_overlap > sim_different) {
        printf("    PASS: similarity ordering is correct\n");
        printf("      identical(1.000) > same_sensors(%.3f) > overlap_3of4(%.3f) > different(%.3f)\n",
               sim_same_sensors, sim_overlap, sim_different);
    } else {
        printf("    WARN: similarity ordering not strictly monotonic\n");
        printf("      identical=%.3f, same_sensors=%.3f, overlap=%.3f, different=%.3f\n",
               sim_identical, sim_same_sensors, sim_overlap, sim_different);
    }

    /* All non-identical similarities should be < 1.0 */
    if (sim_same_sensors >= 1.0 || sim_overlap >= 1.0 || sim_different >= 1.0) {
        printf("    FAIL: non-identical nodes have similarity 1.0 (collision!)\n");
        pass = 0;
    }

    /* Different profiles should be near 0.5 (random baseline) */
    if (sim_relay < 0.35 || sim_relay > 0.65) {
        printf("    WARN: relay node similarity %.3f far from random baseline 0.5\n", sim_relay);
    } else {
        printf("    PASS: dissimilar nodes near random baseline (relay=%.3f)\n", sim_relay);
    }

    printf("\n");

    /* --- Test 5: Bit distribution --- */
    printf("[5] Bit distribution (should be ~50%% ones)\n");
    for (size_t i = 0; i < num_nodes; i++) {
        int ones = 0;
        for (int j = 0; j < AWP_HDC_SIG_SIZE; j++)
            ones += popcount_byte(vectors[i][j]);
        printf("    [%zu] %d/%d ones (%.1f%%)  %s\n",
               i, ones, AWP_HDC_DIM, 100.0 * ones / AWP_HDC_DIM,
               (ones > 1800 && ones < 2300) ? "OK" : "SKEWED");
    }

    printf("\n========================================\n");
    printf("  %s\n", pass ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    printf("========================================\n");

    return pass ? 0 : 1;
}
