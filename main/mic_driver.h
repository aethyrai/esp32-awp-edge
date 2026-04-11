/**
 * PDM Microphone Driver — MSM261D3526H1CPM on XIAO ESP32S3 Sense
 *
 * Captures audio via I2S PDM, computes RMS amplitude and dB SPL,
 * and integrates with sensor_hub for telemetry.
 */

#pragma once

#include <stdbool.h>
#include "sensor_hub.h"

#ifdef __cplusplus
extern "C" {
#endif

/* XIAO ESP32S3 Sense — PDM microphone pins */
#define MIC_PDM_CLK_GPIO    42
#define MIC_PDM_DATA_GPIO   41

/* Sample configuration */
#define MIC_SAMPLE_RATE     16000
#define MIC_SAMPLE_BITS     16
#define MIC_SAMPLE_COUNT    1024  /* samples per read — ~64ms at 16kHz */

/**
 * Initialize the PDM microphone via I2S.
 * Returns true on success.
 */
bool mic_driver_init(void);

/**
 * Read audio samples and compute RMS dB level.
 * Returns the dB level (0-100 scale, higher = louder).
 * Returns -1.0 on failure.
 */
float mic_driver_read_db(void);

/**
 * Read raw PCM samples into a caller-provided buffer.
 * Returns true on success, bytes_read set to actual bytes read.
 */
bool mic_driver_read_pcm(void *buf, size_t buf_size, size_t *bytes_read);

/**
 * Sensor hub read callback — reports audio dB level.
 */
bool mic_sensor_read(void *ctx, sensor_reading_t *out);

/**
 * Register microphone as a sensor in the hub.
 */
int mic_register(sensor_hub_t *hub);

#ifdef __cplusplus
}
#endif
