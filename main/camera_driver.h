/**
 * Camera Driver — OV2640 on XIAO ESP32S3 Sense
 *
 * Initializes the camera, provides periodic capture, and integrates
 * with sensor_hub to report frame metadata as telemetry.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sensor_hub.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XIAO ESP32S3 Sense — OV2640 pin mapping
 */
#define CAM_PIN_PWDN    -1
#define CAM_PIN_RESET   -1
#define CAM_PIN_XCLK    10
#define CAM_PIN_SIOD    40
#define CAM_PIN_SIOC    39
#define CAM_PIN_D7      48
#define CAM_PIN_D6      11
#define CAM_PIN_D5      12
#define CAM_PIN_D4      14
#define CAM_PIN_D3      16
#define CAM_PIN_D2      18
#define CAM_PIN_D1      17
#define CAM_PIN_D0      15
#define CAM_PIN_VSYNC   38
#define CAM_PIN_HREF    47
#define CAM_PIN_PCLK    13

/**
 * Initialize the OV2640 camera.
 * Allocates frame buffers in PSRAM.
 * Returns true on success.
 */
bool camera_driver_init(void);

/**
 * Capture a single frame. Returns frame size in bytes, or 0 on failure.
 * Frame buffer is returned to the pool internally.
 */
size_t camera_driver_capture(void);

/**
 * Sensor hub read callback — reports frame size in bytes as the sensor value.
 * Captures a frame, records the size, then releases it.
 */
bool camera_sensor_read(void *ctx, sensor_reading_t *out);

/**
 * Register camera as a sensor in the hub.
 */
int camera_register(sensor_hub_t *hub);

#ifdef __cplusplus
}
#endif
