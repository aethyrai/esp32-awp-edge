/**
 * Sensor Hub — Pluggable sensor abstraction for ESP32
 *
 * Register sensor drivers at startup, the hub polls them on a timer
 * and produces JSON telemetry for AWP transmission.
 *
 * Supported sensor types:
 *  - ADC (analog: temperature, light, moisture, current)
 *  - GPIO (digital: PIR motion, reed switch, button)
 *  - I2C (bus: BME280, SHT31, BH1750, etc.)
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SENSOR_MAX_COUNT    16
#define SENSOR_NAME_MAX     32
#define SENSOR_JSON_BUF_SIZE 1024

/* ========================================================================= */
/* Sensor Types                                                              */
/* ========================================================================= */

typedef enum {
    SENSOR_TYPE_ADC,
    SENSOR_TYPE_GPIO,
    SENSOR_TYPE_I2C,
    SENSOR_TYPE_VIRTUAL,  /* computed/derived values */
} sensor_type_t;

typedef enum {
    SENSOR_UNIT_CELSIUS,
    SENSOR_UNIT_FAHRENHEIT,
    SENSOR_UNIT_PERCENT,     /* humidity, battery */
    SENSOR_UNIT_LUX,
    SENSOR_UNIT_HPA,         /* pressure */
    SENSOR_UNIT_BOOLEAN,     /* motion, door open/closed */
    SENSOR_UNIT_MILLIVOLT,
    SENSOR_UNIT_RAW,
} sensor_unit_t;

/* ========================================================================= */
/* Sensor Reading                                                            */
/* ========================================================================= */

typedef struct {
    float   value;
    bool    valid;
    int64_t timestamp_ms;  /* esp_timer epoch */
} sensor_reading_t;

/* ========================================================================= */
/* Sensor Driver Interface                                                   */
/* ========================================================================= */

/**
 * Read callback — called by the hub to poll one sensor.
 * Implementations should fill out the reading and return true on success.
 */
typedef bool (*sensor_read_fn)(void *driver_ctx, sensor_reading_t *out);

typedef struct {
    char            name[SENSOR_NAME_MAX];
    sensor_type_t   type;
    sensor_unit_t   unit;
    sensor_read_fn  read;
    void           *driver_ctx;

    /* ADC config (ignored for non-ADC types) */
    int  adc_channel;
    int  adc_atten;  /* ADC_ATTEN_DB_* */

    /* GPIO config (ignored for non-GPIO types) */
    int  gpio_num;
    bool gpio_inverted;
} sensor_config_t;

/* ========================================================================= */
/* Sensor Hub API                                                            */
/* ========================================================================= */

typedef struct {
    sensor_config_t  sensors[SENSOR_MAX_COUNT];
    sensor_reading_t readings[SENSOR_MAX_COUNT];
    size_t           count;
} sensor_hub_t;

/**
 * Initialize the sensor hub.
 */
void sensor_hub_init(sensor_hub_t *hub);

/**
 * Register a sensor. Returns the sensor index, or -1 on failure.
 */
int sensor_hub_register(sensor_hub_t *hub, const sensor_config_t *config);

/**
 * Poll all registered sensors and update readings.
 */
void sensor_hub_poll(sensor_hub_t *hub);

/**
 * Format current readings as JSON for AWP telemetry.
 *
 * Output example:
 * {"node":"esp32-edge","sensors":[
 *   {"name":"temperature","value":23.5,"unit":"celsius","valid":true},
 *   {"name":"motion","value":1.0,"unit":"boolean","valid":true}
 * ],"ts":1234567890}
 *
 * @param hub       Sensor hub
 * @param node_name Node name for the JSON
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @return Number of bytes written (excluding null terminator)
 */
int sensor_hub_to_json(const sensor_hub_t *hub, const char *node_name,
                       char *buf, size_t buf_size);

/**
 * Format capabilities as JSON for CAPABILITY_ANNOUNCE.
 *
 * Output example:
 * {"tier":"EDGE","capabilities":["cache","relay","sensor"],
 *  "sensors":["temperature","humidity","motion"]}
 */
int sensor_hub_capabilities_json(const sensor_hub_t *hub,
                                 char *buf, size_t buf_size);

/* ========================================================================= */
/* Built-in Sensor Drivers                                                   */
/* ========================================================================= */

/**
 * ADC sensor driver — reads an ADC channel and converts to voltage.
 * Set adc_channel and adc_atten in config. driver_ctx is unused.
 */
bool sensor_driver_adc(void *ctx, sensor_reading_t *out);

/**
 * GPIO sensor driver — reads a digital input pin.
 * Set gpio_num and gpio_inverted in config. driver_ctx is unused.
 */
bool sensor_driver_gpio(void *ctx, sensor_reading_t *out);

/**
 * NTC thermistor driver — reads ADC and converts to temperature.
 * driver_ctx should point to a sensor_ntc_config_t.
 */
typedef struct {
    int   adc_channel;
    int   adc_atten;
    float r_series;     /* series resistor in ohms (e.g., 10000) */
    float r_nominal;    /* NTC nominal resistance at t_nominal (e.g., 10000) */
    float t_nominal;    /* nominal temperature in Celsius (e.g., 25) */
    float b_coefficient; /* beta coefficient (e.g., 3950) */
} sensor_ntc_config_t;

bool sensor_driver_ntc(void *ctx, sensor_reading_t *out);

#ifdef __cplusplus
}
#endif
