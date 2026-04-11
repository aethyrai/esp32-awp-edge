/**
 * Sensor Hub — implementation
 */

#include "sensor_hub.h"

#include <string.h>
#include <stdio.h>
#include <math.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "esp_adc/adc_oneshot.h"
#include "driver/gpio.h"

static const char *TAG = "sensor_hub";

/* ADC handle — shared across all ADC sensors (non-static for industrial_drivers.c) */
adc_oneshot_unit_handle_t s_adc_handle = NULL;

void ensure_adc_init(void)
{
    if (s_adc_handle) return;

    adc_oneshot_unit_init_cfg_t cfg = {
        .unit_id = ADC_UNIT_1,
    };
    esp_err_t err = adc_oneshot_new_unit(&cfg, &s_adc_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ADC init failed: %s", esp_err_to_name(err));
    }
}

/* ========================================================================= */
/* Hub API                                                                   */
/* ========================================================================= */

void sensor_hub_init(sensor_hub_t *hub)
{
    memset(hub, 0, sizeof(*hub));
    hub->lock = xSemaphoreCreateMutex();
    if (!hub->lock) {
        ESP_LOGE(TAG, "sensor_hub_init: failed to create lock mutex");
    }
}

int sensor_hub_register(sensor_hub_t *hub, const sensor_config_t *config)
{
    if (hub->count >= SENSOR_MAX_COUNT) {
        ESP_LOGW(TAG, "Sensor hub full, cannot register '%s'", config->name);
        return -1;
    }

    int idx = hub->count;
    hub->sensors[idx] = *config;
    hub->readings[idx].valid = false;
    hub->count++;

    /* Initialize hardware for built-in drivers */
    if (config->type == SENSOR_TYPE_ADC || config->read == sensor_driver_adc) {
        ensure_adc_init();
        if (s_adc_handle) {
            adc_oneshot_chan_cfg_t chan_cfg = {
                .atten = config->adc_atten,
                .bitwidth = ADC_BITWIDTH_12,
            };
            adc_oneshot_config_channel(s_adc_handle, config->adc_channel, &chan_cfg);
        }
    }

    if (config->type == SENSOR_TYPE_GPIO || config->read == sensor_driver_gpio) {
        gpio_config_t io_cfg = {
            .pin_bit_mask = (1ULL << config->gpio_num),
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
        };
        gpio_config(&io_cfg);
    }

    ESP_LOGI(TAG, "Registered sensor [%d]: '%s' (type=%d)", idx, config->name, config->type);
    return idx;
}

/* ========================================================================= */
/* Anomaly Detection                                                         */
/* ========================================================================= */

static anomaly_flags_t check_anomalies(const sensor_config_t *cfg,
                                        anomaly_state_t *state,
                                        float value)
{
    const anomaly_config_t *ac = &cfg->anomaly;
    anomaly_flags_t flags = ANOMALY_NONE;

    /* Range check */
    if (ac->range_lo != 0.0f || ac->range_hi != 0.0f) {
        if (ac->range_hi > ac->range_lo) {
            if (value < ac->range_lo || value > ac->range_hi) {
                flags |= ANOMALY_RANGE;
            }
        }
    }

    /* Rate-of-change check (skip first reading) */
    if (ac->max_rate > 0.0f && state->primed) {
        float delta = value - state->last_value;
        if (delta < 0) delta = -delta;
        if (delta > ac->max_rate) {
            flags |= ANOMALY_RATE;
        }
    }

    /* Stuck-value check */
    if (ac->stuck_threshold > 0) {
        if (state->primed && value == state->last_value) {
            state->stuck_count++;
        } else {
            state->stuck_count = 0;
        }
        if (state->stuck_count >= ac->stuck_threshold) {
            flags |= ANOMALY_STUCK;
        }
    }

    /* Update state */
    state->last_value = value;
    state->primed = true;

    /* Rolling history */
    if (state->history_count < ANOMALY_HISTORY_SIZE) {
        state->history[state->history_count++] = value;
    } else {
        memmove(state->history, state->history + 1,
                (ANOMALY_HISTORY_SIZE - 1) * sizeof(float));
        state->history[ANOMALY_HISTORY_SIZE - 1] = value;
    }

    if (flags != ANOMALY_NONE) {
        ESP_LOGW(TAG, "ANOMALY on '%s': value=%.2f flags=0x%02x%s%s%s",
                 cfg->name, value, flags,
                 (flags & ANOMALY_RATE)  ? " RATE"  : "",
                 (flags & ANOMALY_STUCK) ? " STUCK" : "",
                 (flags & ANOMALY_RANGE) ? " RANGE" : "");
    }

    return flags;
}

/* ========================================================================= */
/* Polling                                                                   */
/* ========================================================================= */

void sensor_hub_poll(sensor_hub_t *hub)
{
    /* Serialize hardware access + anomaly_state updates across tasks
     * (telemetry_task, sensor_monitor_task, handle_agent_call). Without
     * this, concurrent callers corrupt anomaly counters and race on the
     * camera/mic drivers. */
    if (hub->lock && xSemaphoreTake(hub->lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "sensor_hub_poll: lock timeout — skipping poll");
        return;
    }

    int64_t now = esp_timer_get_time() / 1000;

    for (size_t i = 0; i < hub->count; i++) {
        sensor_reading_t reading = { .valid = false, .timestamp_ms = now, .anomaly = ANOMALY_NONE };
        sensor_config_t *s = &hub->sensors[i];

        if (s->read) {
            reading.valid = s->read(s->driver_ctx, &reading);
            reading.timestamp_ms = now;
        }

        /* Run anomaly detection on valid readings */
        if (reading.valid) {
            reading.anomaly = check_anomalies(s, &hub->anomaly_state[i], reading.value);
        }

        hub->readings[i] = reading;
    }

    if (hub->lock) xSemaphoreGive(hub->lock);
}

const char *sensor_unit_str(sensor_unit_t u)
{
    switch (u) {
    case SENSOR_UNIT_CELSIUS:    return "°C";
    case SENSOR_UNIT_FAHRENHEIT: return "°F";
    case SENSOR_UNIT_PERCENT:    return "%";
    case SENSOR_UNIT_LUX:        return "lux";
    case SENSOR_UNIT_HPA:        return "hPa";
    case SENSOR_UNIT_BOOLEAN:    return "bool";
    case SENSOR_UNIT_MILLIVOLT:  return "mV";
    case SENSOR_UNIT_RAW:        return "raw";
    default:                     return "?";
    }
}

int sensor_hub_to_json(const sensor_hub_t *hub, const char *node_name,
                       char *buf, size_t buf_size)
{
    if (buf_size == 0) return 0;
    buf[0] = '\0';

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        ESP_LOGE(TAG, "sensor_hub_to_json: cJSON_CreateObject failed (heap?)");
        return -1;
    }
    cJSON_AddStringToObject(root, "node", node_name);
    cJSON_AddStringToObject(root, "type", "sensor_telemetry");

    cJSON *sensors = cJSON_AddArrayToObject(root, "sensors");
    for (size_t i = 0; i < hub->count; i++) {
        cJSON *s = cJSON_CreateObject();
        cJSON_AddStringToObject(s, "name", hub->sensors[i].name);
        cJSON_AddNumberToObject(s, "value",
            round(hub->readings[i].value * 100.0) / 100.0);
        cJSON_AddStringToObject(s, "unit", sensor_unit_str(hub->sensors[i].unit));
        cJSON_AddBoolToObject(s, "valid", hub->readings[i].valid);
        if (hub->readings[i].anomaly != ANOMALY_NONE) {
            cJSON *flags = cJSON_AddArrayToObject(s, "anomaly");
            if (hub->readings[i].anomaly & ANOMALY_RATE)
                cJSON_AddItemToArray(flags, cJSON_CreateString("rate"));
            if (hub->readings[i].anomaly & ANOMALY_STUCK)
                cJSON_AddItemToArray(flags, cJSON_CreateString("stuck"));
            if (hub->readings[i].anomaly & ANOMALY_RANGE)
                cJSON_AddItemToArray(flags, cJSON_CreateString("range"));
        }
        cJSON_AddItemToArray(sensors, s);
    }

    cJSON_AddNumberToObject(root, "ts",
        (double)(esp_timer_get_time() / 1000));

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        ESP_LOGE(TAG, "sensor_hub_to_json: cJSON_PrintUnformatted failed");
        return -1;
    }

    int len = snprintf(buf, buf_size, "%s", json);
    size_t full_len = strlen(json);
    cJSON_free(json);

    /* Detect truncation — snprintf returns the length it WOULD have written.
     * Return -2 to signal "buffer too small" so callers can refuse to send
     * invalid JSON upstream. */
    if (len < 0 || (size_t)len >= buf_size) {
        ESP_LOGW(TAG, "sensor_hub_to_json: truncated (%zu needed, %zu available)",
                 full_len, buf_size);
        buf[0] = '\0';
        return -2;
    }

    return len;
}

int sensor_hub_capabilities_json(const sensor_hub_t *hub,
                                 char *buf, size_t buf_size)
{
    if (buf_size == 0) return 0;
    buf[0] = '\0';

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        ESP_LOGE(TAG, "capabilities_json: cJSON_CreateObject failed (heap?)");
        return -1;
    }
    cJSON_AddStringToObject(root, "tier", "EDGE");

    cJSON *caps = cJSON_AddArrayToObject(root, "capabilities");
    cJSON_AddItemToArray(caps, cJSON_CreateString("cache"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("relay"));
    cJSON_AddItemToArray(caps, cJSON_CreateString("sensor"));

    cJSON *sensors = cJSON_AddArrayToObject(root, "sensors");
    for (size_t i = 0; i < hub->count; i++) {
        cJSON_AddItemToArray(sensors, cJSON_CreateString(hub->sensors[i].name));
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        ESP_LOGE(TAG, "capabilities_json: cJSON_PrintUnformatted failed");
        return -1;
    }

    int len = snprintf(buf, buf_size, "%s", json);
    size_t full_len = strlen(json);
    cJSON_free(json);

    if (len < 0 || (size_t)len >= buf_size) {
        ESP_LOGW(TAG, "capabilities_json: truncated (%zu needed, %zu available)",
                 full_len, buf_size);
        buf[0] = '\0';
        return -2;
    }

    return len;
}

/* ========================================================================= */
/* Built-in Drivers                                                          */
/* ========================================================================= */

bool sensor_driver_adc(void *ctx, sensor_reading_t *out)
{
    if (!s_adc_handle) return false;

    /* ctx is unused — channel info is in the sensor_config_t,
       but we pass channel via a simple cast for built-in usage */
    int channel = (int)(intptr_t)ctx;
    int raw = 0;

    esp_err_t err = adc_oneshot_read(s_adc_handle, channel, &raw);
    if (err != ESP_OK) return false;

    /* Convert 12-bit ADC to millivolts (approximate, depends on attenuation) */
    out->value = (float)raw * 3300.0f / 4095.0f;
    out->valid = true;
    return true;
}

bool sensor_driver_gpio(void *ctx, sensor_reading_t *out)
{
    int gpio_num = (int)(intptr_t)ctx;
    int level = gpio_get_level(gpio_num);

    out->value = (float)level;
    out->valid = true;
    return true;
}

bool sensor_driver_ntc(void *ctx, sensor_reading_t *out)
{
    if (!s_adc_handle || !ctx) return false;

    sensor_ntc_config_t *ntc = (sensor_ntc_config_t *)ctx;
    int raw = 0;

    esp_err_t err = adc_oneshot_read(s_adc_handle, ntc->adc_channel, &raw);
    if (err != ESP_OK) return false;

    if (raw == 0) return false;

    /* Voltage divider: NTC on top, R_series to ground */
    float voltage = (float)raw * 3.3f / 4095.0f;
    float r_ntc = ntc->r_series * voltage / (3.3f - voltage);

    /* Steinhart-Hart (simplified B-equation) */
    float t_kelvin = 1.0f / (
        (1.0f / (ntc->t_nominal + 273.15f)) +
        (1.0f / ntc->b_coefficient) * logf(r_ntc / ntc->r_nominal)
    );

    out->value = t_kelvin - 273.15f;  /* to Celsius */
    out->valid = true;
    return true;
}
