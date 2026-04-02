/**
 * AIOS Edge Node — ESP32 AWP Firmware
 *
 * Main entry point. Initializes WiFi, sensor hub, and AWP edge node.
 * Runs a sensor polling loop that reports telemetry over AWP to the
 * upstream CORE/NODE.
 *
 * Configuration via `idf.py menuconfig` → "AWP Edge Node Configuration"
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_task_wdt.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"

#include "awp_protocol.h"
#include "awp_edge_node.h"
#include "sensor_hub.h"
#include "crypto_test.h"

static const char *TAG = "awp_main";

/* ========================================================================= */
/* Globals                                                                   */
/* ========================================================================= */

static edge_node_t  g_node;
static sensor_hub_t g_sensors;

/* ========================================================================= */
/* Application Message Callback                                              */
/* ========================================================================= */

/**
 * Called for AWP messages the edge node doesn't handle internally.
 * Extend this to handle RINGCAST_TASK, AGENT_CALL, etc.
 */
static void on_awp_message(const awp_frame_t *frame, void *user_data)
{
    (void)user_data;

    ESP_LOGI(TAG, "AWP msg 0x%02x from %s (%zu bytes payload)",
             frame->msg_type, frame->node_id, frame->payload_len);

    switch (frame->msg_type) {
    case AWP_MSG_RINGCAST_TASK:
        /*
         * TODO: Parse task, evaluate capability match, optionally bid.
         * For now, just log it. A real implementation would:
         * 1. Parse the task JSON + skill_required HV
         * 2. Compute cosine similarity with our capability HV
         * 3. If match > threshold and load < 90%, submit RINGCAST_BID
         */
        ESP_LOGI(TAG, "Ring-Cast task — not bidding (EDGE node)");
        break;

    case AWP_MSG_AGENT_CALL:
        /*
         * TODO: Handle direct agent calls (e.g., "read sensor X",
         * "toggle relay Y"). Parse JSON payload, dispatch to actuator.
         */
        ESP_LOGI(TAG, "Agent call received — not implemented yet");
        break;

    default:
        ESP_LOGD(TAG, "Unhandled message type: 0x%02x", frame->msg_type);
        break;
    }
}

/* ========================================================================= */
/* Sensor Registration                                                       */
/* ========================================================================= */

/**
 * Register your sensors here. Modify this function for your hardware setup.
 *
 * Examples below show common sensor configurations.
 * Uncomment and adjust pin numbers for your wiring.
 */
static void register_sensors(void)
{
    /*
     * Example: NTC thermistor on ADC channel 6 (GPIO34)
     * Wiring: 3.3V → NTC → GPIO34 → 10K resistor → GND
     */
    /*
    static sensor_ntc_config_t ntc_cfg = {
        .adc_channel = ADC_CHANNEL_6,
        .adc_atten = ADC_ATTEN_DB_12,
        .r_series = 10000.0f,
        .r_nominal = 10000.0f,
        .t_nominal = 25.0f,
        .b_coefficient = 3950.0f,
    };
    sensor_config_t temp = {
        .name = "temperature",
        .type = SENSOR_TYPE_ADC,
        .unit = SENSOR_UNIT_CELSIUS,
        .read = sensor_driver_ntc,
        .driver_ctx = &ntc_cfg,
        .adc_channel = ADC_CHANNEL_6,
        .adc_atten = ADC_ATTEN_DB_12,
    };
    sensor_hub_register(&g_sensors, &temp);
    */

    /*
     * Example: PIR motion sensor on GPIO27
     * Wiring: VCC → PIR VCC, GND → PIR GND, PIR OUT → GPIO27
     */
    /*
    sensor_config_t motion = {
        .name = "motion",
        .type = SENSOR_TYPE_GPIO,
        .unit = SENSOR_UNIT_BOOLEAN,
        .read = sensor_driver_gpio,
        .driver_ctx = (void *)(intptr_t)27,
        .gpio_num = 27,
    };
    sensor_hub_register(&g_sensors, &motion);
    */

    /*
     * Example: Light sensor (LDR) on ADC channel 7 (GPIO35)
     * Wiring: 3.3V → LDR → GPIO35 → 10K resistor → GND
     */
    /*
    sensor_config_t light = {
        .name = "light",
        .type = SENSOR_TYPE_ADC,
        .unit = SENSOR_UNIT_RAW,
        .read = sensor_driver_adc,
        .driver_ctx = (void *)(intptr_t)ADC_CHANNEL_7,
        .adc_channel = ADC_CHANNEL_7,
        .adc_atten = ADC_ATTEN_DB_12,
    };
    sensor_hub_register(&g_sensors, &light);
    */

    /*
     * Example: Door reed switch on GPIO26
     * Wiring: GPIO26 → reed switch → GND (uses internal pull-up)
     */
    /*
    sensor_config_t door = {
        .name = "door",
        .type = SENSOR_TYPE_GPIO,
        .unit = SENSOR_UNIT_BOOLEAN,
        .read = sensor_driver_gpio,
        .driver_ctx = (void *)(intptr_t)26,
        .gpio_num = 26,
        .gpio_inverted = true,  // closed=LOW=0, we want closed=1
    };
    sensor_hub_register(&g_sensors, &door);
    */

    ESP_LOGI(TAG, "Registered %d sensors (edit register_sensors() to add yours)",
             (int)g_sensors.count);
}

/* ========================================================================= */
/* Sensor Telemetry Task                                                     */
/* ========================================================================= */

static void telemetry_task(void *arg)
{
    edge_node_t *node = (edge_node_t *)arg;
    char json_buf[SENSOR_JSON_BUF_SIZE];
    bool announced = false;

    esp_task_wdt_add(NULL);
    esp_task_wdt_reset();

    while (node->running) {
        /* Wait until upstream is connected — 3s chunks for WDT */
        while (node->running) {
            esp_task_wdt_reset();
            EventBits_t bits = xEventGroupWaitBits(node->events,
                EDGE_EVT_UPSTREAM_READY, pdFALSE, pdTRUE, pdMS_TO_TICKS(3000));
            if (bits & EDGE_EVT_UPSTREAM_READY) break;
        }
        if (!node->running) break;

        /* Announce capabilities once after connection */
        if (!announced && g_sensors.count > 0) {
            char cap_buf[512];
            sensor_hub_capabilities_json(&g_sensors, cap_buf, sizeof(cap_buf));
            edge_node_announce_capabilities(node, cap_buf);
            announced = true;
            ESP_LOGI(TAG, "Capabilities announced");
        }

        /* Poll sensors */
        sensor_hub_poll(&g_sensors);

        /* Build and send telemetry */
        if (g_sensors.count > 0) {
            int len = sensor_hub_to_json(&g_sensors, node->config.node_name,
                                         json_buf, sizeof(json_buf));
            if (len > 0) {
                awp_err_t err = edge_node_send_telemetry(node, json_buf);
                if (err != AWP_OK) {
                    ESP_LOGW(TAG, "Telemetry send failed: %s", awp_err_str(err));
                    announced = false; /* re-announce on reconnect */
                }
            }
        }

        /* Sleep in 3s chunks for WDT */
        uint32_t remaining = node->config.sensor_poll_interval_ms;
        while (remaining > 0 && node->running) {
            uint32_t chunk = (remaining > 3000) ? 3000 : remaining;
            vTaskDelay(pdMS_TO_TICKS(chunk));
            esp_task_wdt_reset();
            remaining -= chunk;
        }
    }

    vTaskDelete(NULL);
}

/* ========================================================================= */
/* Stats Logging Task                                                        */
/* ========================================================================= */

static void stats_task(void *arg)
{
    edge_node_t *node = (edge_node_t *)arg;

    while (node->running) {
        vTaskDelay(pdMS_TO_TICKS(60000)); /* every 60 seconds */

        edge_stats_t s = edge_node_stats(node);
        const char *state_str;
        switch (edge_node_state(node)) {
        case EDGE_STATE_INIT:             state_str = "INIT"; break;
        case EDGE_STATE_WIFI_CONNECTING:  state_str = "WIFI_CONNECTING"; break;
        case EDGE_STATE_WIFI_CONNECTED:   state_str = "WIFI_CONNECTED"; break;
        case EDGE_STATE_TCP_CONNECTING:   state_str = "TCP_CONNECTING"; break;
        case EDGE_STATE_HANDSHAKE:        state_str = "HANDSHAKE"; break;
        case EDGE_STATE_CONNECTED:        state_str = "CONNECTED"; break;
        case EDGE_STATE_DISCONNECTED:     state_str = "DISCONNECTED"; break;
        default:                          state_str = "UNKNOWN"; break;
        }

        /* Task stack watermarks under live load */
        UBaseType_t conn_hwm = 0, hb_hwm = 0;
        if (node->conn_task) conn_hwm = uxTaskGetStackHighWaterMark(node->conn_task);
        if (node->heartbeat_task) hb_hwm = uxTaskGetStackHighWaterMark(node->heartbeat_task);

        ESP_LOGI(TAG,
            "Stats: state=%s sent=%lu recv=%lu reconnects=%lu",
            state_str,
            (unsigned long)s.frames_sent,
            (unsigned long)s.frames_received,
            (unsigned long)s.reconnect_count);
        ESP_LOGI(TAG,
            "Stack: conn=%lu/%lu hb=%lu/%lu free_heap=%lu",
            49152UL - (unsigned long)(conn_hwm * sizeof(StackType_t)), 49152UL,
            8192UL - (unsigned long)(hb_hwm * sizeof(StackType_t)), 8192UL,
            (unsigned long)esp_get_free_heap_size());
    }

    vTaskDelete(NULL);
}

/* ========================================================================= */
/* app_main                                                                  */
/* ========================================================================= */

/* Load PSK from NVS (provisioned per-device) or Kconfig (build-time fallback) */
static size_t load_psk(uint8_t *psk_out, size_t max_len)
{
    /* Try NVS first — per-device provisioning takes priority */
    nvs_handle_t nvs;
    if (nvs_open("awp_crypto", NVS_READONLY, &nvs) == ESP_OK) {
        size_t len = max_len;
        if (nvs_get_blob(nvs, "awp_psk", psk_out, &len) == ESP_OK && len > 0) {
            nvs_close(nvs);
            ESP_LOGI(TAG, "PSK loaded from NVS (%zu bytes)", len);
            return len;
        }
        nvs_close(nvs);
    }

    /* Fall back to Kconfig hex string */
    const char *hex = CONFIG_AWP_PSK;
    if (hex && hex[0] != '\0') {
        size_t hex_len = strlen(hex);
        size_t bin_len = hex_len / 2;
        if (bin_len > max_len) bin_len = max_len;
        for (size_t i = 0; i < bin_len; i++) {
            unsigned int b;
            if (sscanf(hex + i * 2, "%2x", &b) != 1) break;
            psk_out[i] = (uint8_t)b;
        }
        if (bin_len > 0) {
            ESP_LOGI(TAG, "PSK loaded from Kconfig (%zu bytes)", bin_len);
            return bin_len;
        }
    }

    ESP_LOGW(TAG, "No PSK configured — MITM protection inactive");
    return 0;
}

void app_main(void)
{
    ESP_LOGI(TAG, "==============================================");
    ESP_LOGI(TAG, "  AIOS Edge Node — AethyrWire Protocol v0.1");
    ESP_LOGI(TAG, "  Node: %s", CONFIG_AWP_NODE_NAME);
    ESP_LOGI(TAG, "  Upstream: %s:%d", CONFIG_AWP_UPSTREAM_HOST, CONFIG_AWP_UPSTREAM_PORT);

    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(TAG, "  Firmware: %s %s (%s)", app->project_name, app->version, app->date);
    ESP_LOGI(TAG, "==============================================");

    /* Run crypto self-tests before anything else */
    if (!crypto_self_test()) {
        ESP_LOGE(TAG, "CRYPTO SELF-TEST FAILED — HALTING");
        while (1) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    /* Initialize sensor hub */
    sensor_hub_init(&g_sensors);
    register_sensors();

    /* Load PSK for mutual authentication */
    uint8_t psk_buf[AWP_PSK_MAX_SIZE];
    size_t psk_len = load_psk(psk_buf, sizeof(psk_buf));

    /* Configure edge node */
    edge_config_t config = {
        .node_name              = CONFIG_AWP_NODE_NAME,
        .upstream_host          = CONFIG_AWP_UPSTREAM_HOST,
        .upstream_port          = CONFIG_AWP_UPSTREAM_PORT,
        .listen_port            = CONFIG_AWP_LISTEN_PORT,
        .hdc_cache_capacity     = CONFIG_AWP_HDC_CACHE_CAPACITY,
        .heartbeat_interval_ms  = CONFIG_AWP_HEARTBEAT_INTERVAL_MS,
        .sensor_poll_interval_ms = CONFIG_AWP_SENSOR_POLL_INTERVAL_MS,
        .msg_callback           = on_awp_message,
        .callback_user_data     = NULL,
        .psk                    = psk_len > 0 ? psk_buf : NULL,
        .psk_len                = psk_len,
    };

    /* Initialize and start edge node */
    edge_node_init(&g_node, &config);
    edge_node_compute_hdc_identity(&g_node, &g_sensors);
    edge_node_start(&g_node);

    /* Launch application tasks */
    xTaskCreate(telemetry_task, "awp_telem", 4096, &g_node, 3, NULL);
    xTaskCreate(stats_task, "awp_stats", 4096, &g_node, 1, NULL);

    ESP_LOGI(TAG, "All tasks launched. Edge node running.");
}
