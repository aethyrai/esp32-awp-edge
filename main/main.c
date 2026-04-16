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
#include "camera_driver.h"
#include "mic_driver.h"
#include "esp_camera.h"
#include "esp_heap_caps.h"
#include "cJSON.h"

static const char *TAG = "awp_main";

/* ========================================================================= */
/* Globals                                                                   */
/* ========================================================================= */

static edge_node_t  g_node;
static sensor_hub_t g_sensors;

/* Stream control — modifiable via agent calls */
volatile int  g_camera_target_fps = 10;
volatile bool g_stream_enabled = true;

/* ========================================================================= */
/* Application Message Callback                                              */
/* ========================================================================= */

/* ========================================================================= */
/* Agent Call Handler — Remote Commands                                      */
/* ========================================================================= */

/**
 * Handle an agent call from the upstream node.
 *
 * Payload is JSON: {"action":"<command>", ...params}
 *
 * Supported commands:
 *   read_sensor    — poll a sensor by name, return current value
 *   snapshot       — capture one JPEG frame and send it back
 *   get_status     — return device diagnostics (heap, uptime, state, sensors)
 *   set_fps        — change camera stream target fps
 *   stream_control — start/stop camera and audio streams
 *   restart        — reboot the device
 */
#define AGENT_CALL_MAX_SIZE 4096  /* reject oversized command payloads */

static void handle_agent_call(const awp_frame_t *frame)
{
    if (frame->payload_len == 0) return;
    if (frame->payload_len > AGENT_CALL_MAX_SIZE) {
        ESP_LOGW(TAG, "Agent call rejected: payload too large (%zu bytes)", frame->payload_len);
        return;
    }

    cJSON *req = cJSON_ParseWithLength((const char *)frame->payload, frame->payload_len);
    if (!req) {
        ESP_LOGW(TAG, "Agent call: invalid JSON");
        return;
    }

    const cJSON *action = cJSON_GetObjectItem(req, "action");
    if (!cJSON_IsString(action)) {
        ESP_LOGW(TAG, "Agent call: missing 'action' field");
        cJSON_Delete(req);
        return;
    }

    ESP_LOGI(TAG, "Agent call: action=%s", action->valuestring);

    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        ESP_LOGE(TAG, "Agent call: failed to allocate response (heap exhausted?) — dropping '%s'",
                 action->valuestring);
        cJSON_Delete(req);
        return;
    }
    cJSON_AddStringToObject(resp, "action", action->valuestring);

    if (strcmp(action->valuestring, "read_sensor") == 0) {
        const cJSON *name = cJSON_GetObjectItem(req, "name");
        bool found = false;

        sensor_hub_poll(&g_sensors);
        for (size_t i = 0; i < g_sensors.count; i++) {
            if (name && cJSON_IsString(name) &&
                strcmp(g_sensors.sensors[i].name, name->valuestring) == 0) {
                cJSON_AddStringToObject(resp, "name", g_sensors.sensors[i].name);
                cJSON_AddNumberToObject(resp, "value", g_sensors.readings[i].value);
                cJSON_AddBoolToObject(resp, "valid", g_sensors.readings[i].valid);
                found = true;
                break;
            }
        }
        if (!found) {
            /* Return all sensors */
            cJSON *sensors = cJSON_AddArrayToObject(resp, "sensors");
            for (size_t i = 0; i < g_sensors.count; i++) {
                cJSON *s = cJSON_CreateObject();
                cJSON_AddStringToObject(s, "name", g_sensors.sensors[i].name);
                cJSON_AddNumberToObject(s, "value", g_sensors.readings[i].value);
                cJSON_AddBoolToObject(s, "valid", g_sensors.readings[i].valid);
                cJSON_AddItemToArray(sensors, s);
            }
        }
        cJSON_AddStringToObject(resp, "status", "ok");

    } else if (strcmp(action->valuestring, "snapshot") == 0) {
        /* Capture one frame and send as media */
        camera_fb_t *fb = esp_camera_fb_get();
        if (fb) {
            edge_node_send_media(&g_node, fb->buf, fb->len, "jpeg");
            cJSON_AddStringToObject(resp, "status", "ok");
            cJSON_AddNumberToObject(resp, "size", fb->len);
            esp_camera_fb_return(fb);
        } else {
            cJSON_AddStringToObject(resp, "status", "error");
            cJSON_AddStringToObject(resp, "error", "camera capture failed");
        }

    } else if (strcmp(action->valuestring, "get_status") == 0) {
        cJSON_AddStringToObject(resp, "status", "ok");
        cJSON_AddStringToObject(resp, "node_id", g_node.node_id);
        cJSON_AddStringToObject(resp, "state",
            edge_node_state(&g_node) == EDGE_STATE_CONNECTED ? "connected" : "disconnected");
        cJSON_AddNumberToObject(resp, "free_heap", esp_get_free_heap_size());
        cJSON_AddNumberToObject(resp, "free_psram", heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        cJSON_AddNumberToObject(resp, "uptime_ms", esp_timer_get_time() / 1000);
        cJSON_AddNumberToObject(resp, "sensors", g_sensors.count);

        edge_stats_t stats = edge_node_stats(&g_node);
        cJSON_AddNumberToObject(resp, "frames_sent", stats.frames_sent);
        cJSON_AddNumberToObject(resp, "frames_recv", stats.frames_received);
        cJSON_AddNumberToObject(resp, "reconnects", stats.reconnect_count);
        cJSON_AddNumberToObject(resp, "media_dropped", stats.media_frames_dropped);
        cJSON_AddNumberToObject(resp, "media_send_fail", stats.media_send_failures);
        cJSON_AddNumberToObject(resp, "stream_bytes_dropped", stats.stream_bytes_dropped);

    } else if (strcmp(action->valuestring, "set_fps") == 0) {
        const cJSON *fps = cJSON_GetObjectItem(req, "fps");
        if (cJSON_IsNumber(fps) && fps->valueint >= 1 && fps->valueint <= 30) {
            /* Camera stream task reads this global */
            extern volatile int g_camera_target_fps;
            g_camera_target_fps = fps->valueint;
            cJSON_AddStringToObject(resp, "status", "ok");
            cJSON_AddNumberToObject(resp, "fps", fps->valueint);
            ESP_LOGI(TAG, "Camera fps set to %d", fps->valueint);
        } else {
            cJSON_AddStringToObject(resp, "status", "error");
            cJSON_AddStringToObject(resp, "error", "fps must be 1-30");
        }

    } else if (strcmp(action->valuestring, "stream_control") == 0) {
        const cJSON *enable = cJSON_GetObjectItem(req, "enable");
        if (cJSON_IsBool(enable)) {
            extern volatile bool g_stream_enabled;
            g_stream_enabled = cJSON_IsTrue(enable);
            cJSON_AddStringToObject(resp, "status", "ok");
            cJSON_AddBoolToObject(resp, "streaming", g_stream_enabled);
            ESP_LOGI(TAG, "Streaming %s", g_stream_enabled ? "enabled" : "disabled");
        } else {
            cJSON_AddStringToObject(resp, "status", "error");
            cJSON_AddStringToObject(resp, "error", "missing 'enable' bool");
        }

    } else if (strcmp(action->valuestring, "restart") == 0) {
        /* Cooldown: ignore restart commands within 60s of boot to prevent DoS loop */
        int64_t uptime_s = esp_timer_get_time() / 1000000;
        if (uptime_s < 60) {
            cJSON_AddStringToObject(resp, "status", "error");
            cJSON_AddStringToObject(resp, "error", "restart cooldown (< 60s uptime)");
        } else {
            cJSON_AddStringToObject(resp, "status", "ok");
            cJSON_AddStringToObject(resp, "message", "restarting in 1s");
            char *json = cJSON_PrintUnformatted(resp);
            if (json) {
                awp_err_t send_err = edge_node_send_telemetry(&g_node, json);
                if (send_err != AWP_OK) {
                    ESP_LOGW(TAG, "Agent call: restart ack send failed: %s",
                             awp_err_str(send_err));
                }
                cJSON_free(json);
            } else {
                ESP_LOGE(TAG, "Agent call: restart ack JSON print failed");
            }
            cJSON_Delete(resp);
            cJSON_Delete(req);
            vTaskDelay(pdMS_TO_TICKS(1000));
            edge_reboot_with_reason(EDGE_REBOOT_AGENT_REQUEST);
            /* unreachable */
        }

    } else {
        cJSON_AddStringToObject(resp, "status", "error");
        cJSON_AddStringToObject(resp, "error", "unknown action");
    }

    /* Send response — surface send/serialize failures so a dropped ack
     * doesn't leave the upstream guessing. */
    char *json = cJSON_PrintUnformatted(resp);
    if (json) {
        awp_err_t send_err = edge_node_send_telemetry(&g_node, json);
        if (send_err != AWP_OK) {
            ESP_LOGW(TAG, "Agent call '%s': response send failed: %s",
                     action->valuestring, awp_err_str(send_err));
        }
        cJSON_free(json);
    } else {
        ESP_LOGE(TAG, "Agent call '%s': cJSON_PrintUnformatted failed — response dropped",
                 action->valuestring);
    }
    cJSON_Delete(resp);
    cJSON_Delete(req);
}

/**
 * Called for AWP messages the edge node doesn't handle internally.
 */
static void on_awp_message(const awp_frame_t *frame, void *user_data)
{
    (void)user_data;

    switch (frame->msg_type) {
    case AWP_MSG_RINGCAST_TASK:
        break;  /* EDGE nodes don't bid on tasks */

    case AWP_MSG_AGENT_CALL:
        handle_agent_call(frame);
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
 * Register XIAO ESP32S3 Sense peripherals as sensors.
 * - OV2640 camera → reports JPEG frame size (KB)
 * - PDM microphone → reports audio level (dB, 0-100 scale)
 */
static void register_sensors(void)
{
    int cam_idx = camera_register(&g_sensors);
    if (cam_idx >= 0) {
        ESP_LOGI(TAG, "Camera registered as sensor [%d]", cam_idx);
    }

    int mic_idx = mic_register(&g_sensors);
    if (mic_idx >= 0) {
        ESP_LOGI(TAG, "Microphone registered as sensor [%d]", mic_idx);
    }

    ESP_LOGI(TAG, "Registered %d sensors", (int)g_sensors.count);
}

/* ========================================================================= */
/* Local Sensor Monitor Task (serial output, no upstream needed)             */
/* ========================================================================= */

static void sensor_monitor_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(3000)); /* let init settle */

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "========== SENSOR MONITOR ==========");
    ESP_LOGI(TAG, "Polling camera + mic every 5s");
    ESP_LOGI(TAG, "====================================");

    while (1) {
        sensor_hub_poll(&g_sensors);

        ESP_LOGI(TAG, "--- Sensors ---");
        for (size_t i = 0; i < g_sensors.count; i++) {
            const sensor_config_t *s = &g_sensors.sensors[i];
            const sensor_reading_t *r = &g_sensors.readings[i];

            if (!r->valid) {
                ESP_LOGW(TAG, "  %-20s  INVALID", s->name);
            } else {
                ESP_LOGI(TAG, "  %-20s  %.1f %s", s->name, r->value,
                         sensor_unit_str(s->unit));
            }
        }

        ESP_LOGI(TAG, "  free_heap: %u  free_psram: %u",
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        ESP_LOGI(TAG, "");

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

/* ========================================================================= */
/* Camera Stream Task — dedicated video pipeline                             */
/* ========================================================================= */

static void camera_stream_task(void *arg)
{
    edge_node_t *node = (edge_node_t *)arg;

    esp_task_wdt_add(NULL);
    esp_task_wdt_reset();

    /* Wait for encrypted session before streaming */
    while (node->running) {
        esp_task_wdt_reset();
        EventBits_t bits = xEventGroupWaitBits(node->events,
            EDGE_EVT_UPSTREAM_READY, pdFALSE, pdTRUE, pdMS_TO_TICKS(1000));
        if (bits & EDGE_EVT_UPSTREAM_READY) break;
    }

    ESP_LOGI(TAG, "Camera stream started — target %d fps", g_camera_target_fps);

    /* Exponential log rate limiter — log first failure, then every 2^N-th. */
    uint32_t capture_failures = 0;
    uint32_t next_capture_log = 1;
    uint32_t send_failures = 0;
    uint32_t next_send_log = 1;

    while (node->running) {
        esp_task_wdt_reset();

        /* Respect stream_control commands */
        if (!g_stream_enabled) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        int64_t frame_start = esp_timer_get_time();
        int frame_ms = 1000 / g_camera_target_fps;

        /* Check connection is still up */
        EventBits_t bits = xEventGroupGetBits(node->events);
        if (!(bits & EDGE_EVT_UPSTREAM_READY)) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        /* Capture and send — surface failures instead of dropping silently. */
        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) {
            node->stats.media_frames_dropped++;
            capture_failures++;
            if (capture_failures == next_capture_log) {
                ESP_LOGW(TAG, "Camera capture failed (total=%lu)",
                         (unsigned long)capture_failures);
                next_capture_log *= 2;
            }
        } else {
            awp_err_t send_err = edge_node_send_media(node, fb->buf, fb->len, "jpeg");
            if (send_err != AWP_OK) {
                node->stats.media_send_failures++;
                send_failures++;
                if (send_failures == next_send_log) {
                    ESP_LOGW(TAG, "Camera frame send failed: %s (total=%lu)",
                             awp_err_str(send_err), (unsigned long)send_failures);
                    next_send_log *= 2;
                }
            }
            esp_camera_fb_return(fb);
        }

        /* Frame rate control — sleep remainder of frame interval */
        int64_t elapsed_us = esp_timer_get_time() - frame_start;
        int32_t remaining_ms = frame_ms - (int32_t)(elapsed_us / 1000);
        if (remaining_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(remaining_ms));
        }
    }

    vTaskDelete(NULL);
}

/* ========================================================================= */
/* Audio Stream Task — dedicated audio pipeline                              */
/* ========================================================================= */

#define AUDIO_CHUNK_MS     100  /* 100ms chunks = 10 chunks/sec */
#define AUDIO_CHUNK_BYTES  (MIC_SAMPLE_RATE * 2 * AUDIO_CHUNK_MS / 1000) /* 16kHz * 16bit * 100ms = 3200 bytes */

static void audio_stream_task(void *arg)
{
    edge_node_t *node = (edge_node_t *)arg;

    esp_task_wdt_add(NULL);
    esp_task_wdt_reset();

    /* Allocate PCM buffer in PSRAM — reused every chunk */
    int16_t *pcm_buf = heap_caps_malloc(AUDIO_CHUNK_BYTES, MALLOC_CAP_SPIRAM);
    if (!pcm_buf) {
        ESP_LOGE(TAG, "Failed to allocate audio buffer");
        esp_task_wdt_delete(NULL);
        vTaskDelete(NULL);
        return;
    }

    /* Wait for encrypted session */
    while (node->running) {
        esp_task_wdt_reset();
        EventBits_t bits = xEventGroupWaitBits(node->events,
            EDGE_EVT_UPSTREAM_READY, pdFALSE, pdTRUE, pdMS_TO_TICKS(1000));
        if (bits & EDGE_EVT_UPSTREAM_READY) break;
    }

    ESP_LOGI(TAG, "Audio stream started — %dms chunks (%d bytes)", AUDIO_CHUNK_MS, AUDIO_CHUNK_BYTES);

    uint32_t read_failures = 0;
    uint32_t next_read_log = 1;
    uint32_t send_failures = 0;
    uint32_t next_send_log = 1;

    while (node->running) {
        esp_task_wdt_reset();

        if (!g_stream_enabled) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        /* Check connection */
        EventBits_t bits = xEventGroupGetBits(node->events);
        if (!(bits & EDGE_EVT_UPSTREAM_READY)) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        /* Read PCM and send — i2s_channel_read blocks for AUDIO_CHUNK_MS */
        size_t bytes_read = 0;
        if (mic_driver_read_pcm(pcm_buf, AUDIO_CHUNK_BYTES, &bytes_read)) {
            awp_err_t send_err = edge_node_send_media(node, (uint8_t *)pcm_buf,
                                                      bytes_read, "pcm16");
            if (send_err != AWP_OK) {
                node->stats.media_send_failures++;
                send_failures++;
                if (send_failures == next_send_log) {
                    ESP_LOGW(TAG, "Audio chunk send failed: %s (total=%lu)",
                             awp_err_str(send_err), (unsigned long)send_failures);
                    next_send_log *= 2;
                }
            }
        } else {
            node->stats.media_frames_dropped++;
            read_failures++;
            if (read_failures == next_read_log) {
                ESP_LOGW(TAG, "Mic read failed (total=%lu)",
                         (unsigned long)read_failures);
                next_read_log *= 2;
            }
            /* Back off briefly so a dead mic doesn't starve the CPU. */
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    heap_caps_free(pcm_buf);
    esp_task_wdt_delete(NULL);
    vTaskDelete(NULL);
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

        /* Fresh WDT window at the top of each body iteration — the body
         * can take up to ~2s under mutex contention (1s per send timeout
         * against priority-4 stream tasks), and the sleep-loop's first
         * reset is another 2s away, so the body must start with a clean
         * watchdog or it can drift past the 5s limit. */
        esp_task_wdt_reset();

        /* Announce capabilities once after connection */
        if (!announced && g_sensors.count > 0) {
            char cap_buf[512];
            int cap_len = sensor_hub_capabilities_json(&g_sensors, cap_buf, sizeof(cap_buf));
            if (cap_len > 0) {
                awp_err_t cap_err = edge_node_announce_capabilities(node, cap_buf);
                if (cap_err == AWP_OK) {
                    announced = true;
                    ESP_LOGI(TAG, "Capabilities announced");
                } else {
                    ESP_LOGW(TAG, "Capability announce send failed: %s",
                             awp_err_str(cap_err));
                }
            } else {
                ESP_LOGE(TAG, "Capabilities JSON build failed (rc=%d) — skipping announce",
                         cap_len);
            }
        }
        esp_task_wdt_reset();

        /* Poll sensors */
        sensor_hub_poll(&g_sensors);
        esp_task_wdt_reset();

        /* Build and send JSON telemetry (sensor metadata only) */
        if (g_sensors.count > 0) {
            int len = sensor_hub_to_json(&g_sensors, node->config.node_name,
                                         json_buf, sizeof(json_buf));
            if (len > 0) {
                awp_err_t err = edge_node_send_telemetry(node, json_buf);
                if (err != AWP_OK) {
                    ESP_LOGW(TAG, "Telemetry send failed: %s", awp_err_str(err));
                    announced = false; /* re-announce on reconnect */
                }
            } else if (len < 0) {
                ESP_LOGE(TAG, "Telemetry JSON build failed (rc=%d) — skipping send", len);
            }
        }
        esp_task_wdt_reset();

        /* Sleep in 2s chunks for WDT (tighter than the 5s timeout so the
         * gap stays bounded even when body iterations are slow). */
        uint32_t remaining = node->config.sensor_poll_interval_ms;
        while (remaining > 0 && node->running) {
            uint32_t chunk = (remaining > 2000) ? 2000 : remaining;
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
        if (hex_len % 2 != 0) {
            ESP_LOGW(TAG, "Kconfig PSK has odd hex length (%zu) — ignoring", hex_len);
            return 0;
        }
        size_t bin_len = hex_len / 2;
        if (bin_len > max_len) bin_len = max_len;
        size_t decoded = 0;
        for (size_t i = 0; i < bin_len; i++) {
            unsigned int b;
            if (sscanf(hex + i * 2, "%2x", &b) != 1) {
                ESP_LOGW(TAG, "Kconfig PSK: invalid hex at byte %zu — truncating", i);
                break;
            }
            psk_out[i] = (uint8_t)b;
            decoded++;
        }
        if (decoded > 0) {
            ESP_LOGI(TAG, "PSK loaded from Kconfig (%zu bytes)", decoded);
            return decoded;
        }
    }

    return 0;
}

#define AWP_PSK_MIN_SIZE 16   /* 128 bits — matches formal audit F-01 */

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

    /* Load PSK for mutual authentication. Without a secret PSK the
     * handshake admits an active MITM that learns the session key —
     * see docs/audits/formal/REPORT.md F-01. */
    uint8_t psk_buf[AWP_PSK_MAX_SIZE];
    size_t psk_len = load_psk(psk_buf, sizeof(psk_buf));

    if (psk_len < AWP_PSK_MIN_SIZE) {
#if CONFIG_AWP_REQUIRE_PSK
        ESP_LOGE(TAG, "SECURITY: PSK missing or too short (%zu < %d bytes).",
                 psk_len, AWP_PSK_MIN_SIZE);
        ESP_LOGE(TAG, "Provision a PSK via NVS ('awp_crypto'/'awp_psk') or");
        ESP_LOGE(TAG, "idf.py menuconfig -> AWP Edge Node Configuration -> PSK.");
        ESP_LOGE(TAG, "Refusing to start without authenticated handshake.");
        while (1) { vTaskDelay(pdMS_TO_TICKS(5000)); }
#else
        ESP_LOGW(TAG, "CONFIG_AWP_REQUIRE_PSK=n and PSK is short/missing — "
                      "handshake is vulnerable to active MITM (audit F-01)");
#endif
    }

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

    /* Launch application tasks.
     * All sender tasks (telemetry, camera_stream, audio_stream) run at
     * priority 4 so they round-robin fairly on tx_mutex. An earlier
     * attempt ran telemetry at priority 3, which starved it behind the
     * streams and caused capability announces and periodic sensor JSON
     * to fail every cycle. Equal priority keeps all senders fair. */
    xTaskCreate(telemetry_task, "awp_telem", 8192, &g_node, 4, NULL);
    xTaskCreate(camera_stream_task, "cam_stream", 16384, &g_node, 4, NULL);
    xTaskCreate(audio_stream_task, "aud_stream", 8192, &g_node, 4, NULL);
    xTaskCreate(stats_task, "awp_stats", 4096, &g_node, 1, NULL);
    xTaskCreate(sensor_monitor_task, "sensor_mon", 8192, NULL, 2, NULL);

    ESP_LOGI(TAG, "All tasks launched. AV edge node running.");
}
