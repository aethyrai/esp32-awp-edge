/**
 * Camera Driver — OV2640 on XIAO ESP32S3 Sense
 */

#include "camera_driver.h"

#include "esp_log.h"
#include "esp_camera.h"

static const char *TAG = "camera";

static bool s_initialized = false;

bool camera_driver_init(void)
{
    if (s_initialized) return true;

    camera_config_t config = {
        .pin_pwdn     = CAM_PIN_PWDN,
        .pin_reset    = CAM_PIN_RESET,
        .pin_xclk     = CAM_PIN_XCLK,
        .pin_sccb_sda = CAM_PIN_SIOD,
        .pin_sccb_scl = CAM_PIN_SIOC,
        .pin_d7       = CAM_PIN_D7,
        .pin_d6       = CAM_PIN_D6,
        .pin_d5       = CAM_PIN_D5,
        .pin_d4       = CAM_PIN_D4,
        .pin_d3       = CAM_PIN_D3,
        .pin_d2       = CAM_PIN_D2,
        .pin_d1       = CAM_PIN_D1,
        .pin_d0       = CAM_PIN_D0,
        .pin_vsync    = CAM_PIN_VSYNC,
        .pin_href     = CAM_PIN_HREF,
        .pin_pclk     = CAM_PIN_PCLK,

        .xclk_freq_hz = 20000000,
        .ledc_timer   = LEDC_TIMER_0,
        .ledc_channel = LEDC_CHANNEL_0,

        .pixel_format = PIXFORMAT_JPEG,
        .frame_size   = FRAMESIZE_HD,    /* 1280x720 */
        .jpeg_quality = 12,              /* 0-63, lower = better quality */
        .fb_count     = 3,               /* triple-buffer: avoids FB-OVF when poll interval > frame rate */
        .fb_location  = CAMERA_FB_IN_PSRAM,
        .grab_mode    = CAMERA_GRAB_WHEN_EMPTY,
    };

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Camera init failed: 0x%x (%s)", err, esp_err_to_name(err));
        return false;
    }

    /* Tune sensor settings for indoor use */
    sensor_t *sensor = esp_camera_sensor_get();
    if (sensor) {
        sensor->set_brightness(sensor, 0);
        sensor->set_contrast(sensor, 0);
        sensor->set_saturation(sensor, 0);
        sensor->set_whitebal(sensor, 1);
        sensor->set_awb_gain(sensor, 1);
        sensor->set_exposure_ctrl(sensor, 1);
        sensor->set_gain_ctrl(sensor, 1);
    }

    s_initialized = true;
    ESP_LOGI(TAG, "Camera initialized — VGA JPEG, %d frame buffers in PSRAM", config.fb_count);
    return true;
}

size_t camera_driver_capture(void)
{
    if (!s_initialized) return 0;

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) {
        ESP_LOGW(TAG, "Capture failed — no frame buffer");
        return 0;
    }

    size_t len = fb->len;
    esp_camera_fb_return(fb);
    return len;
}

bool camera_sensor_read(void *ctx, sensor_reading_t *out)
{
    (void)ctx;

    if (!s_initialized) return false;

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) return false;

    /* Report frame size in KB as the sensor value */
    out->value = (float)fb->len / 1024.0f;
    out->valid = true;

    esp_camera_fb_return(fb);
    return true;
}

int camera_register(sensor_hub_t *hub)
{
    if (!camera_driver_init()) {
        ESP_LOGE(TAG, "Cannot register camera sensor — init failed");
        return -1;
    }

    sensor_config_t cfg = {
        .name       = "camera_frame_kb",
        .type       = SENSOR_TYPE_VIRTUAL,
        .unit       = SENSOR_UNIT_RAW,
        .read       = camera_sensor_read,
        .driver_ctx = NULL,
        .anomaly    = {
            .range_lo        = 0.5f,    /* <0.5 KB = blank/black frame */
            .range_hi        = 300.0f,  /* >300 KB = corrupted frame */
            .max_rate        = 200.0f,  /* >200 KB jump between polls */
            .stuck_threshold = 10,      /* same size 10x = frozen sensor */
        },
    };

    return sensor_hub_register(hub, &cfg);
}
