/**
 * PDM Microphone Driver — MSM261D3526H1CPM on XIAO ESP32S3 Sense
 */

#include "mic_driver.h"

#include <math.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "driver/i2s_pdm.h"

static const char *TAG = "mic";

static i2s_chan_handle_t s_rx_handle = NULL;
static bool s_initialized = false;

bool mic_driver_init(void)
{
    if (s_initialized) return true;

    /* Allocate an I2S RX channel */
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    chan_cfg.dma_desc_num = 4;
    chan_cfg.dma_frame_num = MIC_SAMPLE_COUNT;

    esp_err_t err = i2s_new_channel(&chan_cfg, NULL, &s_rx_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2S channel alloc failed: %s", esp_err_to_name(err));
        return false;
    }

    /* Configure PDM RX mode */
    i2s_pdm_rx_config_t pdm_cfg = {
        .clk_cfg  = I2S_PDM_RX_CLK_DEFAULT_CONFIG(MIC_SAMPLE_RATE),
        .slot_cfg = I2S_PDM_RX_SLOT_PCM_FMT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .clk = MIC_PDM_CLK_GPIO,
            .din = MIC_PDM_DATA_GPIO,
            .invert_flags = {
                .clk_inv = false,
            },
        },
    };

    err = i2s_channel_init_pdm_rx_mode(s_rx_handle, &pdm_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PDM RX init failed: %s", esp_err_to_name(err));
        i2s_del_channel(s_rx_handle);
        s_rx_handle = NULL;
        return false;
    }

    err = i2s_channel_enable(s_rx_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2S channel enable failed: %s", esp_err_to_name(err));
        i2s_del_channel(s_rx_handle);
        s_rx_handle = NULL;
        return false;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "PDM mic initialized — %d Hz, %d-bit, GPIO CLK=%d DATA=%d",
             MIC_SAMPLE_RATE, MIC_SAMPLE_BITS, MIC_PDM_CLK_GPIO, MIC_PDM_DATA_GPIO);
    return true;
}

float mic_driver_read_db(void)
{
    if (!s_initialized) return -1.0f;

    int16_t samples[MIC_SAMPLE_COUNT];
    size_t bytes_read = 0;

    esp_err_t err = i2s_channel_read(s_rx_handle, samples, sizeof(samples),
                                      &bytes_read, pdMS_TO_TICKS(200));
    if (err != ESP_OK || bytes_read == 0) {
        ESP_LOGW(TAG, "Mic read failed: %s (got %zu bytes)",
                 esp_err_to_name(err), bytes_read);
        return -1.0f;
    }

    size_t num_samples = bytes_read / sizeof(int16_t);

    /* Compute RMS amplitude */
    double sum_sq = 0.0;
    for (size_t i = 0; i < num_samples; i++) {
        double s = (double)samples[i];
        sum_sq += s * s;
    }
    double rms = sqrt(sum_sq / (double)num_samples);

    /* Convert to dB (relative to full-scale 16-bit = 32767) */
    if (rms < 1.0) rms = 1.0;  /* floor to avoid log(0) */
    float db = 20.0f * log10f((float)(rms / 32767.0));

    /* Shift to 0-100 scale: -96 dBFS (silence) → 0, 0 dBFS (clipping) → 100 */
    float level = (db + 96.0f) * (100.0f / 96.0f);
    if (level < 0.0f) level = 0.0f;
    if (level > 100.0f) level = 100.0f;

    return level;
}

bool mic_driver_read_pcm(void *buf, size_t buf_size, size_t *bytes_read)
{
    if (!s_initialized) return false;

    esp_err_t err = i2s_channel_read(s_rx_handle, buf, buf_size,
                                      bytes_read, pdMS_TO_TICKS(200));
    return (err == ESP_OK && *bytes_read > 0);
}

bool mic_sensor_read(void *ctx, sensor_reading_t *out)
{
    (void)ctx;

    float db = mic_driver_read_db();
    if (db < 0.0f) return false;

    out->value = db;
    out->valid = true;
    return true;
}

int mic_register(sensor_hub_t *hub)
{
    if (!mic_driver_init()) {
        ESP_LOGE(TAG, "Cannot register mic sensor — init failed");
        return -1;
    }

    sensor_config_t cfg = {
        .name       = "audio_level_db",
        .type       = SENSOR_TYPE_VIRTUAL,
        .unit       = SENSOR_UNIT_PERCENT,
        .read       = mic_sensor_read,
        .driver_ctx = NULL,
        .anomaly    = {
            .range_lo        = 0.0f,
            .range_hi        = 100.0f,  /* dB scale is 0-100 */
            .max_rate        = 60.0f,   /* >60% jump between polls = ultrasonic attack */
            .stuck_threshold = 20,      /* same dB 20x = mic dead or shielded */
        },
    };

    return sensor_hub_register(hub, &cfg);
}
