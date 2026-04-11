/**
 * AWP Stream Reader — TCP frame reassembly
 */

#include "awp_stream.h"

#include <string.h>
#include "esp_log.h"
#include "esp_heap_caps.h"

static const char *TAG = "awp_stream";

void awp_stream_init(awp_stream_t *s)
{
    s->len = 0;
    s->err_count = 0;
    s->bytes_dropped = 0;
    s->buf_size = AWP_STREAM_BUF_SIZE;
    s->buf = heap_caps_malloc(s->buf_size, MALLOC_CAP_SPIRAM);
    if (!s->buf) {
        ESP_LOGE(TAG, "Failed to allocate stream buffer in PSRAM (%zu bytes)", s->buf_size);
        s->buf_size = 0;
    }
}

awp_err_t awp_stream_feed(awp_stream_t *s,
                          const uint8_t *data, size_t data_len,
                          awp_frame_t *frames, size_t max_frames,
                          size_t *out_count)
{
    *out_count = 0;

    /* Append new data to buffer */
    if (!s->buf || s->buf_size == 0) return AWP_ERR_NOMEM;

    if (s->len + data_len > s->buf_size) {
        /* Track how many bytes we're discarding so it surfaces in stats. */
        size_t dropped;
        if (data_len >= s->buf_size) {
            /* New data alone exceeds buffer — reset and take tail */
            dropped = s->len + (data_len - s->buf_size);
            memcpy(s->buf, data + data_len - s->buf_size, s->buf_size);
            s->len = s->buf_size;
        } else {
            size_t shift = (s->len + data_len) - s->buf_size;
            dropped = shift;
            memmove(s->buf, s->buf + shift, s->len - shift);
            s->len -= shift;
            memcpy(s->buf + s->len, data, data_len);
            s->len += data_len;
        }
        s->bytes_dropped += dropped;
        ESP_LOGW(TAG, "Stream buffer overflow: dropped %zu bytes (total dropped=%lu)",
                 dropped, (unsigned long)s->bytes_dropped);
    } else {
        memcpy(s->buf + s->len, data, data_len);
        s->len += data_len;
    }

    /* Extract complete frames */
    while (s->len >= AWP_MIN_FRAME_SIZE && *out_count < max_frames) {
        /* Verify magic before trusting any header fields */
        uint32_t magic = ((uint32_t)s->buf[AWP_OFF_MAGIC]     << 24) |
                         ((uint32_t)s->buf[AWP_OFF_MAGIC + 1] << 16) |
                         ((uint32_t)s->buf[AWP_OFF_MAGIC + 2] <<  8) |
                         ((uint32_t)s->buf[AWP_OFF_MAGIC + 3]);
        if (magic != AWP_MAGIC) {
            /* Desynchronized — drop one byte and rescan */
            memmove(s->buf, s->buf + 1, --s->len);
            s->err_count++;
            continue;
        }

        /* Read total length from header */
        uint32_t frame_len = ((uint32_t)s->buf[AWP_OFF_LENGTH]     << 24) |
                             ((uint32_t)s->buf[AWP_OFF_LENGTH + 1] << 16) |
                             ((uint32_t)s->buf[AWP_OFF_LENGTH + 2] <<  8) |
                             ((uint32_t)s->buf[AWP_OFF_LENGTH + 3]);

        /* Sanity check */
        if (frame_len < AWP_MIN_FRAME_SIZE || frame_len > s->buf_size) {
            ESP_LOGW(TAG, "Invalid frame length %lu, dropping magic",
                     (unsigned long)frame_len);
            memmove(s->buf, s->buf + 1, --s->len);
            s->err_count++;
            continue;
        }

        /* Wait for complete frame */
        if (s->len < frame_len) {
            break;
        }

        /* Decode frame */
        awp_err_t err = awp_decode_frame(s->buf, frame_len, &frames[*out_count]);
        if (err == AWP_OK) {
            (*out_count)++;
        } else {
            ESP_LOGW(TAG, "Frame decode error: %s", awp_err_str(err));
            s->err_count++;
        }

        /* Consume frame from buffer */
        s->len -= frame_len;
        if (s->len > 0) {
            memmove(s->buf, s->buf + frame_len, s->len);
        }
    }

    return AWP_OK;
}

void awp_stream_clear(awp_stream_t *s)
{
    s->len = 0;
}
