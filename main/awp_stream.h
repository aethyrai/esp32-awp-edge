/**
 * AWP Stream Reader — TCP frame reassembly
 *
 * Accumulates TCP data and extracts complete AWP frames.
 * Matches Python AWPStreamReader in aios_network/protocol.py.
 */

#pragma once

#include "awp_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of frames returned per feed() call */
#define AWP_STREAM_MAX_FRAMES 8

/* Stream buffer size — must hold at least one max-size ESP32 frame */
#define AWP_STREAM_BUF_SIZE  (AWP_HEADER_SIZE + AWP_ESP32_MAX_PAYLOAD + AWP_CHECKSUM_SIZE + 1024)

typedef struct {
    uint8_t  buf[AWP_STREAM_BUF_SIZE];
    size_t   len;       /* bytes currently in buffer */
    uint32_t err_count; /* total decode errors */
} awp_stream_t;

/**
 * Initialize a stream reader.
 */
void awp_stream_init(awp_stream_t *s);

/**
 * Feed raw TCP data into the stream reader.
 *
 * @param s         Stream reader
 * @param data      New data from recv()
 * @param data_len  Length of new data
 * @param frames    Output array of decoded frames (caller provides)
 * @param max_frames  Size of frames array
 * @param out_count Receives number of frames decoded
 * @return AWP_OK, or AWP_ERR_NOMEM if buffer overflow
 *
 * Note: frame payload pointers reference the stream's internal buffer.
 * They are only valid until the next call to awp_stream_feed().
 * Copy any payload data you need before calling feed() again.
 */
awp_err_t awp_stream_feed(awp_stream_t *s,
                          const uint8_t *data, size_t data_len,
                          awp_frame_t *frames, size_t max_frames,
                          size_t *out_count);

/**
 * Clear the stream buffer.
 */
void awp_stream_clear(awp_stream_t *s);

/**
 * Get number of bytes pending in the buffer.
 */
static inline size_t awp_stream_pending(const awp_stream_t *s)
{
    return s->len;
}

#ifdef __cplusplus
}
#endif
