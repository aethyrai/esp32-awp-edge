/**
 * AethyrWire Protocol (AWP) — ESP32 Implementation
 */

#include "awp_protocol.h"

#include <string.h>
#include <arpa/inet.h>

#include "blake3.h"
#include "esp_log.h"

static const char *TAG = "awp_proto";

/* ========================================================================= */
/* Big-Endian Helpers                                                        */
/* ========================================================================= */

static inline void put_u32_be(uint8_t *buf, uint32_t val)
{
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >>  8) & 0xFF;
    buf[3] =  val        & 0xFF;
}

static inline void put_u16_be(uint8_t *buf, uint16_t val)
{
    buf[0] = (val >> 8) & 0xFF;
    buf[1] =  val       & 0xFF;
}

static inline uint32_t get_u32_be(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] <<  8) |
           ((uint32_t)buf[3]);
}

static inline uint16_t get_u16_be(const uint8_t *buf)
{
    return ((uint16_t)buf[0] << 8) |
           ((uint16_t)buf[1]);
}

/* ========================================================================= */
/* Error Strings                                                             */
/* ========================================================================= */

const char *awp_err_str(awp_err_t err)
{
    switch (err) {
    case AWP_OK:           return "OK";
    case AWP_ERR_MAGIC:    return "invalid magic number";
    case AWP_ERR_VERSION:  return "unsupported protocol version";
    case AWP_ERR_CHECKSUM: return "checksum verification failed";
    case AWP_ERR_SIZE:     return "frame size error";
    case AWP_ERR_DECODE:   return "frame decode error";
    case AWP_ERR_ENCODE:   return "frame encode / encrypt error";
    case AWP_ERR_NOMEM:    return "buffer too small";
    default:               return "unknown error";
    }
}

/* ========================================================================= */
/* Frame Checksum                                                            */
/* ========================================================================= */

void awp_blake2b_checksum(const uint8_t *data, size_t data_len, uint8_t *out)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, data_len);
    blake3_hasher_finalize(&hasher, out, AWP_CHECKSUM_SIZE);
}

/* ========================================================================= */
/* Frame Encoding                                                            */
/* ========================================================================= */

awp_err_t awp_encode_frame(const awp_frame_t *frame,
                           uint8_t *out_buf, size_t buf_size,
                           size_t *out_len)
{
    size_t total = awp_frame_size(frame->payload_len);

    if (total > buf_size) {
        ESP_LOGE(TAG, "Buffer too small: need %zu, have %zu", total, buf_size);
        return AWP_ERR_NOMEM;
    }

    if (frame->payload_len > AWP_ESP32_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "Payload too large for ESP32: %zu", frame->payload_len);
        return AWP_ERR_SIZE;
    }

    uint8_t *p = out_buf;

    put_u32_be(p + AWP_OFF_MAGIC,   AWP_MAGIC);
    put_u16_be(p + AWP_OFF_VERSION, frame->version);
    put_u16_be(p + AWP_OFF_FLAGS,   frame->flags);
    put_u32_be(p + AWP_OFF_LENGTH,  (uint32_t)total);

    /* Node ID (32 bytes, null-padded) */
    memset(p + AWP_OFF_NODE_ID, 0, AWP_NODE_ID_SIZE);
    size_t nid_len = strlen(frame->node_id);
    if (nid_len > AWP_NODE_ID_SIZE) nid_len = AWP_NODE_ID_SIZE;
    memcpy(p + AWP_OFF_NODE_ID, frame->node_id, nid_len);

    memset(p + AWP_OFF_HDC_SIG, 0, AWP_HDC_SIG_SIZE);

    /* Message Type (2 bytes) */
    put_u16_be(p + AWP_OFF_MSG_TYPE, (uint16_t)frame->msg_type);

    /* Tenant HV (64 bytes) */
    if (frame->has_tenant_hv) {
        memcpy(p + AWP_OFF_TENANT_HV, frame->tenant_hv, AWP_TENANT_HV_SIZE);
    } else {
        memset(p + AWP_OFF_TENANT_HV, 0, AWP_TENANT_HV_SIZE);
    }

    /* Session ID (16 bytes) */
    if (frame->has_session_id) {
        memcpy(p + AWP_OFF_SESSION_ID, frame->session_id, AWP_SESSION_ID_SIZE);
    } else {
        memset(p + AWP_OFF_SESSION_ID, 0, AWP_SESSION_ID_SIZE);
    }

    /* Payload */
    if (frame->payload_len > 0 && frame->payload != NULL) {
        memcpy(p + AWP_OFF_PAYLOAD, frame->payload, frame->payload_len);
    }

    /* Checksum */
    size_t data_len = AWP_HEADER_SIZE + frame->payload_len;
    awp_blake2b_checksum(p, data_len, p + data_len);

    *out_len = total;
    return AWP_OK;
}

/* ========================================================================= */
/* Frame Decoding                                                            */
/* ========================================================================= */

awp_err_t awp_decode_frame(const uint8_t *data, size_t data_len,
                           awp_frame_t *frame)
{
    if (data_len < AWP_MIN_FRAME_SIZE) {
        ESP_LOGW(TAG, "Frame too small: %zu < %d", data_len, AWP_MIN_FRAME_SIZE);
        return AWP_ERR_SIZE;
    }

    /* Magic */
    uint32_t magic = get_u32_be(data + AWP_OFF_MAGIC);
    if (magic != AWP_MAGIC) {
        ESP_LOGW(TAG, "Bad magic: 0x%08lx", (unsigned long)magic);
        return AWP_ERR_MAGIC;
    }

    /* Version */
    uint16_t version = get_u16_be(data + AWP_OFF_VERSION);
    if (version != AWP_VERSION) {
        ESP_LOGW(TAG, "Bad version: 0x%04x", version);
        return AWP_ERR_VERSION;
    }

    /* Length */
    uint32_t total_len = get_u32_be(data + AWP_OFF_LENGTH);
    if (total_len > AWP_MAX_FRAME_SIZE) {
        ESP_LOGW(TAG, "Frame too large: %lu", (unsigned long)total_len);
        return AWP_ERR_SIZE;
    }
    if ((size_t)total_len != data_len) {
        ESP_LOGW(TAG, "Length mismatch: header=%lu, actual=%zu",
                 (unsigned long)total_len, data_len);
        return AWP_ERR_DECODE;
    }

    /* Verify checksum */
    size_t frame_data_len = data_len - AWP_CHECKSUM_SIZE;
    uint8_t computed[AWP_CHECKSUM_SIZE];
    awp_blake2b_checksum(data, frame_data_len, computed);

    if (memcmp(computed, data + frame_data_len, AWP_CHECKSUM_SIZE) != 0) {
        ESP_LOGW(TAG, "Checksum mismatch");
        return AWP_ERR_CHECKSUM;
    }

    /* Parse fields */
    frame->version = version;
    frame->flags   = get_u16_be(data + AWP_OFF_FLAGS);
    frame->msg_type = (awp_msg_type_t)get_u16_be(data + AWP_OFF_MSG_TYPE);

    /* Node ID — copy and null-terminate, stripping trailing zeros */
    memcpy(frame->node_id, data + AWP_OFF_NODE_ID, AWP_NODE_ID_SIZE);
    frame->node_id[AWP_NODE_ID_SIZE] = '\0';
    for (int i = AWP_NODE_ID_SIZE - 1; i >= 0; i--) {
        if (frame->node_id[i] == '\0') continue;
        break;
    }

    /* HDC Signature */
    memcpy(frame->hdc_signature, data + AWP_OFF_HDC_SIG, AWP_HDC_SIG_SIZE);

    /* Tenant HV */
    memcpy(frame->tenant_hv, data + AWP_OFF_TENANT_HV, AWP_TENANT_HV_SIZE);
    frame->has_tenant_hv = false;
    for (int i = 0; i < AWP_TENANT_HV_SIZE; i++) {
        if (frame->tenant_hv[i] != 0) {
            frame->has_tenant_hv = true;
            break;
        }
    }

    /* Session ID */
    memcpy(frame->session_id, data + AWP_OFF_SESSION_ID, AWP_SESSION_ID_SIZE);
    frame->has_session_id = false;
    for (int i = 0; i < AWP_SESSION_ID_SIZE; i++) {
        if (frame->session_id[i] != 0) {
            frame->has_session_id = true;
            break;
        }
    }

    /* Payload */
    frame->payload_len = data_len - AWP_HEADER_SIZE - AWP_CHECKSUM_SIZE;
    frame->payload = (frame->payload_len > 0)
        ? (uint8_t *)(data + AWP_OFF_PAYLOAD)
        : NULL;

    return AWP_OK;
}
