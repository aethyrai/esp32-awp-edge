/**
 * AethyrWire Protocol (AWP) — ESP32 Implementation
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Protocol Constants                                                        */
/* ========================================================================= */

#define AWP_MAGIC           0xAE370000
#define AWP_VERSION         0x0001

/* HDC dimensions */
#define AWP_HDC_DIM         4096
#define AWP_HDC_PACKED_SIZE (AWP_HDC_DIM / 32)  /* 128 int32s = 512 bytes */

/* Header field sizes */
#define AWP_MAGIC_SIZE      4
#define AWP_VERSION_SIZE    2
#define AWP_FLAGS_SIZE      2
#define AWP_LENGTH_SIZE     4
#define AWP_NODE_ID_SIZE    32
#define AWP_HDC_SIG_SIZE    (AWP_HDC_PACKED_SIZE * 4)
#define AWP_MSG_TYPE_SIZE   2
#define AWP_TENANT_HV_SIZE  64
#define AWP_SESSION_ID_SIZE 16
#define AWP_CHECKSUM_SIZE   32

/* Header layout offsets */
#define AWP_OFF_MAGIC       0
#define AWP_OFF_VERSION     (AWP_OFF_MAGIC + AWP_MAGIC_SIZE)
#define AWP_OFF_FLAGS       (AWP_OFF_VERSION + AWP_VERSION_SIZE)
#define AWP_OFF_LENGTH      (AWP_OFF_FLAGS + AWP_FLAGS_SIZE)
#define AWP_OFF_NODE_ID     (AWP_OFF_LENGTH + AWP_LENGTH_SIZE)
#define AWP_OFF_HDC_SIG     (AWP_OFF_NODE_ID + AWP_NODE_ID_SIZE)
#define AWP_OFF_MSG_TYPE    (AWP_OFF_HDC_SIG + AWP_HDC_SIG_SIZE)
#define AWP_OFF_TENANT_HV   (AWP_OFF_MSG_TYPE + AWP_MSG_TYPE_SIZE)
#define AWP_OFF_SESSION_ID  (AWP_OFF_TENANT_HV + AWP_TENANT_HV_SIZE)
#define AWP_OFF_PAYLOAD     (AWP_OFF_SESSION_ID + AWP_SESSION_ID_SIZE)

#define AWP_HEADER_SIZE     AWP_OFF_PAYLOAD  /* 638 bytes */
#define AWP_MIN_FRAME_SIZE  (AWP_HEADER_SIZE + AWP_CHECKSUM_SIZE) /* 670 bytes */

/* Maximum sizes */
#define AWP_MAX_FRAME_SIZE      (16 * 1024 * 1024)  /* 16 MB */
#define AWP_MAX_PAYLOAD_SIZE    (AWP_MAX_FRAME_SIZE - 1024)

/* ESP32 practical limits — large buffers allocated in PSRAM.
 * Sized for: 2B msg_type + HDC_SIG(512) + 256KB plaintext + ENCRYPT_OVERHEAD(40).
 * The 256KB cap gives comfortable headroom for HD JPEGs (observed max ~76KB)
 * and room to grow into FHD resolution without another protocol rev. */
#define AWP_ESP32_MAX_PAYLOAD   262144

/* Frame flags */
#define AWP_FLAG_ENCRYPTED      0x0001
#define AWP_FLAG_COMPRESSED     0x0002
#define AWP_FLAG_PRIORITY       0x0004
#define AWP_FLAG_REQUIRES_ACK   0x0008
#define AWP_FLAG_IS_RESPONSE    0x0010
#define AWP_FLAG_MULTIPART      0x0020
#define AWP_FLAG_HDC_ENCLOSED   0x0040

/* ========================================================================= */
/* Message Types                                                             */
/* ========================================================================= */

typedef enum {
    AWP_MSG_PING                = 0x01,
    AWP_MSG_PONG                = 0x02,
    AWP_MSG_DISCOVER_REQUEST    = 0x03,
    AWP_MSG_DISCOVER_RESPONSE   = 0x04,
    AWP_MSG_JOIN_NETWORK        = 0x05,
    AWP_MSG_LEAVE_NETWORK       = 0x06,
    AWP_MSG_PEER_LIST           = 0x07,
    AWP_MSG_CAPABILITY_ANNOUNCE = 0x08,
    AWP_MSG_AGENT_MIGRATE       = 0x10,
    AWP_MSG_AGENT_MIGRATE_ACK   = 0x11,
    AWP_MSG_AGENT_LOCATE_REQ    = 0x12,
    AWP_MSG_AGENT_LOCATE_RESP   = 0x13,
    AWP_MSG_AGENT_FETCH_REQ     = 0x14,
    AWP_MSG_AGENT_FETCH_RESP    = 0x15,
    AWP_MSG_AGENT_CALL          = 0x16,
    AWP_MSG_AGENT_CALL_RESPONSE = 0x17,
    AWP_MSG_HDC_STORE           = 0x20,
    AWP_MSG_HDC_STORE_ACK       = 0x21,
    AWP_MSG_HDC_QUERY           = 0x22,
    AWP_MSG_HDC_QUERY_RESULT    = 0x23,
    AWP_MSG_HDC_REPLICATE       = 0x24,
    AWP_MSG_HDC_REPLICATE_ACK   = 0x25,
    AWP_MSG_HDC_DELETE          = 0x26,
    AWP_MSG_HDC_DELETE_ACK      = 0x27,
    AWP_MSG_HDC_SYNC_REQUEST    = 0x28,
    AWP_MSG_HDC_SYNC_RESPONSE   = 0x29,
    AWP_MSG_GWT_REGISTER        = 0x30,
    AWP_MSG_GWT_REGISTER_ACK    = 0x31,
    AWP_MSG_GWT_PROPOSE         = 0x32,
    AWP_MSG_GWT_BROADCAST       = 0x33,
    AWP_MSG_GWT_DELIBERATE      = 0x34,
    AWP_MSG_GWT_RESULT          = 0x35,
    AWP_MSG_CONSENSUS_PROPOSE   = 0x40,
    AWP_MSG_CONSENSUS_VOTE      = 0x41,
    AWP_MSG_CONSENSUS_COMMIT    = 0x42,
    AWP_MSG_CONSENSUS_ABORT     = 0x43,
    AWP_MSG_RINGCAST_TASK       = 0x50,
    AWP_MSG_RINGCAST_BID        = 0x51,
    AWP_MSG_RINGCAST_AWARD      = 0x52,
    AWP_MSG_RINGCAST_COMPLETE   = 0x53,
    AWP_MSG_SQUAD_JOIN          = 0x54,
    AWP_MSG_SQUAD_LEAVE         = 0x55,
    AWP_MSG_SQUAD_EVICT         = 0x56,
    AWP_MSG_SQUAD_PROMOTE       = 0x57,
    AWP_MSG_FEDERATION_ROUTE    = 0x58,
    AWP_MSG_FEDERATION_BALANCE  = 0x59,
    AWP_MSG_FEDERATION_REPORT   = 0x5A,
    AWP_MSG_FEDERATION_ELECT    = 0x5B,
    AWP_MSG_DIRECTORATE_COMMAND = 0x5C,
    AWP_MSG_DIRECTORATE_DELIB   = 0x5D,
    AWP_MSG_DIRECTORATE_CONSENS = 0x5E,
    AWP_MSG_DIRECTORATE_VETO    = 0x5F,
    /* Edge media stream (0x70-0x7F) */
    AWP_MSG_MEDIA_FRAME         = 0x70,  /* JPEG frame or audio chunk */
    AWP_MSG_MEDIA_META          = 0x71,  /* JSON metadata for media stream */

    AWP_MSG_ERROR               = 0xF0,
    AWP_MSG_REDIRECT            = 0xF1,
    AWP_MSG_HELLO               = 0xF2,
    AWP_MSG_HELLO_ACK           = 0xF3,
    AWP_MSG_REGISTRY_SYNC       = 0xF4,
    AWP_MSG_HDC_QUERY_RESPONSE  = 0xF5,
} awp_msg_type_t;

/* ========================================================================= */
/* Frame Structure                                                           */
/* ========================================================================= */

typedef struct {
    awp_msg_type_t msg_type;
    uint16_t       flags;
    uint16_t       version;
    char           node_id[AWP_NODE_ID_SIZE + 1];
    uint8_t        hdc_signature[AWP_HDC_SIG_SIZE];
    uint8_t        tenant_hv[AWP_TENANT_HV_SIZE];
    uint8_t        session_id[AWP_SESSION_ID_SIZE];
    bool           has_tenant_hv;
    bool           has_session_id;
    uint8_t       *payload;
    size_t         payload_len;
} awp_frame_t;

/* ========================================================================= */
/* Error Codes                                                               */
/* ========================================================================= */

typedef enum {
    AWP_OK = 0,
    AWP_ERR_MAGIC,
    AWP_ERR_VERSION,
    AWP_ERR_CHECKSUM,
    AWP_ERR_SIZE,
    AWP_ERR_DECODE,
    AWP_ERR_ENCODE,
    AWP_ERR_NOMEM,
} awp_err_t;

const char *awp_err_str(awp_err_t err);

/* ========================================================================= */
/* Encoding / Decoding                                                       */
/* ========================================================================= */

/**
 * Encode an AWP frame into a byte buffer.
 *
 * @param frame     Frame to encode
 * @param out_buf   Output buffer (caller-allocated)
 * @param buf_size  Size of output buffer
 * @param out_len   Receives the actual encoded length
 * @return AWP_OK on success
 */
awp_err_t awp_encode_frame(const awp_frame_t *frame,
                           uint8_t *out_buf, size_t buf_size,
                           size_t *out_len);

/**
 * Decode an AWP frame from a byte buffer.
 *
 * The returned frame's payload pointer points into the input buffer —
 * caller must not free data before they're done with the frame.
 *
 * @param data      Raw frame bytes
 * @param data_len  Length of data
 * @param frame     Output frame structure
 * @return AWP_OK on success
 */
awp_err_t awp_decode_frame(const uint8_t *data, size_t data_len,
                           awp_frame_t *frame);

/**
 * Compute frame checksum.
 */
void awp_blake2b_checksum(const uint8_t *data, size_t data_len, uint8_t *out);

/**
 * Convenience: compute total encoded frame size for a given payload length.
 */
static inline size_t awp_frame_size(size_t payload_len)
{
    return AWP_HEADER_SIZE + payload_len + AWP_CHECKSUM_SIZE;
}

#ifdef __cplusplus
}
#endif
