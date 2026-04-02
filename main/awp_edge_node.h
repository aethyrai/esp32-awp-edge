/**
 * AWP Edge Node — ESP32 implementation
 */

#pragma once

#include "awp_protocol.h"
#include "awp_stream.h"
#include "awp_crypto.h"
#include "sensor_hub.h"

#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Node State                                                                */
/* ========================================================================= */

typedef enum {
    EDGE_STATE_INIT,
    EDGE_STATE_WIFI_CONNECTING,
    EDGE_STATE_WIFI_CONNECTED,
    EDGE_STATE_TCP_CONNECTING,
    EDGE_STATE_HANDSHAKE,
    EDGE_STATE_CONNECTED,       /* upstream alive, exchanging frames */
    EDGE_STATE_DISCONNECTED,
} edge_state_t;

/* ========================================================================= */
/* HDC LRU Cache                                                             */
/* ========================================================================= */

typedef struct hdc_cache_entry {
    char     key[64];
    uint8_t *vector;     /* heap-allocated, AWP_HDC_SIG_SIZE bytes */
    struct hdc_cache_entry *prev;
    struct hdc_cache_entry *next;
} hdc_cache_entry_t;

typedef struct {
    hdc_cache_entry_t *head;  /* most recently used */
    hdc_cache_entry_t *tail;  /* least recently used */
    size_t count;
    size_t capacity;
} hdc_cache_t;

/* ========================================================================= */
/* Edge Node Statistics                                                      */
/* ========================================================================= */

typedef struct {
    uint32_t cache_hits;
    uint32_t cache_misses;
    uint32_t frames_sent;
    uint32_t frames_received;
    uint32_t reconnect_count;
    int64_t  connected_since;  /* epoch ms, 0 if disconnected */
} edge_stats_t;

/* ========================================================================= */
/* Message Callback                                                          */
/* ========================================================================= */

/**
 * Application-level message callback. Payload buffer is temporary —
 * copy any data you need before returning.
 */
typedef void (*awp_msg_callback_t)(const awp_frame_t *frame, void *user_data);

/* ========================================================================= */
/* Edge Node Configuration                                                   */
/* ========================================================================= */

typedef struct {
    const char *node_name;
    const char *upstream_host;
    uint16_t    upstream_port;
    uint16_t    listen_port;
    size_t      hdc_cache_capacity;
    uint32_t    heartbeat_interval_ms;
    uint32_t    sensor_poll_interval_ms;
    awp_msg_callback_t msg_callback;
    void       *callback_user_data;

    /* Pre-shared key (set to NULL/0 to disable) */
    const uint8_t *psk;
    size_t          psk_len;
} edge_config_t;

/* ========================================================================= */
/* Edge Node Handle                                                          */
/* ========================================================================= */

typedef struct {
    edge_config_t  config;
    edge_state_t   state;

    /* Identity */
    char           node_id[AWP_NODE_ID_SIZE + 1];
    uint8_t        hdc_signature[AWP_HDC_SIG_SIZE];

    /* Upstream TCP */
    int            sock;
    awp_stream_t   stream;

    /* Transmit buffer — large enough for one frame */
    uint8_t        tx_buf[AWP_HEADER_SIZE + AWP_ESP32_MAX_PAYLOAD + AWP_CHECKSUM_SIZE];

    /* HDC cache */
    hdc_cache_t    cache;

    /* Stats */
    edge_stats_t   stats;

    /* PQC Crypto */
    awp_crypto_t   crypto;

    /* FreeRTOS */
    EventGroupHandle_t  events;
    SemaphoreHandle_t   tx_mutex;       /* guards tx_buf + encrypt path */
    TaskHandle_t        conn_task;
    TaskHandle_t        heartbeat_task;

    bool           running;
} edge_node_t;

/* Event bits */
#define EDGE_EVT_WIFI_CONNECTED    BIT0
#define EDGE_EVT_WIFI_DISCONNECTED BIT1
#define EDGE_EVT_UPSTREAM_READY    BIT2
#define EDGE_EVT_SHUTDOWN          BIT3

/* ========================================================================= */
/* Public API                                                                */
/* ========================================================================= */

void edge_node_init(edge_node_t *node, const edge_config_t *config);
void edge_node_compute_hdc_identity(edge_node_t *node, const sensor_hub_t *sensors);
void edge_node_start(edge_node_t *node);
void edge_node_stop(edge_node_t *node);
awp_err_t edge_node_send(edge_node_t *node, const awp_frame_t *frame);
awp_err_t edge_node_announce_capabilities(edge_node_t *node,
                                          const char *capabilities_json);
awp_err_t edge_node_send_telemetry(edge_node_t *node,
                                   const char *json_payload);
edge_state_t edge_node_state(const edge_node_t *node);
edge_stats_t edge_node_stats(const edge_node_t *node);

#ifdef __cplusplus
}
#endif
