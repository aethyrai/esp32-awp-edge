/**
 * AWP Edge Node — ESP32 implementation
 */

#include "awp_edge_node.h"
#include "sensor_hub.h"

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "cJSON.h"
#include "esp_task_wdt.h"
#include <fcntl.h>

static const char *TAG = "awp_edge";

/* ========================================================================= */
/* HDC Cache                                                                 */
/* ========================================================================= */

static void cache_init(hdc_cache_t *c, size_t capacity)
{
    c->head = NULL;
    c->tail = NULL;
    c->count = 0;
    c->capacity = capacity;
}

static void cache_destroy(hdc_cache_t *c)
{
    hdc_cache_entry_t *e = c->head;
    while (e) {
        hdc_cache_entry_t *next = e->next;
        free(e->vector);
        free(e);
        e = next;
    }
    c->head = c->tail = NULL;
    c->count = 0;
}

/* ========================================================================= */
/* HDC Identity Computation                                                  */
/* ========================================================================= */

#include "blake3.h"

static void hdc_basis(const char *name, uint8_t out[AWP_HDC_SIG_SIZE])
{
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, "awp-hdc-basis-v1");
    blake3_hasher_update(&h, (const uint8_t *)name, strlen(name));
    blake3_hasher_finalize(&h, out, AWP_HDC_SIG_SIZE);
}

static void hdc_bind(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++)
        out[i] = a[i] ^ b[i];
}

static void hdc_permute(const uint8_t *in, int k, uint8_t *out)
{
    k = ((k % AWP_HDC_SIG_SIZE) + AWP_HDC_SIG_SIZE) % AWP_HDC_SIG_SIZE;
    memcpy(out, in + k, AWP_HDC_SIG_SIZE - k);
    memcpy(out + AWP_HDC_SIG_SIZE - k, in, k);
}

static void hdc_tally(uint16_t *counts, const uint8_t *vec)
{
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++) {
        uint8_t b = vec[i];
        int base = i * 8;
        counts[base + 0] += (b >> 0) & 1;
        counts[base + 1] += (b >> 1) & 1;
        counts[base + 2] += (b >> 2) & 1;
        counts[base + 3] += (b >> 3) & 1;
        counts[base + 4] += (b >> 4) & 1;
        counts[base + 5] += (b >> 5) & 1;
        counts[base + 6] += (b >> 6) & 1;
        counts[base + 7] += (b >> 7) & 1;
    }
}

static void hdc_threshold(const uint16_t *counts, size_t n, uint8_t *out)
{
    uint8_t tiebreaker[AWP_HDC_SIG_SIZE];
    bool need_tiebreak = (n % 2 == 0);
    if (need_tiebreak) {
        hdc_basis("_tiebreaker_", tiebreaker);
    }

    size_t thresh = n / 2;
    memset(out, 0, AWP_HDC_SIG_SIZE);
    for (int i = 0; i < AWP_HDC_SIG_SIZE; i++) {
        uint8_t byte = 0;
        int base = i * 8;
        for (int bit = 0; bit < 8; bit++) {
            uint16_t c = counts[base + bit];
            if (c > thresh) {
                byte |= (1 << bit);
            } else if (need_tiebreak && c == thresh) {
                if (tiebreaker[i] & (1 << bit)) byte |= (1 << bit);
            }
        }
        out[i] = byte;
    }
}

/* ========================================================================= */
/* WiFi Event Handling                                                       */
/* ========================================================================= */

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    edge_node_t *node = (edge_node_t *)arg;

    if (base == WIFI_EVENT) {
        switch (id) {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            ESP_LOGW(TAG, "WiFi disconnected, reconnecting...");
            node->state = EDGE_STATE_WIFI_CONNECTING;
            xEventGroupSetBits(node->events, EDGE_EVT_WIFI_DISCONNECTED);
            xEventGroupClearBits(node->events, EDGE_EVT_WIFI_CONNECTED);
            esp_wifi_connect();
            break;
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        node->state = EDGE_STATE_WIFI_CONNECTED;
        xEventGroupSetBits(node->events, EDGE_EVT_WIFI_CONNECTED);
        xEventGroupClearBits(node->events, EDGE_EVT_WIFI_DISCONNECTED);
    }
}

static void wifi_init_sta(edge_node_t *node)
{
    node->state = EDGE_STATE_WIFI_CONNECTING;

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t wifi_handler, ip_handler;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, node, &wifi_handler));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, node, &ip_handler));

    wifi_config_t wifi_cfg = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    strncpy((char *)wifi_cfg.sta.ssid, CONFIG_AWP_WIFI_SSID,
            sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, CONFIG_AWP_WIFI_PASSWORD,
            sizeof(wifi_cfg.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "WiFi STA initialized, connecting to %s", CONFIG_AWP_WIFI_SSID);
}

/* ========================================================================= */
/* Frame Helpers                                                             */
/* ========================================================================= */

static void fill_identity(edge_node_t *node, awp_frame_t *frame)
{
    memset(frame, 0, sizeof(*frame));
    strncpy(frame->node_id, node->node_id, AWP_NODE_ID_SIZE);
    memcpy(frame->hdc_signature, node->hdc_signature, AWP_HDC_SIG_SIZE);
    frame->version = AWP_VERSION;
}

static awp_err_t send_raw(edge_node_t *node, const uint8_t *data, size_t len)
{
    if (node->sock < 0) return AWP_ERR_DECODE;

    size_t sent = 0;
    while (sent < len) {
        int n = send(node->sock, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            ESP_LOGE(TAG, "send() failed: errno %d", errno);
            return AWP_ERR_DECODE;
        }
        sent += n;
    }
    node->stats.frames_sent++;
    return AWP_OK;
}

/* ========================================================================= */
/* HELLO Handshake                                                           */
/* ========================================================================= */

static awp_err_t do_handshake(edge_node_t *node)
{
    ESP_LOGI(TAG, "Sending HELLO to upstream...");
    node->state = EDGE_STATE_HANDSHAKE;

    /* Generate ephemeral KEM keypair */
    if (!awp_crypto_new_keypair(&node->crypto)) {
        ESP_LOGE(TAG, "Ephemeral keypair generation failed");
        return AWP_ERR_ENCODE;
    }

    /* Reset replay window for new session */
    node->crypto.replay_top = 0;
    node->crypto.replay_bitmap = 0;

    /* Build HELLO payload */
    cJSON *jhello = cJSON_CreateObject();
    cJSON_AddStringToObject(jhello, "node_id", node->node_id);
    cJSON_AddStringToObject(jhello, "name", node->config.node_name);
    cJSON_AddNumberToObject(jhello, "tier", 1);
    cJSON_AddNumberToObject(jhello, "subtype", 1);

    char addr_buf[32];
    snprintf(addr_buf, sizeof(addr_buf), "0.0.0.0:%d", (int)node->config.listen_port);
    cJSON_AddStringToObject(jhello, "address", addr_buf);

    cJSON *caps = cJSON_AddArrayToObject(jhello, "capabilities");
    cJSON_AddItemToArray(caps, cJSON_CreateNumber(11));
    cJSON_AddItemToArray(caps, cJSON_CreateNumber(10));
    cJSON_AddNumberToObject(jhello, "hdc_capacity", (int)node->cache.capacity);

    if (node->crypto.kem_ready) {
        char kem_ek_hex[AWP_KEM_PK_SIZE * 2 + 1];
        awp_crypto_get_ek_hex(&node->crypto, kem_ek_hex, sizeof(kem_ek_hex));
        cJSON_AddStringToObject(jhello, "kem_encapsulation_key", kem_ek_hex);
    }

    char *payload = cJSON_PrintUnformatted(jhello);
    cJSON_Delete(jhello);
    if (!payload) return AWP_ERR_ENCODE;
    int plen = strlen(payload);

    awp_frame_t hello;
    fill_identity(node, &hello);
    hello.msg_type = AWP_MSG_HELLO;
    hello.payload = (uint8_t *)payload;
    hello.payload_len = plen;

    size_t enc_len = 0;
    awp_err_t err = awp_encode_frame(&hello, node->tx_buf, sizeof(node->tx_buf), &enc_len);
    cJSON_free(payload);
    if (err != AWP_OK) return err;

    ESP_LOGI(TAG, "HELLO payload: %d bytes (KEM key %s)",
             plen, node->crypto.kem_ready ? "included" : "omitted");

    err = send_raw(node, node->tx_buf, enc_len);
    if (err != AWP_OK) return err;

    /* Wait for HELLO_ACK */
    ESP_LOGI(TAG, "Waiting for HELLO_ACK...");

    int64_t deadline = esp_timer_get_time() / 1000 + 10000; /* 10s timeout */
    awp_stream_clear(&node->stream);

    while (esp_timer_get_time() / 1000 < deadline) {
        uint8_t rx_buf[4096];
        int n = recv(node->sock, rx_buf, sizeof(rx_buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                vTaskDelay(pdMS_TO_TICKS(50));
                continue;
            }
            ESP_LOGE(TAG, "recv() during handshake: errno %d", errno);
            return AWP_ERR_DECODE;
        }
        if (n == 0) {
            ESP_LOGE(TAG, "Connection closed during handshake");
            return AWP_ERR_DECODE;
        }

        awp_frame_t frames[4];
        size_t count = 0;
        awp_stream_feed(&node->stream, rx_buf, n, frames, 4, &count);

        for (size_t i = 0; i < count; i++) {
            if (frames[i].msg_type == AWP_MSG_HELLO_ACK) {
                ESP_LOGI(TAG, "HELLO_ACK received from %s", frames[i].node_id);
                node->stats.frames_received++;

                /* PQC handshake */
                if (node->crypto.kem_ready && frames[i].payload_len > 0) {
                    /* Null-terminate payload for safe string operations */
                    size_t plen = frames[i].payload_len;
                    char *ack_json = malloc(plen + 1);
                    if (!ack_json) break;
                    memcpy(ack_json, frames[i].payload, plen);
                    ack_json[plen] = '\0';

                    cJSON *jack = cJSON_Parse(ack_json);
                    free(ack_json);
                    if (!jack) {
                        ESP_LOGE(TAG, "HELLO_ACK JSON parse failed");
                        return AWP_ERR_DECODE;
                    }

                    cJSON *ct_item = cJSON_GetObjectItem(jack, "kem_ciphertext");
                    if (!cJSON_IsString(ct_item) || !ct_item->valuestring) {
                        ESP_LOGE(TAG, "SECURITY: No KEM ciphertext in HELLO_ACK — refusing unencrypted session");
                        cJSON_Delete(jack);
                        return AWP_ERR_DECODE;  /* Abort — downgrade attack prevention */
                    }

                    const char *ct_hex = ct_item->valuestring;
                    if (strlen(ct_hex) == AWP_KEM_CT_SIZE * 2) {
                        if (awp_crypto_accept_handshake(&node->crypto, ct_hex)) {
                            ESP_LOGI(TAG, "PQC session established — ML-KEM-768 + ChaCha20-Poly1305");
                            UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
                            ESP_LOGI(TAG, "conn task stack: alloc=49152 peak=%lu free=%lu bytes",
                                     49152UL - (unsigned long)(hwm * sizeof(StackType_t)),
                                     (unsigned long)(hwm * sizeof(StackType_t)));
                        } else {
                            ESP_LOGW(TAG, "PQC handshake failed");
                        }
                    } else {
                        ESP_LOGW(TAG, "KEM ciphertext wrong length: %zu (expected %d)",
                                 strlen(ct_hex), AWP_KEM_CT_SIZE * 2);
                    }
                    cJSON_Delete(jack);

                    /* Refuse connection without PQC session */
                    if (!awp_crypto_has_session(&node->crypto)) {
                        ESP_LOGE(TAG, "SECURITY: PQC handshake did not complete — aborting");
                        return AWP_ERR_DECODE;
                    }

                    /* Send auth token */
                    uint8_t auth_token[32];
                    awp_crypto_auth_token(&node->crypto, node->node_id, auth_token);

                    char token_hex[65];
                    for (int t = 0; t < 32; t++)
                        sprintf(token_hex + t*2, "%02x", auth_token[t]);
                    token_hex[64] = '\0';

                    cJSON *jauth = cJSON_CreateObject();
                    cJSON_AddStringToObject(jauth, "type", "node_auth");
                    cJSON_AddStringToObject(jauth, "node_id", node->node_id);
                    cJSON_AddStringToObject(jauth, "token", token_hex);
                    char *auth_str = cJSON_PrintUnformatted(jauth);
                    cJSON_Delete(jauth);

                    if (auth_str) {
                        awp_frame_t auth_frame;
                        fill_identity(node, &auth_frame);
                        auth_frame.msg_type = AWP_MSG_CAPABILITY_ANNOUNCE;
                        auth_frame.payload = (uint8_t *)auth_str;
                        auth_frame.payload_len = strlen(auth_str);
                        /* This will be auto-encrypted by edge_node_send */
                        edge_node_send(node, &auth_frame);
                        cJSON_free(auth_str);
                    }
                    ESP_LOGI(TAG, "Sent encrypted auth token");
                }

                return AWP_OK;
            }
        }
    }

    ESP_LOGW(TAG, "HELLO_ACK timeout");
    return AWP_ERR_DECODE;
}

/* ========================================================================= */
/* Connection Task                                                           */
/* ========================================================================= */

static void tcp_connect(edge_node_t *node)
{
    node->state = EDGE_STATE_TCP_CONNECTING;

    if (node->sock >= 0) {
        close(node->sock);
        node->sock = -1;
    }

    node->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (node->sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        return;
    }

    /* Set recv timeout for handshake */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(node->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(node->config.upstream_port),
    };
    inet_pton(AF_INET, node->config.upstream_host, &dest.sin_addr);

    ESP_LOGI(TAG, "Connecting to %s:%d ...",
             node->config.upstream_host, node->config.upstream_port);

    if (connect(node->sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        ESP_LOGW(TAG, "connect() failed: errno %d", errno);
        close(node->sock);
        node->sock = -1;
        return;
    }

    ESP_LOGI(TAG, "TCP connected to upstream");

    /* Handshake */
    if (do_handshake(node) == AWP_OK) {
        node->state = EDGE_STATE_CONNECTED;
        node->stats.connected_since = esp_timer_get_time() / 1000;
        xEventGroupSetBits(node->events, EDGE_EVT_UPSTREAM_READY);

        /* Switch to non-blocking for message loop */
        int flags = fcntl(node->sock, F_GETFL, 0);
        fcntl(node->sock, F_SETFL, flags | O_NONBLOCK);
    } else {
        ESP_LOGW(TAG, "Handshake failed");
        close(node->sock);
        node->sock = -1;
        node->state = EDGE_STATE_DISCONNECTED;
    }
}

static void handle_upstream_frame(edge_node_t *node, const awp_frame_t *frame)
{
    node->stats.frames_received++;

    switch (frame->msg_type) {
    case AWP_MSG_PONG:
        /* Heartbeat response — nothing to do */
        break;

    case AWP_MSG_PING: {
        /* Respond with PONG — uses edge_node_send for auto-encryption */
        cJSON *jpong = cJSON_CreateObject();
        cJSON_AddNumberToObject(jpong, "timestamp",
            (double)(esp_timer_get_time() / 1000) / 1000.0);
        cJSON_AddNumberToObject(jpong, "ping_timestamp", 0);
        cJSON_AddItemToObject(jpong, "capabilities", cJSON_CreateArray());
        char *pong_str = cJSON_PrintUnformatted(jpong);
        cJSON_Delete(jpong);

        if (pong_str) {
            awp_frame_t pong;
            fill_identity(node, &pong);
            pong.msg_type = AWP_MSG_PONG;
            pong.flags = AWP_FLAG_IS_RESPONSE;
            pong.payload = (uint8_t *)pong_str;
            pong.payload_len = strlen(pong_str);
            edge_node_send(node, &pong);
            cJSON_free(pong_str);
        }
        break;
    }

    case AWP_MSG_DISCOVER_REQUEST: {
        /* Respond with our node info — auto-encrypted */
        char addr_buf[32];
        snprintf(addr_buf, sizeof(addr_buf), "0.0.0.0:%d",
                 (int)node->config.listen_port);

        cJSON *jnode = cJSON_CreateObject();
        cJSON_AddStringToObject(jnode, "node_id", node->node_id);
        cJSON_AddStringToObject(jnode, "name", node->config.node_name);
        cJSON_AddNumberToObject(jnode, "tier", 1);
        cJSON_AddNumberToObject(jnode, "subtype", 1);
        cJSON_AddStringToObject(jnode, "address", addr_buf);
        cJSON *dcaps = cJSON_AddArrayToObject(jnode, "capabilities");
        cJSON_AddItemToArray(dcaps, cJSON_CreateNumber(11));
        cJSON_AddItemToArray(dcaps, cJSON_CreateNumber(10));
        cJSON_AddNumberToObject(jnode, "hdc_capacity", (int)node->cache.capacity);

        cJSON *jdisc = cJSON_CreateObject();
        cJSON *nodes_arr = cJSON_AddArrayToObject(jdisc, "nodes");
        cJSON_AddItemToArray(nodes_arr, jnode);

        char *disc_str = cJSON_PrintUnformatted(jdisc);
        cJSON_Delete(jdisc);

        if (disc_str) {
            awp_frame_t resp;
            fill_identity(node, &resp);
            resp.msg_type = AWP_MSG_DISCOVER_RESPONSE;
            resp.flags = AWP_FLAG_IS_RESPONSE;
            resp.payload = (uint8_t *)disc_str;
            resp.payload_len = strlen(disc_str);
            edge_node_send(node, &resp);
            cJSON_free(disc_str);
        }
        break;
    }

    case AWP_MSG_HDC_QUERY_RESPONSE:
        /* Cache results locally */
        ESP_LOGD(TAG, "HDC query response (%zu bytes)", frame->payload_len);
        break;

    case AWP_MSG_ERROR:
        ESP_LOGW(TAG, "Error from upstream: %.*s",
                 (int)frame->payload_len, (char *)frame->payload);
        break;

    case AWP_MSG_RINGCAST_TASK:
        ESP_LOGI(TAG, "Ring-Cast task received (%zu bytes)", frame->payload_len);
        /* FALLTHROUGH */

    default:
        if (node->config.msg_callback) {
            node->config.msg_callback(frame, node->config.callback_user_data);
        }
        break;
    }
}

static void connection_task(void *arg)
{
    edge_node_t *node = (edge_node_t *)arg;
    esp_task_wdt_add(NULL);

    while (node->running) {
        /* Wait for WiFi — 3s chunks for WDT (timeout=5s) */
        while (node->running) {
            esp_task_wdt_reset();
            EventBits_t bits = xEventGroupWaitBits(node->events,
                EDGE_EVT_WIFI_CONNECTED, pdFALSE, pdTRUE, pdMS_TO_TICKS(3000));
            if (bits & EDGE_EVT_WIFI_CONNECTED) break;
        }
        if (!node->running) break;

        /* Connect if needed — exponential backoff on failure */
        if (node->state != EDGE_STATE_CONNECTED) {
            static uint32_t backoff_ms = 1000;
            tcp_connect(node);
            if (node->state != EDGE_STATE_CONNECTED) {
                node->stats.reconnect_count++;
                ESP_LOGW(TAG, "Reconnect in %lums (attempt %lu)",
                         (unsigned long)backoff_ms,
                         (unsigned long)node->stats.reconnect_count);
                /* Sleep backoff in WDT-safe chunks */
                uint32_t remaining = backoff_ms;
                while (remaining > 0 && node->running) {
                    uint32_t chunk = (remaining > 3000) ? 3000 : remaining;
                    vTaskDelay(pdMS_TO_TICKS(chunk));
                    esp_task_wdt_reset();
                    remaining -= chunk;
                }
                /* Exponential backoff: 1s → 2s → 4s → ... → max */
                backoff_ms *= 2;
                if (backoff_ms > CONFIG_AWP_RECONNECT_BACKOFF_MAX_MS) {
                    backoff_ms = CONFIG_AWP_RECONNECT_BACKOFF_MAX_MS;
                }
                continue;
            }
            backoff_ms = 1000; /* reset on success */
        }

        /* Message receive loop */
        esp_task_wdt_reset();
        uint8_t rx_buf[2048];
        int n = recv(node->sock, rx_buf, sizeof(rx_buf), 0);

        if (n > 0) {
            awp_frame_t frames[AWP_STREAM_MAX_FRAMES];
            size_t count = 0;
            awp_stream_feed(&node->stream, rx_buf, n, frames,
                           AWP_STREAM_MAX_FRAMES, &count);

            for (size_t i = 0; i < count; i++) {
                /* Decrypt payload if FLAG_ENCRYPTED is set */
                if ((frames[i].flags & AWP_FLAG_ENCRYPTED) &&
                    awp_crypto_has_session(&node->crypto) &&
                    frames[i].payload_len > AWP_ENCRYPT_OVERHEAD) {

                    uint8_t *dec_buf = malloc(frames[i].payload_len);
                    size_t dec_len = 0;
                    if (dec_buf && awp_crypto_decrypt(&node->crypto,
                            frames[i].payload, frames[i].payload_len,
                            dec_buf, &dec_len)) {
                        /* Strip enclosed HDC signature from decrypted payload */
                        if ((frames[i].flags & AWP_FLAG_HDC_ENCLOSED) &&
                            dec_len > AWP_HDC_SIG_SIZE) {
                            memcpy(frames[i].hdc_signature, dec_buf, AWP_HDC_SIG_SIZE);
                            frames[i].payload = dec_buf + AWP_HDC_SIG_SIZE;
                            frames[i].payload_len = dec_len - AWP_HDC_SIG_SIZE;
                        } else {
                            frames[i].payload = dec_buf;
                            frames[i].payload_len = dec_len;
                        }
                        frames[i].flags &= ~(AWP_FLAG_ENCRYPTED | AWP_FLAG_HDC_ENCLOSED);
                        handle_upstream_frame(node, &frames[i]);
                        free(dec_buf);
                    } else {
                        ESP_LOGW(TAG, "Failed to decrypt frame 0x%02x", frames[i].msg_type);
                        if (dec_buf) free(dec_buf);
                    }
                } else {
                    handle_upstream_frame(node, &frames[i]);
                }
            }
        } else if (n == 0) {
            /* Upstream closed */
            ESP_LOGW(TAG, "Upstream disconnected");
            close(node->sock);
            node->sock = -1;
            node->state = EDGE_STATE_DISCONNECTED;
            node->stats.connected_since = 0;
            memset(node->crypto.session_key, 0, AWP_KEY_SIZE);
            node->crypto.session_ready = false;
            xEventGroupClearBits(node->events, EDGE_EVT_UPSTREAM_READY);
            continue;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                vTaskDelay(pdMS_TO_TICKS(50));
            } else {
                ESP_LOGE(TAG, "recv() error: errno %d", errno);
                close(node->sock);
                node->sock = -1;
                node->state = EDGE_STATE_DISCONNECTED;
                node->stats.connected_since = 0;
                memset(node->crypto.session_key, 0, AWP_KEY_SIZE);
                node->crypto.session_ready = false;
                xEventGroupClearBits(node->events, EDGE_EVT_UPSTREAM_READY);
            }
        }
    }

    vTaskDelete(NULL);
}

/* ========================================================================= */
/* Heartbeat Task                                                            */
/* ========================================================================= */

static void heartbeat_task(void *arg)
{
    edge_node_t *node = (edge_node_t *)arg;
    esp_task_wdt_add(NULL);
    esp_task_wdt_reset();

    while (node->running) {
        /* Wait until upstream is connected — use 3s chunks for WDT (timeout=5s) */
        while (node->running) {
            esp_task_wdt_reset();
            EventBits_t bits = xEventGroupWaitBits(node->events,
                EDGE_EVT_UPSTREAM_READY, pdFALSE, pdTRUE, pdMS_TO_TICKS(3000));
            if (bits & EDGE_EVT_UPSTREAM_READY) break;
        }
        if (!node->running) break;

        /* Build PING with embedded diagnostics for remote monitoring */
        cJSON *jping = cJSON_CreateObject();
        cJSON_AddNumberToObject(jping, "timestamp",
            (double)(esp_timer_get_time() / 1000) / 1000.0);
        cJSON_AddNumberToObject(jping, "free_heap",
            (double)esp_get_free_heap_size());
        cJSON_AddNumberToObject(jping, "min_heap",
            (double)esp_get_minimum_free_heap_size());
        cJSON_AddNumberToObject(jping, "frames_sent",
            (double)node->stats.frames_sent);
        cJSON_AddNumberToObject(jping, "frames_recv",
            (double)node->stats.frames_received);
        cJSON_AddNumberToObject(jping, "reconnects",
            (double)node->stats.reconnect_count);
        cJSON_AddNumberToObject(jping, "uptime_ms",
            (double)(esp_timer_get_time() / 1000));
        char *ping_str = cJSON_PrintUnformatted(jping);
        cJSON_Delete(jping);

        if (ping_str) {
            awp_frame_t ping;
            fill_identity(node, &ping);
            ping.msg_type = AWP_MSG_PING;
            ping.payload = (uint8_t *)ping_str;
            ping.payload_len = strlen(ping_str);

            if (edge_node_send(node, &ping) != AWP_OK) {
                ESP_LOGW(TAG, "Heartbeat send failed");
            }
            cJSON_free(ping_str);
        }

        /* Sleep in 3s chunks so WDT stays fed (timeout=5s) */
        uint32_t remaining = node->config.heartbeat_interval_ms;
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
/* Public API                                                                */
/* ========================================================================= */

void edge_node_init(edge_node_t *node, const edge_config_t *config)
{
    memset(node, 0, sizeof(*node));
    node->config = *config;
    node->state = EDGE_STATE_INIT;
    node->sock = -1;
    node->running = false;

    /* Init NVS early — crypto needs it for nonce persistence */
    esp_err_t nvs_ret = nvs_flash_init();
    if (nvs_ret == ESP_ERR_NVS_NO_FREE_PAGES || nvs_ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* Generate random node ID (12 hex chars, matching Python) */
    uint32_t r[2];
    esp_fill_random(r, sizeof(r));
    snprintf(node->node_id, sizeof(node->node_id),
             "%08lx%04lx", (unsigned long)r[0], (unsigned long)(r[1] & 0xFFFF));

    /* Initialize subsystems */
    awp_stream_init(&node->stream);
    cache_init(&node->cache, config->hdc_cache_capacity);

    /* Initialize crypto */
    awp_crypto_init(&node->crypto);

    node->events = xEventGroupCreate();
    node->tx_mutex = xSemaphoreCreateMutex();
    configASSERT(node->tx_mutex);

    /* Set PSK if provided */
    if (config->psk && config->psk_len > 0) {
        awp_crypto_set_psk(&node->crypto, config->psk, config->psk_len);
    }

    ESP_LOGI(TAG, "Edge node initialized: id=%s, name=%s, psk=%s",
             node->node_id, config->node_name,
             node->crypto.psk_len > 0 ? "yes" : "none");
}

void edge_node_compute_hdc_identity(edge_node_t *node, const sensor_hub_t *sensors)
{
    /* Heap-allocated bit counters */
    uint16_t *counts = calloc(AWP_HDC_DIM, sizeof(uint16_t));
    if (!counts) {
        ESP_LOGE(TAG, "HDC identity: alloc failed, signature will be zero");
        return;
    }

    uint8_t basis[AWP_HDC_SIG_SIZE];
    uint8_t value[AWP_HDC_SIG_SIZE];
    uint8_t bound[AWP_HDC_SIG_SIZE];
    uint8_t perm[AWP_HDC_SIG_SIZE];
    size_t n = 0;

    /* --- Node identity --- */
    hdc_basis("node_id", basis);
    hdc_basis(node->node_id, value);
    hdc_bind(basis, value, bound);
    hdc_tally(counts, bound); n++;

    /* --- Node name --- */
    hdc_basis("node_name", basis);
    hdc_basis(node->config.node_name, value);
    hdc_bind(basis, value, bound);
    hdc_tally(counts, bound); n++;

    /* --- Tier (EDGE = 1) --- */
    hdc_basis("tier_edge", basis);
    hdc_tally(counts, basis); n++;

    /* --- PQC capability --- */
    if (node->crypto.kem_ready) {
        hdc_basis("pqc_mlkem768", basis);
        hdc_tally(counts, basis); n++;
    }

    /* Sensor profile */
    if (sensors) {
        for (size_t i = 0; i < sensors->count; i++) {
            hdc_basis("sensor", basis);
            hdc_basis(sensors->sensors[i].name, value);
            hdc_bind(basis, value, bound);
            hdc_permute(bound, (int)(i + 1), perm);
            hdc_tally(counts, perm); n++;
        }
    }

    /* Threshold into final identity vector */
    hdc_threshold(counts, n, node->hdc_signature);
    free(counts);

    ESP_LOGI(TAG, "HDC identity computed: %zu components, %d-bit vector",
             n, AWP_HDC_DIM);
}

void edge_node_start(edge_node_t *node)
{
    node->running = true;

    /* NVS already initialized in edge_node_init() */

    /* Init network stack */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Start WiFi */
    wifi_init_sta(node);

    /* Launch tasks */
    xTaskCreate(connection_task, "awp_conn", 49152, node, 5, &node->conn_task);
    xTaskCreate(heartbeat_task, "awp_hb", 8192, node, 4, &node->heartbeat_task);

    ESP_LOGI(TAG, "Edge node started");
}

void edge_node_stop(edge_node_t *node)
{
    ESP_LOGI(TAG, "Stopping edge node...");
    node->running = false;

    xEventGroupSetBits(node->events, EDGE_EVT_SHUTDOWN |
                       EDGE_EVT_WIFI_CONNECTED | EDGE_EVT_UPSTREAM_READY);

    /* Give tasks time to exit */
    vTaskDelay(pdMS_TO_TICKS(500));

    if (node->sock >= 0) {
        close(node->sock);
        node->sock = -1;
    }

    cache_destroy(&node->cache);

    /* Wipe session key material */
    memset(node->crypto.session_key, 0, AWP_KEY_SIZE);
    node->crypto.session_ready = false;

    if (node->tx_mutex) {
        vSemaphoreDelete(node->tx_mutex);
        node->tx_mutex = NULL;
    }

    if (node->events) {
        vEventGroupDelete(node->events);
        node->events = NULL;
    }

    ESP_LOGI(TAG, "Edge node stopped");
}

awp_err_t edge_node_send(edge_node_t *node, const awp_frame_t *frame)
{
    if (xSemaphoreTake(node->tx_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "tx_mutex timeout — send dropped");
        return AWP_ERR_ENCODE;
    }

    if (node->state != EDGE_STATE_CONNECTED) {
        xSemaphoreGive(node->tx_mutex);
        return AWP_ERR_DECODE;
    }

    awp_err_t ret;

    /* Encrypt if session is established */
    if (awp_crypto_has_session(&node->crypto) && frame->payload_len > 0) {
        /* Static: tx_mutex serialises access */
        static uint8_t enc_payload[AWP_HDC_SIG_SIZE + AWP_ESP32_MAX_PAYLOAD + AWP_ENCRYPT_OVERHEAD];
        size_t enc_payload_len = 0;

        /* Build combined plaintext */
        size_t combined_len = AWP_HDC_SIG_SIZE + frame->payload_len;
        memcpy(node->tx_buf, node->hdc_signature, AWP_HDC_SIG_SIZE);
        memcpy(node->tx_buf + AWP_HDC_SIG_SIZE, frame->payload, frame->payload_len);

        if (!awp_crypto_encrypt(&node->crypto,
                                node->tx_buf, combined_len,
                                enc_payload, &enc_payload_len)) {
            ESP_LOGE(TAG, "SECURITY: encryption failed — refusing plaintext send");
            xSemaphoreGive(node->tx_mutex);
            return AWP_ERR_ENCODE;
        }

        /* Build encrypted frame copy */
        awp_frame_t enc_frame = *frame;
        enc_frame.payload = enc_payload;
        enc_frame.payload_len = enc_payload_len;
        enc_frame.flags |= AWP_FLAG_ENCRYPTED | AWP_FLAG_HDC_ENCLOSED;

        size_t wire_len = 0;
        ret = awp_encode_frame(&enc_frame, node->tx_buf,
                               sizeof(node->tx_buf), &wire_len);
        if (ret == AWP_OK) {
            ret = send_raw(node, node->tx_buf, wire_len);
        }
    } else {
        size_t wire_len = 0;
        ret = awp_encode_frame(frame, node->tx_buf, sizeof(node->tx_buf), &wire_len);
        if (ret == AWP_OK) {
            ret = send_raw(node, node->tx_buf, wire_len);
        }
    }

    xSemaphoreGive(node->tx_mutex);
    return ret;
}

awp_err_t edge_node_announce_capabilities(edge_node_t *node,
                                          const char *capabilities_json)
{
    awp_frame_t frame;
    fill_identity(node, &frame);
    frame.msg_type = AWP_MSG_CAPABILITY_ANNOUNCE;
    frame.payload = (uint8_t *)capabilities_json;
    frame.payload_len = strlen(capabilities_json);
    frame.flags = AWP_FLAG_REQUIRES_ACK;

    return edge_node_send(node, &frame);
}

awp_err_t edge_node_send_telemetry(edge_node_t *node,
                                   const char *json_payload)
{
    awp_frame_t frame;
    fill_identity(node, &frame);
    frame.msg_type = AWP_MSG_AGENT_CALL_RESPONSE;
    frame.payload = (uint8_t *)json_payload;
    frame.payload_len = strlen(json_payload);
    frame.flags = AWP_FLAG_IS_RESPONSE;

    return edge_node_send(node, &frame);
}

edge_state_t edge_node_state(const edge_node_t *node)
{
    return node->state;
}

edge_stats_t edge_node_stats(const edge_node_t *node)
{
    return node->stats;
}
