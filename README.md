# esp32-awp-edge

Post-quantum encrypted IoT edge node for ESP32-S3. Speaks the [AethyrWire Protocol](https://aethyr.cloud) (AWP) with ML-KEM-768 key exchange, BLAKE3 frame integrity, and XChaCha20-Poly1305 payload encryption.

**2.1 seconds from cold boot to post-quantum encrypted session on a $5 chip.**

## Benchmarks

All numbers measured on ESP32-S3-WROOM-1 @ 240MHz, 50 iterations, reporting mean and standard deviation.

| Operation | Mean | StdDev |
|---|---|---|
| ML-KEM-768 keygen | 9,052us | 164us |
| ML-KEM-768 encapsulate | 10,070us | 11us |
| ML-KEM-768 decapsulate | 12,197us | 11us |
| XChaCha20-Poly1305 encrypt | 243us | 46us |
| BLAKE3 (1KB) | 255us | 102us |
| BLAKE3 KDF | 49us | 60us |
| AWP frame encode + decode | 363us | 95us |

| Metric | Value |
|---|---|
| Cold boot to PQC session | 2.1 seconds |
| Firmware size | 833KB |
| Free heap (runtime) | 157KB |

## Security

| Layer | Algorithm | Implementation |
|---|---|---|
| Key exchange | ML-KEM-768 | [mlkem-native](https://github.com/pq-code-package/mlkem-native) v1.0.0 (formally verified) |
| Frame integrity | BLAKE3-256 | [Official C](https://github.com/BLAKE3-team/BLAKE3) (portable) |
| Payload encryption | XChaCha20-Poly1305 | mbedTLS |
| Key derivation | BLAKE3 | — |
| Nonce persistence | ESP32 NVS flash | — |

### Hardening

- **No plaintext fallback.** Handshake aborts without post-quantum key exchange.
- **Constant-time cryptographic operations.** Timing side-channels mitigated.
- **Nonce reuse prevention.** Counter persisted to flash, survives unclean power loss.
- **Mutual authentication.** Session key possession verified at establishment.
- **Boot self-test.** 14 crypto tests on every boot. Firmware halts on failure.

### Verification

- 14 self-tests on every boot
- Cross-platform interop proven byte-for-byte
- 410,000 fuzz iterations (AddressSanitizer + UBSan), zero crashes
- 100,000 single-bit-flip tests, 100% detected

## Quick Start

Requirements: ESP32-S3 board, USB cable, [ESP-IDF v5.4](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32s3/get-started/index.html).

```bash
git clone https://github.com/aethyrai/esp32-awp-edge
cd esp32-awp-edge

# Configure WiFi and upstream node
idf.py menuconfig
# → AWP Edge Node Configuration
#   WiFi SSID / Password
#   Upstream host IP and port

# Build and flash
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

Serial output on boot:

```
Crypto Self-Test Suite
  [1] BLAKE3: empty input...                           PASS
  [2] BLAKE3: 251 sequential bytes...                  PASS
  [3] BLAKE3: derive_key (KDF mode)...                 PASS
  [4] XChaCha20-Poly1305: encrypt/decrypt round-trip...PASS
  [5] XChaCha20-Poly1305: tamper detection...          PASS
  [6] XChaCha20-Poly1305: wrong key rejection...       PASS
  [7] XChaCha20-Poly1305: nonce uniqueness...          PASS
  [8] ML-KEM-768: keygen + encap/decap round-trip...   PASS
  [9] ML-KEM-768: wrong secret key rejection...        PASS
  [10] INTEROP: BLAKE3 KDF matches Python...           PASS
  [11] INTEROP: decrypt Python-produced ciphertext...  PASS
  [12] Replay window: accept / duplicate / too-old...  PASS
  [13] AWP: frame encode/decode round-trip...          PASS
  [14] AWP: BLAKE3 checksum tamper detection...        PASS
  ALL 14 TESTS PASSED (261ms)

ML-KEM-768 keypair ready
WiFi connected
TCP connected to upstream
PQC session established
```

## Project Structure

```
esp32-awp-edge/
├── main/
│   ├── awp_protocol.{c,h}     Frame encoder/decoder
│   ├── awp_stream.{c,h}       TCP stream reassembly
│   ├── awp_edge_node.{c,h}    Edge node lifecycle
│   ├── awp_crypto.{c,h}       Post-quantum crypto
│   ├── sensor_hub.{c,h}       Pluggable sensor drivers
│   ├── crypto_test.{c,h}      Boot self-tests
│   └── main.c                 Entry point
├── components/
│   ├── blake3/                 BLAKE3 official C (portable, no SIMD)
│   └── mlkem768/               mlkem-native v1.0.0 (formally verified ML-KEM-768)
├── test/
│   └── fuzz_awp.c             Frame decoder fuzzer
├── jetson/
│   ├── setup-mesh-ap.sh       Create dedicated WiFi AP on Jetson
│   ├── stop-mesh-ap.sh        Stop mesh AP
│   └── aios-node.service      systemd service for AWP node
├── demo/
│   └── run_demo.py            Scripted 2-minute demo
└── sdkconfig.defaults         Build defaults
```

## Stack Usage

Minimum safe task stack for ML-KEM operations: **24KB**.

## Fuzz Testing

Compile and run on the host (not ESP32):

```bash
cc -fsanitize=address,undefined -g -O1 \
   -Itest -Imain -Icomponents/blake3 \
   test/fuzz_awp.c main/awp_protocol.c main/awp_stream.c \
   components/blake3/blake3.c components/blake3/blake3_portable.c \
   components/blake3/blake3_dispatch.c \
   -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 \
   -DBLAKE3_NO_AVX512 -DBLAKE3_NO_NEON \
   -o test/fuzz_awp -Wno-format -lm && ./test/fuzz_awp
```

## Hardware

Tested on:
- **ESP32-S3-WROOM-1** (QFN56, rev v0.2) — WiFi, BLE, 8MB PSRAM
- **Jetson Orin Nano Super** — upstream NODE, dedicated 2.4GHz WiFi AP

Should work on any ESP32-S3 board with ESP-IDF v5.4.

## What This Connects To

This firmware is the edge node for the [Aethyr](https://aethyr.cloud) distributed agent mesh. The ESP32 handles the sensory edge: sensors, actuators, and encrypted transport. The intelligence lives upstream.

## License

Apache 2.0
