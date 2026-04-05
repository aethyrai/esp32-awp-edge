# AWP Demo Server

Minimal Python upstream node for testing ESP32 edge devices. Accepts AethyrWire Protocol connections, performs ML-KEM-768 post-quantum handshakes, and responds to heartbeats.

## Quick Start

```bash
# Install (optional deps for better performance)
pip install blake3

# Run
python awp_demo_server.py

# Flash the ESP32, point it at this server's IP
# The edge node will connect, handshake, and start sending heartbeats
```

Output:
```
============================================================
  AWP Demo Server
============================================================
  Node ID:   a1b2c3d4e5f6...
  Listening: ('0.0.0.0', 9000)
  PQC:       ML-KEM-768 (psam-crypto)
  Integrity: BLAKE3
  PSK:       none
============================================================

12:34:56  [192.168.0.50:4321] Connection opened
12:34:56  [192.168.0.50:4321] HELLO from esp32-edge-01
12:34:56  [192.168.0.50:4321] ML-KEM-768 session key established
12:34:56  [192.168.0.50:4321] Handshake complete (PQC)
12:34:57  [192.168.0.50:4321] PING -> PONG
```

## Post-Quantum Crypto

For full ML-KEM-768 key exchange, install `psam-crypto`:

```bash
pip install psam-crypto
```

Without it, the server still speaks AWP correctly but handshakes complete without post-quantum key exchange. Payloads travel unencrypted. Useful for protocol debugging.

## Options

```
--port PORT    Listen port (default: 9000)
--psk HEX      Pre-shared key for KDF binding (hex string)
-v             Debug-level logging (shows PING/PONG)
```

## What It Does

1. Listens for TCP connections on port 9000
2. Reads an AWP HELLO frame from the edge node
3. Performs ML-KEM-768 key exchange (if psam-crypto is installed)
4. Sends HELLO_ACK with session parameters
5. Responds to PING with PONG (keepalive)
6. Responds to DISCOVER_REQUEST with node info
7. Echoes any other message type back to the sender

## Protocol

The demo server implements the [AethyrWire Protocol](https://aethyr.cloud) (AWP) -- a binary-framed TCP protocol with a 638-byte fixed header, BLAKE3 integrity checksums, and optional XChaCha20-Poly1305 payload encryption.

See the main [README](../README.md) for protocol details and benchmarks.

## ESP32 Configuration

In `idf.py menuconfig`, set the upstream node address to this server:

```
AWP Edge Node Configuration --->
    Upstream node host: <this machine's IP>
    Upstream node port: 9000
```

## Requirements

- Python 3.8+
- No required dependencies (stdlib only)
- Optional: `blake3` (faster checksums)
- Optional: `psam-crypto` (ML-KEM-768 post-quantum key exchange)
