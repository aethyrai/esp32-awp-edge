#!/usr/bin/env python3
"""
AWP Demo Server -- Minimal AethyrWire Protocol upstream node.

Accepts post-quantum encrypted connections from ESP32 edge nodes,
responds to heartbeats, and echoes messages. Works standalone --
no AIOS installation required.

Usage:
    python awp_demo_server.py                    # Listen on port 9000
    python awp_demo_server.py --port 9001        # Custom port
    python awp_demo_server.py --psk deadbeef...  # Pre-shared key (hex)

Requirements:
    pip install -r requirements.txt

Post-quantum crypto (optional):
    pip install psam-crypto     # Enables ML-KEM-768 key exchange

Without psam-crypto the server still speaks AWP, but handshakes
complete without post-quantum key exchange and payloads travel
unencrypted. Useful for protocol debugging.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

# ---------------------------------------------------------------------------
# Optional post-quantum crypto
# ---------------------------------------------------------------------------
try:
    from psam_crypto import (
        generate_kem_keypair,
        encrypt as pqc_encrypt,
        decrypt as pqc_decrypt,
        blake3_hash,
        derive_key as pqc_derive_key,
        EncapsulationKey,
        SymmetricKey,
        EncryptedData,
    )
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

# ---------------------------------------------------------------------------
# BLAKE3 -- try C binding, fall back to hashlib BLAKE2b
# ---------------------------------------------------------------------------
try:
    import blake3 as _blake3

    def _checksum(data: bytes) -> bytes:
        return _blake3.blake3(data).digest()

    HASH_NAME = "BLAKE3"
except ImportError:
    if PQC_AVAILABLE:
        def _checksum(data: bytes) -> bytes:
            return blake3_hash(data)
        HASH_NAME = "BLAKE3 (psam)"
    else:
        def _checksum(data: bytes) -> bytes:
            return hashlib.blake2b(data, digest_size=32).digest()
        HASH_NAME = "BLAKE2b (fallback)"

# ---------------------------------------------------------------------------
# AWP constants (must match esp32-awp-edge/main/awp_protocol.h)
# ---------------------------------------------------------------------------
AWP_MAGIC = 0xAE370000
AWP_VERSION = 0x0001
MAX_FRAME_SIZE = 16 * 1024 * 1024

# Header field sizes
NODE_ID_SIZE = 32
HDC_SIG_SIZE = 512
MSG_TYPE_SIZE = 2
TENANT_HV_SIZE = 64
SESSION_ID_SIZE = 16
CHECKSUM_SIZE = 32

# Fixed header: magic(4) + version(2) + flags(2) + length(4) +
#               node_id(32) + hdc_sig(512) + msg_type(2) +
#               tenant_hv(64) + session_id(16) = 638 bytes
HEADER_SIZE = 4 + 2 + 2 + 4 + NODE_ID_SIZE + HDC_SIG_SIZE + \
              MSG_TYPE_SIZE + TENANT_HV_SIZE + SESSION_ID_SIZE

# Frame flags
FLAG_ENCRYPTED = 0x0001
FLAG_COMPRESSED = 0x0002
FLAG_PRIORITY = 0x0004
FLAG_REQUIRES_ACK = 0x0008
FLAG_IS_RESPONSE = 0x0010
FLAG_MULTIPART = 0x0020
FLAG_HDC_ENCLOSED = 0x0040


class MsgType(IntEnum):
    """AWP message types (subset needed for demo)."""
    PING = 0x01
    PONG = 0x02
    DISCOVER_REQUEST = 0x03
    DISCOVER_RESPONSE = 0x04
    ERROR = 0xF0
    HELLO = 0xF2
    HELLO_ACK = 0xF3


# ---------------------------------------------------------------------------
# AWP frame
# ---------------------------------------------------------------------------
@dataclass
class AWPFrame:
    msg_type: int
    node_id: str = ""
    hdc_signature: bytes = field(default_factory=lambda: b"\x00" * HDC_SIG_SIZE)
    payload: bytes = b""
    flags: int = 0
    tenant_hv: bytes = field(default_factory=lambda: b"\x00" * TENANT_HV_SIZE)
    session_id: bytes = field(default_factory=lambda: b"\x00" * SESSION_ID_SIZE)

    def encode(self) -> bytes:
        """Encode frame to wire bytes."""
        node_id_bytes = self.node_id.encode().ljust(NODE_ID_SIZE, b"\x00")[:NODE_ID_SIZE]
        hdc_wire = b"\x00" * HDC_SIG_SIZE  # Always zeroed on wire
        tenant = (self.tenant_hv or b"\x00" * TENANT_HV_SIZE)[:TENANT_HV_SIZE].ljust(TENANT_HV_SIZE, b"\x00")
        session = (self.session_id or b"\x00" * SESSION_ID_SIZE)[:SESSION_ID_SIZE].ljust(SESSION_ID_SIZE, b"\x00")
        payload = self.payload or b""

        total_len = HEADER_SIZE + len(payload) + CHECKSUM_SIZE

        header = struct.pack(">IHHI",
                             AWP_MAGIC, AWP_VERSION, self.flags, total_len)
        body = (header + node_id_bytes + hdc_wire +
                struct.pack(">H", self.msg_type) +
                tenant + session + payload)
        checksum = _checksum(body)
        return body + checksum

    @classmethod
    def decode(cls, data: bytes) -> "AWPFrame":
        """Decode wire bytes to frame. Raises ValueError on invalid data."""
        min_size = HEADER_SIZE + CHECKSUM_SIZE
        if len(data) < min_size:
            raise ValueError(f"Frame too short: {len(data)} < {min_size}")

        magic, version, flags, length = struct.unpack_from(">IHHI", data, 0)
        if magic != AWP_MAGIC:
            raise ValueError(f"Bad magic: 0x{magic:08X}")
        if version != AWP_VERSION:
            raise ValueError(f"Bad version: 0x{version:04X}")

        # Verify checksum
        frame_data = data[:-CHECKSUM_SIZE]
        expected = data[-CHECKSUM_SIZE:]
        actual = _checksum(frame_data)
        if actual != expected:
            raise ValueError("Checksum mismatch")

        off = 12
        node_id = data[off:off + NODE_ID_SIZE].rstrip(b"\x00").decode(errors="replace")
        off += NODE_ID_SIZE
        hdc_sig = data[off:off + HDC_SIG_SIZE]
        off += HDC_SIG_SIZE
        msg_type = struct.unpack_from(">H", data, off)[0]
        off += MSG_TYPE_SIZE
        tenant_hv = data[off:off + TENANT_HV_SIZE]
        off += TENANT_HV_SIZE
        session_id = data[off:off + SESSION_ID_SIZE]
        off += SESSION_ID_SIZE

        payload = data[off:-CHECKSUM_SIZE] if off < len(data) - CHECKSUM_SIZE else b""

        return cls(
            msg_type=msg_type,
            node_id=node_id,
            hdc_signature=hdc_sig,
            payload=payload,
            flags=flags,
            tenant_hv=tenant_hv,
            session_id=session_id,
        )


# ---------------------------------------------------------------------------
# Stream reader -- reassemble frames from TCP byte stream
# ---------------------------------------------------------------------------
class AWPStreamReader:
    """Buffers TCP data and yields complete AWP frames."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[AWPFrame]:
        self._buf.extend(data)
        frames: list[AWPFrame] = []
        while len(self._buf) >= HEADER_SIZE + CHECKSUM_SIZE:
            # Peek at length field (offset 8, uint32 big-endian)
            length = struct.unpack_from(">I", self._buf, 8)[0]
            if length > MAX_FRAME_SIZE:
                # Corrupt -- discard buffer
                self._buf.clear()
                break
            if len(self._buf) < length:
                break  # Need more data
            frame_bytes = bytes(self._buf[:length])
            del self._buf[:length]
            try:
                frames.append(AWPFrame.decode(frame_bytes))
            except ValueError as e:
                log.warning("Frame decode error: %s", e)
        return frames


# ---------------------------------------------------------------------------
# Node identity (simplified -- no numpy/HDC dependency)
# ---------------------------------------------------------------------------
def generate_node_id() -> str:
    return secrets.token_hex(16)


def generate_hdc_signature(node_id: str) -> bytes:
    """Deterministic 512-byte pseudo-HDC signature from node ID."""
    seed = hashlib.sha256(node_id.encode()).digest()
    sig = bytearray()
    i = 0
    while len(sig) < HDC_SIG_SIZE:
        block = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        sig.extend(block)
        i += 1
    return bytes(sig[:HDC_SIG_SIZE])


# ---------------------------------------------------------------------------
# Per-peer session state
# ---------------------------------------------------------------------------
@dataclass
class PeerSession:
    addr: str
    node_id: str = ""
    session_key: Optional[bytes] = None
    kem_dk: object = None  # DecapsulationKey (psam_crypto)
    kem_ek_hex: str = ""   # Our encapsulation key (hex)
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    frames_rx: int = 0
    frames_tx: int = 0


# ---------------------------------------------------------------------------
# Demo server
# ---------------------------------------------------------------------------
class AWPDemoServer:
    """Minimal AWP upstream node for ESP32 edge devices."""

    def __init__(self, port: int = 9000, psk: bytes = b""):
        self.port = port
        self.psk = psk
        self.node_id = generate_node_id()
        self.hdc_sig = generate_hdc_signature(self.node_id)
        self.peers: dict[str, PeerSession] = {}

    async def start(self) -> None:
        server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)

        print()
        print("=" * 60)
        print("  AWP Demo Server")
        print("=" * 60)
        print(f"  Node ID:   {self.node_id}")
        print(f"  Listening: {addrs}")
        print(f"  PQC:       {'ML-KEM-768 (psam-crypto)' if PQC_AVAILABLE else 'DISABLED (install psam-crypto)'}")
        print(f"  Integrity: {HASH_NAME}")
        print(f"  PSK:       {'configured' if self.psk else 'none'}")
        print("=" * 60)
        print()

        async with server:
            await server.serve_forever()

    # -- connection handler ------------------------------------------------

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername")
        addr_str = f"{addr[0]}:{addr[1]}" if addr else "unknown"
        log.info("[%s] Connection opened", addr_str)

        peer = PeerSession(addr=addr_str)
        self.peers[addr_str] = peer

        try:
            # Wait for HELLO (30s timeout)
            if not await self._do_handshake(reader, writer, peer):
                return

            # Main message loop
            stream = AWPStreamReader()
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(65536), timeout=300)
                except asyncio.TimeoutError:
                    log.info("[%s] Timeout -- sending keepalive", addr_str)
                    await self._send_ping(writer, peer)
                    continue

                if not data:
                    break  # Connection closed

                for frame in stream.feed(data):
                    peer.frames_rx += 1
                    peer.last_activity = time.time()
                    await self._handle_frame(frame, writer, peer)

        except (ConnectionResetError, BrokenPipeError):
            log.info("[%s] Connection reset", addr_str)
        except Exception as e:
            log.error("[%s] Error: %s", addr_str, e)
        finally:
            writer.close()
            self.peers.pop(addr_str, None)
            log.info("[%s] Disconnected (rx=%d tx=%d)", addr_str,
                     peer.frames_rx, peer.frames_tx)

    # -- handshake ---------------------------------------------------------

    async def _do_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: PeerSession,
    ) -> bool:
        """Perform HELLO / HELLO_ACK handshake. Returns True on success."""
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=30)
        except asyncio.TimeoutError:
            log.warning("[%s] Handshake timeout", peer.addr)
            return False

        if not data:
            return False

        stream = AWPStreamReader()
        frames = stream.feed(data)
        if not frames:
            log.warning("[%s] No valid frame in handshake", peer.addr)
            return False

        hello = frames[0]
        if hello.msg_type != MsgType.HELLO:
            log.warning("[%s] Expected HELLO, got 0x%02X", peer.addr, hello.msg_type)
            return False

        peer.node_id = hello.node_id
        log.info("[%s] HELLO from %s", peer.addr, hello.node_id[:16])

        # Parse HELLO payload
        hello_data: dict = {}
        if hello.payload:
            try:
                hello_data = json.loads(hello.payload)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # Build HELLO_ACK payload
        ack_data: dict = {
            "node_id": self.node_id,
            "tier": "NODE",
            "capabilities": ["relay"],
            "version": "demo-1.0",
        }

        # ML-KEM handshake (responder side)
        if PQC_AVAILABLE:
            peer_ek_hex = hello_data.get("kem_encapsulation_key", "")
            if peer_ek_hex:
                try:
                    # Generate our own keypair for this peer
                    dk, ek = generate_kem_keypair()
                    peer.kem_dk = dk

                    # Encapsulate against peer's public key
                    peer_ek = EncapsulationKey.from_bytes(bytes.fromhex(peer_ek_hex))
                    result = peer_ek.encapsulate()

                    # Derive session key
                    shared = result.shared_secret
                    session_key = pqc_derive_key(
                        "awp-session-key", shared + self.psk)
                    peer.session_key = session_key

                    ack_data["kem_encapsulation_key"] = ek.to_bytes().hex()
                    ack_data["kem_ciphertext"] = result.ciphertext.hex()

                    log.info("[%s] ML-KEM-768 session key established",
                             peer.addr)
                except Exception as e:
                    log.warning("[%s] KEM handshake failed: %s", peer.addr, e)

        # Send HELLO_ACK
        ack_frame = AWPFrame(
            msg_type=MsgType.HELLO_ACK,
            node_id=self.node_id,
            hdc_signature=self.hdc_sig,
            payload=json.dumps(ack_data).encode(),
            session_id=hello.session_id,
        )
        writer.write(ack_frame.encode())
        await writer.drain()
        peer.frames_tx += 1

        pqc_status = "PQC" if peer.session_key else "cleartext"
        log.info("[%s] Handshake complete (%s)", peer.addr, pqc_status)
        return True

    # -- message handler ---------------------------------------------------

    async def _handle_frame(
        self,
        frame: AWPFrame,
        writer: asyncio.StreamWriter,
        peer: PeerSession,
    ) -> None:
        """Process one incoming frame."""
        payload = frame.payload

        # Decrypt if encrypted and we have a session key
        if frame.flags & FLAG_ENCRYPTED and peer.session_key and PQC_AVAILABLE:
            try:
                key = SymmetricKey.from_bytes(peer.session_key)
                enc = EncryptedData.from_bytes(payload)
                plaintext = pqc_decrypt(key, enc, b"awp")
                # Strip HDC signature prefix if enclosed
                if frame.flags & FLAG_HDC_ENCLOSED and len(plaintext) > HDC_SIG_SIZE:
                    plaintext = plaintext[HDC_SIG_SIZE:]
                payload = plaintext
            except Exception as e:
                log.warning("[%s] Decrypt failed: %s", peer.addr, e)
                return

        msg_name = _msg_name(frame.msg_type)

        if frame.msg_type == MsgType.PING:
            log.debug("[%s] PING -> PONG", peer.addr)
            pong = AWPFrame(
                msg_type=MsgType.PONG,
                node_id=self.node_id,
                hdc_signature=self.hdc_sig,
                session_id=frame.session_id,
                flags=FLAG_IS_RESPONSE,
            )
            writer.write(pong.encode())
            await writer.drain()
            peer.frames_tx += 1

        elif frame.msg_type == MsgType.PONG:
            log.debug("[%s] PONG received", peer.addr)

        elif frame.msg_type == MsgType.DISCOVER_REQUEST:
            log.info("[%s] Discovery request", peer.addr)
            resp = AWPFrame(
                msg_type=MsgType.DISCOVER_RESPONSE,
                node_id=self.node_id,
                hdc_signature=self.hdc_sig,
                payload=json.dumps({
                    "node_id": self.node_id,
                    "tier": "NODE",
                    "peers": len(self.peers),
                }).encode(),
                session_id=frame.session_id,
                flags=FLAG_IS_RESPONSE,
            )
            writer.write(resp.encode())
            await writer.drain()
            peer.frames_tx += 1

        else:
            # Echo -- log and reflect the payload back
            preview = ""
            if payload:
                try:
                    preview = payload.decode(errors="replace")[:120]
                except Exception:
                    preview = f"({len(payload)} bytes)"
            log.info("[%s] %s: %s", peer.addr, msg_name, preview or "(empty)")

            echo = AWPFrame(
                msg_type=frame.msg_type,
                node_id=self.node_id,
                hdc_signature=self.hdc_sig,
                payload=payload,
                session_id=frame.session_id,
                flags=FLAG_IS_RESPONSE,
            )
            writer.write(echo.encode())
            await writer.drain()
            peer.frames_tx += 1

    # -- keepalive ---------------------------------------------------------

    async def _send_ping(
        self, writer: asyncio.StreamWriter, peer: PeerSession,
    ) -> None:
        ping = AWPFrame(
            msg_type=MsgType.PING,
            node_id=self.node_id,
            hdc_signature=self.hdc_sig,
        )
        writer.write(ping.encode())
        await writer.drain()
        peer.frames_tx += 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _msg_name(msg_type: int) -> str:
    try:
        return MsgType(msg_type).name
    except ValueError:
        return f"0x{msg_type:02X}"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt,
                        stream=sys.stdout)


log = logging.getLogger("awp-demo")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWP Demo Server -- minimal upstream node for ESP32 edge devices")
    parser.add_argument("--port", type=int, default=9000,
                        help="Listen port (default: 9000)")
    parser.add_argument("--psk", type=str, default="",
                        help="Pre-shared key (hex string)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Debug-level logging")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    psk = bytes.fromhex(args.psk) if args.psk else b""
    server = AWPDemoServer(port=args.port, psk=psk)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutdown.")


if __name__ == "__main__":
    main()
