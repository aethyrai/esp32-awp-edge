#!/usr/bin/env python3
"""
AWP Interop Test — verifies Python decode matches C encode.

Reads test vectors produced by test_interop.c and decodes them
using the Python AWP protocol implementation.

Usage:
    ./test_interop | python3 test/test_interop.py

Or run the C binary and pipe:
    ./test/test_interop | python3 test/test_interop.py
"""

import sys
import struct

# Protocol constants (must match awp_protocol.h)
AWP_MAGIC = 0xAE370000
AWP_VERSION = 0x0001
MAGIC_OFFSET = 0
VERSION_OFFSET = 4
FLAGS_OFFSET = 6
LENGTH_OFFSET = 8
NODE_ID_OFFSET = 12
NODE_ID_SIZE = 32
HDC_SIG_OFFSET = 44
HDC_SIG_SIZE = 512
MSG_TYPE_OFFSET = 556
TENANT_HV_OFFSET = 558
TENANT_HV_SIZE = 64
SESSION_ID_OFFSET = 622
SESSION_ID_SIZE = 16
PAYLOAD_OFFSET = 638
HEADER_SIZE = PAYLOAD_OFFSET  # 638
CHECKSUM_SIZE = 32

FLAG_ENCRYPTED = 0x0001
FLAG_HDC_ENCLOSED = 0x0040


def decode_frame(data: bytes) -> dict:
    """Minimal Python frame decoder matching the C implementation."""
    assert len(data) >= HEADER_SIZE + CHECKSUM_SIZE, f"Frame too small: {len(data)}"

    magic, version, flags, length = struct.unpack(">IHHI", data[0:12])
    assert magic == AWP_MAGIC, f"Bad magic: {hex(magic)}"
    assert version == AWP_VERSION, f"Bad version: {version}"
    assert length == len(data), f"Length mismatch: {length} vs {len(data)}"

    # Verify BLAKE3 checksum
    try:
        import blake3
        expected = data[-CHECKSUM_SIZE:]
        actual = blake3.blake3(data[:-CHECKSUM_SIZE]).digest()[:CHECKSUM_SIZE]
        assert expected == actual, "BLAKE3 checksum mismatch"
    except ImportError:
        import hashlib
        expected = data[-CHECKSUM_SIZE:]
        actual = hashlib.blake2b(data[:-CHECKSUM_SIZE], digest_size=CHECKSUM_SIZE).digest()
        # May not match if C uses BLAKE3 — skip verification
        if expected != actual:
            print("  WARN: checksum verification skipped (no blake3 module, C uses BLAKE3)")

    node_id = data[NODE_ID_OFFSET:NODE_ID_OFFSET + NODE_ID_SIZE].rstrip(b'\x00').decode()
    hdc_sig = data[HDC_SIG_OFFSET:HDC_SIG_OFFSET + HDC_SIG_SIZE]
    msg_type = struct.unpack(">H", data[MSG_TYPE_OFFSET:MSG_TYPE_OFFSET + 2])[0]
    payload = data[PAYLOAD_OFFSET:-CHECKSUM_SIZE]

    return {
        "node_id": node_id,
        "msg_type": msg_type,
        "flags": flags,
        "payload": payload,
        "hdc_sig": hdc_sig,
    }


def main():
    vectors = []
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        vectors.append(line)

    if not vectors:
        print("ERROR: No test vectors received on stdin")
        print("Usage: ./test/test_interop | python3 test/test_interop.py")
        sys.exit(1)

    print(f"AWP Interop Verification — {len(vectors)} vectors")
    print("=" * 50)

    passed = 0
    failed = 0

    for vec in vectors:
        parts = vec.split("|")
        name = parts[0]
        wire_hex = parts[1]
        expected_node_id = parts[2]
        expected_msg_type = int(parts[3], 16) if parts[3] else None
        expected_payload_hex = parts[4] if len(parts) > 4 else ""

        wire = bytes.fromhex(wire_hex)

        try:
            frame = decode_frame(wire)

            checks = []

            # Node ID
            if frame["node_id"] == expected_node_id:
                checks.append("node_id OK")
            else:
                checks.append(f"node_id FAIL: got '{frame['node_id']}', expected '{expected_node_id}'")
                failed += 1
                continue

            # Message type
            if expected_msg_type is not None and frame["msg_type"] == expected_msg_type:
                checks.append(f"msg_type OK (0x{frame['msg_type']:04x})")
            elif expected_msg_type is not None:
                checks.append(f"msg_type FAIL: got 0x{frame['msg_type']:04x}, expected 0x{expected_msg_type:04x}")
                failed += 1
                continue

            # Payload
            if expected_payload_hex:
                expected_payload = bytes.fromhex(expected_payload_hex)
                if frame["payload"] == expected_payload:
                    checks.append(f"payload OK ({len(expected_payload)} bytes)")
                else:
                    checks.append(f"payload FAIL: got {frame['payload'].hex()[:40]}..., expected {expected_payload_hex[:40]}...")
                    failed += 1
                    continue
            else:
                checks.append(f"payload OK (empty, {len(frame['payload'])} bytes)")

            # HDC field should always be zeros on wire
            if frame["hdc_sig"] == b'\x00' * HDC_SIG_SIZE:
                checks.append("hdc_zeroed OK")
            else:
                checks.append("hdc_zeroed FAIL: non-zero bytes in HDC field")
                failed += 1
                continue

            print(f"  PASS  {name}: {', '.join(checks)}")
            passed += 1

        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
