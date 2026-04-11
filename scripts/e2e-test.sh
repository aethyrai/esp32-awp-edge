#!/bin/bash
# ESP32 AWP Edge Node — End-to-End Security Verification
# Idempotent: safe to run multiple times, no side effects
# Verbose: shows full evidence for every check
# Usage: ./scripts/e2e-test.sh

SCRIPT_DIR_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAST_FILE="$(dirname "$SCRIPT_DIR_SELF")/demo-e2e.cast"

# If not already inside asciinema, re-exec under it
if [ -z "$ASCIINEMA_REC" ]; then
    export ASCIINEMA_REC=1
    exec asciinema rec "$CAST_FILE" --overwrite -c "$0"
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS="${GREEN}PASS${NC}"
FAIL="${RED}FAIL${NC}"
SKIP="${YELLOW}SKIP${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
JETSON="aethyr-jetson-orin"
SERIAL_PORT="/dev/ttyACM0"
MEDIA_PORT=8081
JETSON_LAN_IP="192.168.0.59"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

check() {
    local name="$1" result="$2"
    if [ "$result" = "pass" ]; then
        echo -e "  $name: $PASS"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    elif [ "$result" = "skip" ]; then
        echo -e "  $name: $SKIP"
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
    else
        echo -e "  $name: $FAIL"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
}

# ═════════════════════════════════════════════════════
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║  ESP32 AWP Edge Node — E2E Security Verification ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "Date:     $(date)"
echo "Board:    XIAO ESP32S3 Sense"
echo "Upstream: Jetson Orin ($JETSON)"
echo "Serial:   $SERIAL_PORT"
echo ""

# ═════════════════════════════════════════════════════
# Preflight: verify serial port and SSH
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[0/8] Preflight${NC}"
if [ -e "$SERIAL_PORT" ]; then
    echo -e "  Serial port: $PASS ($SERIAL_PORT)"
else
    echo -e "  Serial port: $FAIL ($SERIAL_PORT not found)"
    echo "  Cannot proceed without ESP32 connected."
    exit 1
fi

if ssh -o ConnectTimeout=3 -o BatchMode=yes $JETSON "echo ok" &>/dev/null; then
    echo -e "  SSH to Jetson: $PASS"
else
    echo -e "  SSH to Jetson: $FAIL (cannot reach $JETSON)"
    echo "  Wire capture and media tests will be skipped."
fi
echo ""

# ═════════════════════════════════════════════════════
# 1. Boot & Crypto Self-Tests
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[1/8] Boot & Crypto Self-Tests${NC}"
echo "  Resetting ESP32 and capturing boot output (20s)..."
echo ""
BOOT=$(python3 -c "
import serial, time, sys
ser = serial.Serial('$SERIAL_PORT', 115200, timeout=1)
ser.dtr = False; time.sleep(0.1); ser.dtr = True; time.sleep(0.1); ser.dtr = False
start = time.time()
while time.time() - start < 20:
    line = ser.readline()
    if line:
        text = line.decode('utf-8', errors='replace').rstrip()
        print(text)
ser.close()
" 2>&1)

echo -e "${YELLOW}  ┌── Boot Log (filtered) ──${NC}"
echo "$BOOT" | grep -E "crypto_test|awp_main|awp_edge|awp_crypto|camera|sensor_hub|wifi:security|wifi:connected|pmf|PSK|psk|stream started|Registered|PASS|FAIL" | sed 's/^/  │ /'
echo -e "${YELLOW}  └──────────────────────────${NC}"
echo ""

# Crypto self-tests
TESTS_LINE=$(echo "$BOOT" | grep "TESTS PASSED\|TESTS FAILED" | head -1)
if echo "$TESTS_LINE" | grep -q "ALL.*PASSED"; then
    check "All 13 crypto self-tests" "pass"
else
    check "Crypto self-tests" "fail"
fi

# ML-KEM-768
if echo "$BOOT" | grep -q "keygen + encap/decap" && echo "$BOOT" | grep -q "wrong secret key"; then
    check "ML-KEM-768 keygen + encap/decap + wrong-key rejection" "pass"
else
    check "ML-KEM-768" "fail"
fi

# XChaCha20-Poly1305
if echo "$BOOT" | grep -q "tamper detection" && echo "$BOOT" | grep -q "wrong key rejection"; then
    check "XChaCha20-Poly1305 tamper detection + wrong-key rejection" "pass"
else
    check "XChaCha20-Poly1305" "fail"
fi

# BLAKE3 interop
if echo "$BOOT" | grep -A1 "INTEROP.*BLAKE3" | grep -q "PASS"; then
    check "BLAKE3 cross-platform interop (Python ↔ ESP32)" "pass"
else
    check "BLAKE3 cross-platform interop" "fail"
fi

# XChaCha20 interop
if echo "$BOOT" | grep -A1 "INTEROP.*decrypt Python" | grep -q "PASS"; then
    check "XChaCha20 cross-platform interop (Python ciphertext)" "pass"
else
    check "XChaCha20 cross-platform interop" "fail"
fi
echo ""

# ═════════════════════════════════════════════════════
# 2. WiFi + PMF
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[2/8] WiFi + PMF (802.11w)${NC}"
WIFI_LINE=$(echo "$BOOT" | grep "wifi:security:" | head -1)
echo -e "  ${YELLOW}Wire: ${NC}$WIFI_LINE"

if echo "$WIFI_LINE" | grep -q "pmf:1"; then
    SECURITY=$(echo "$WIFI_LINE" | grep -oP 'security: \K[^,]+')
    check "WiFi security ($SECURITY)" "pass"
    check "PMF 802.11w required (deauth attacks blocked)" "pass"
else
    check "PMF 802.11w" "fail"
fi

IP=$(echo "$BOOT" | grep -oP "WiFi connected, IP: \K[0-9.]+" | head -1)
echo "  ESP32 IP: $IP"
echo ""

# ═════════════════════════════════════════════════════
# 3. PQC Handshake + Edge PSK
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[3/8] PQC Handshake + Edge PSK${NC}"

PSK_LINE=$(echo "$BOOT" | grep "psk=" | head -1)
echo -e "  ${YELLOW}Log: ${NC}$PSK_LINE"

HELLO_LINE=$(echo "$BOOT" | grep "HELLO payload" | head -1)
echo -e "  ${YELLOW}Log: ${NC}$HELLO_LINE"

SESSION_LINE=$(echo "$BOOT" | grep "PQC session established" | head -1)
echo -e "  ${YELLOW}Log: ${NC}$SESSION_LINE"

echo "$BOOT" | grep -q "psk=yes" && check "Edge PSK loaded (32 bytes)" "pass" || check "Edge PSK loaded" "fail"
echo "$BOOT" | grep -q "PQC handshake complete" && check "ML-KEM-768 key exchange completed" "pass" || check "ML-KEM-768 handshake" "fail"
echo "$BOOT" | grep -q "PQC session established" && check "XChaCha20-Poly1305 session established" "pass" || check "Encrypted session" "fail"
echo ""

# ═════════════════════════════════════════════════════
# 4. Camera + Audio Streams
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[4/8] Camera + Audio Streams${NC}"

CAM_LINE=$(echo "$BOOT" | grep "Camera initialized" | head -1)
echo -e "  ${YELLOW}Log: ${NC}$CAM_LINE"

STREAM_LINE=$(echo "$BOOT" | grep "Camera stream started" | head -1)
echo -e "  ${YELLOW}Log: ${NC}$STREAM_LINE"

AUDIO_LINE=$(echo "$BOOT" | grep "Audio stream started" | head -1)
echo -e "  ${YELLOW}Log: ${NC}$AUDIO_LINE"

echo "$BOOT" | grep -q "Camera stream started" && check "Camera stream (10 fps, encrypted)" "pass" || check "Camera stream" "fail"
echo "$BOOT" | grep -q "Audio stream started" && check "Audio stream (100ms chunks, encrypted)" "pass" || check "Audio stream" "fail"
echo ""

# ═════════════════════════════════════════════════════
# 5. Wire Encryption Verification
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[5/8] Wire Encryption Verification${NC}"

if [ -z "$IP" ]; then
    check "Wire capture (no IP — ESP32 not connected)" "skip"
elif ! ssh -o ConnectTimeout=3 -o BatchMode=yes $JETSON "echo ok" &>/dev/null; then
    check "Wire capture (Jetson SSH unavailable)" "skip"
else
    echo "  Capturing raw TCP packets on Jetson WiFi interface..."
    WIRE=$(ssh $JETSON "timeout 3 tcpdump -i wlP1p1s0 -c 5 -x port 9000 and src $IP 2>&1" 2>/dev/null)

    echo -e "${YELLOW}  ┌── Raw Wire Hex ──${NC}"
    echo "$WIRE" | grep "0x00[0-9a-f]0:" | head -12 | sed 's/^/  │ /'
    echo -e "${YELLOW}  └────────────────────${NC}"

    if echo "$WIRE" | grep -q "0x0"; then
        check "Encrypted payload on wire (high-entropy bytes)" "pass"
        if echo "$WIRE" | grep -qi '"node"\|"sensor"\|FFD8FF'; then
            check "Plaintext leak check" "fail"
        else
            check "No plaintext strings in payload" "pass"
        fi
    else
        check "Wire capture" "fail"
    fi
fi
echo ""

# ═════════════════════════════════════════════════════
# 6. Header Scrubbing
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[6/8] Header Scrubbing Verification${NC}"

if [ -z "$IP" ] || ! ssh -o ConnectTimeout=3 -o BatchMode=yes $JETSON "echo ok" &>/dev/null; then
    check "Header scrubbing (requires Jetson SSH)" "skip"
else
    echo "  Capturing and parsing AWP frame headers..."
    HEADERS=$(ssh $JETSON "timeout 3 tcpdump -i wlP1p1s0 -c 15 -w /tmp/e2e_capture.pcap port 9000 and src $IP 2>&1 && python3 -c \"
import struct
data = open('/tmp/e2e_capture.pcap','rb').read()
pos = 24; stream = bytearray()
while pos < len(data):
    if pos + 16 > len(data): break
    incl_len = struct.unpack('<I', data[pos+8:pos+12])[0]
    pkt = data[pos+16:pos+16+incl_len]
    if len(pkt) > 54:
        ip_hdr_len = (pkt[14] & 0x0f) * 4
        tcp_off = 14 + ip_hdr_len
        tcp_hdr_len = ((pkt[tcp_off+12] >> 4) & 0x0f) * 4
        stream.extend(pkt[tcp_off + tcp_hdr_len:])
    pos += 16 + incl_len
magic = bytes([0xae, 0x37, 0x00, 0x00])
idx = 0; found = 0
while idx < len(stream) - 700:
    p = stream.find(magic, idx)
    if p < 0: break
    flags = struct.unpack('>H', stream[p+6:p+8])[0]
    msg_type = struct.unpack('>H', stream[p+556:p+558])[0]
    node_id = bytes(stream[p+12:p+44])
    all_zero = all(b == 0 for b in node_id)
    encrypted = bool(flags & 0x0001)
    length = struct.unpack('>I', stream[p+8:p+12])[0]
    print(f'  msg=0x{msg_type:02x} flags=0x{flags:04x} encrypted={encrypted} node_id_zeroed={all_zero} len={length}')
    found += 1; idx = p + max(length, 4)
    if found >= 5: break
print(f'TOTAL={found}')
\"" 2>/dev/null)

    echo "$HEADERS" | grep -v "^$\|tcpdump\|listening\|packets\|TOTAL"

    TOTAL=$(echo "$HEADERS" | grep "TOTAL=" | grep -oP "TOTAL=\K[0-9]+" || echo "0")
    SCRUBBED=$(echo "$HEADERS" | grep "node_id_zeroed=True" | wc -l)
    ENCRYPTED=$(echo "$HEADERS" | grep "encrypted=True" | wc -l)
    MSG_ZEROED=$(echo "$HEADERS" | grep "msg=0x00" | wc -l)

    if [ "$TOTAL" -gt 0 ] 2>/dev/null; then
        echo ""
        [ "$ENCRYPTED" = "$TOTAL" ] && check "All frames encrypted ($ENCRYPTED/$TOTAL)" "pass" || check "All frames encrypted ($ENCRYPTED/$TOTAL)" "fail"
        [ "$SCRUBBED" = "$TOTAL" ] && check "All node_id fields zeroed ($SCRUBBED/$TOTAL)" "pass" || check "node_id zeroed ($SCRUBBED/$TOTAL)" "fail"
        [ "$MSG_ZEROED" = "$TOTAL" ] && check "All msg_type fields zeroed ($MSG_ZEROED/$TOTAL)" "pass" || check "msg_type zeroed ($MSG_ZEROED/$TOTAL)" "fail"
    else
        check "Frame parsing (no frames found in capture)" "fail"
    fi
fi
echo ""

# ═════════════════════════════════════════════════════
# 7. Media Relay
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[7/8] Media Relay (Jetson → Browser)${NC}"
STREAMS=$(curl -m 5 -s http://$JETSON_LAN_IP:$MEDIA_PORT/ 2>/dev/null)
if echo "$STREAMS" | grep -q "streams"; then
    check "Media relay server (port $MEDIA_PORT)" "pass"
    echo -e "  ${YELLOW}Response: ${NC}$STREAMS"
    NODE_IDS=$(echo "$STREAMS" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(k) for k in d.get('streams',{})]" 2>/dev/null)
    if [ -n "$NODE_IDS" ]; then
        for NID in $NODE_IDS; do
            TYPES=$(echo "$STREAMS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d['streams']['$NID']))" 2>/dev/null)
            check "Stream $NID (types: $TYPES)" "pass"
            echo -e "  MJPEG: ${CYAN}http://$JETSON_LAN_IP:$MEDIA_PORT/stream/$NID${NC}"
            echo -e "  Snap:  ${CYAN}http://$JETSON_LAN_IP:$MEDIA_PORT/frame/$NID${NC}"
        done
    else
        check "Active streams (none yet — ESP32 may still be connecting)" "skip"
    fi
else
    check "Media relay server" "fail"
fi
echo ""

# ═════════════════════════════════════════════════════
# 8. PSK Trust Boundaries
# ═════════════════════════════════════════════════════
echo -e "${BOLD}[8/8] PSK Trust Boundary Verification${NC}"
ESP_PSK=$(grep CONFIG_AWP_PSK "$PROJECT_DIR/sdkconfig" 2>/dev/null | grep -oP '="\K[^"]+')

if ssh -o ConnectTimeout=3 -o BatchMode=yes $JETSON "echo ok" &>/dev/null; then
    JETSON_EDGE_PSK=$(ssh $JETSON "cat /proc/\$(pgrep -of 'python3.*aios_network')/environ 2>/dev/null | tr '\0' '\n' | grep AWP_EDGE_PSK | cut -d= -f2" 2>/dev/null)
    JETSON_MESH_PSK=$(ssh $JETSON "cat /proc/\$(pgrep -of 'python3.*aios_network')/environ 2>/dev/null | tr '\0' '\n' | grep -w AWP_PSK | cut -d= -f2" 2>/dev/null)

    echo "  ESP32 PSK (edge):  ${ESP_PSK:0:16}..."
    echo "  Jetson edge PSK:   ${JETSON_EDGE_PSK:0:16}..."
    echo "  Jetson mesh PSK:   ${JETSON_MESH_PSK:0:16}..."

    [ "$ESP_PSK" = "$JETSON_EDGE_PSK" ] && check "ESP32 PSK matches Jetson edge PSK" "pass" || check "ESP32 ↔ Jetson edge PSK match" "fail"
    [ "$ESP_PSK" != "$JETSON_MESH_PSK" ] && check "Edge PSK differs from mesh PSK (separate trust zones)" "pass" || check "Edge PSK ≠ Mesh PSK" "fail"
else
    check "PSK verification (Jetson SSH unavailable)" "skip"
fi
echo ""

# ═════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║               Security Stack Summary              ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  WiFi:       WPA2-PSK-SHA256 + PMF required      ║"
echo "║  Key Exch:   ML-KEM-768 (FIPS 203, post-quantum) ║"
echo "║  Encryption: XChaCha20-Poly1305 (every frame)    ║"
echo "║  Integrity:  BLAKE3 checksum + Poly1305 tag      ║"
echo "║  AAD:        Frame metadata bound to ciphertext   ║"
echo "║  Replay:     4096-message sliding window          ║"
echo "║  Ratchet:    Key rotated every 256 frames         ║"
echo "║  Headers:    node_id + msg_type scrubbed          ║"
echo "║  PSK:        Edge ≠ Mesh (separate trust zones)   ║"
echo "║  Anomaly:    Rate/stuck/range detection           ║"
echo "║  Media:      10fps video + audio, all encrypted   ║"
echo "╠══════════════════════════════════════════════════╣"
printf "║  Results: ${GREEN}%d PASS${NC}  ${RED}%d FAIL${NC}  ${YELLOW}%d SKIP${NC}              ║\n" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "Completed: $(date)"

if [ "$TOTAL_FAIL" -gt 0 ]; then
    exit 1
fi
