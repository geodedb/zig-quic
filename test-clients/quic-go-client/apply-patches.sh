#!/bin/bash

set -e

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor/quic-go"
SOURCE_DIR="/home/benji/src/spyder/quic/forks/quic-go"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}QUIC-Go Debug Logging Patcher${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -r, --restore    Restore vendor directory from source (removes debug logging)"
    echo "  -h, --help       Display this help message"
    echo ""
    echo "Without options, adds debug logging to the vendor directory."
    exit 0
}

# Function to restore vendor directory from source
restore_vendor() {
    echo -e "${YELLOW}Restoring vendor directory from source...${NC}"

    if [ ! -d "$SOURCE_DIR" ]; then
        echo -e "${RED}ERROR: Source directory not found: $SOURCE_DIR${NC}"
        exit 1
    fi

    # Remove existing vendor/quic-go directory
    if [ -d "$VENDOR_DIR" ]; then
        echo -e "${YELLOW}Removing existing vendor/quic-go...${NC}"
        rm -rf "$VENDOR_DIR"
    fi

    # Create vendor directory if it doesn't exist
    mkdir -p "$(dirname "$VENDOR_DIR")"

    # Copy source to vendor
    echo -e "${BLUE}Copying $SOURCE_DIR to $VENDOR_DIR...${NC}"
    cp -r "$SOURCE_DIR" "$VENDOR_DIR"

    # Clean up any git metadata
    if [ -d "$VENDOR_DIR/.git" ]; then
        rm -rf "$VENDOR_DIR/.git"
    fi

    echo -e "${GREEN}✓ Vendor directory restored successfully${NC}"
    echo
}

# Function to check if vendor directory exists
check_vendor() {
    if [ ! -d "$VENDOR_DIR" ]; then
        echo -e "${RED}ERROR: Vendor directory not found: $VENDOR_DIR${NC}"
        echo -e "${YELLOW}Run with -r/--restore to create it from source${NC}"
        exit 1
    fi
}

# Function to check if debug logging already applied
check_if_patched() {
    if grep -q "\[CONN\] First packet received" "$VENDOR_DIR/connection.go" 2>/dev/null; then
        return 0  # Already patched
    fi
    return 1  # Not patched
}

# Function to add debug logging
add_debug_logging() {
    echo -e "${BLUE}Adding debug logging to vendor/quic-go...${NC}"
    echo

    # Check if already patched
    if check_if_patched; then
        echo -e "${YELLOW}Debug logging already applied!${NC}"
        echo -e "${YELLOW}Use -r/--restore to remove it first if you want to re-apply${NC}"
        exit 0
    fi

    local MODIFIED=0

    # 1. connection.go
    echo -e "${YELLOW}Adding debug logging to connection.go...${NC}"

    # Add logging after receivedFirstPacket = true
    if grep -q "c.receivedFirstPacket = true" "$VENDOR_DIR/connection.go"; then
        sed -i '/c\.receivedFirstPacket = true/a\
\t\tfmt.Printf("[CONN] First packet received from server, switching to new conn ID: %s\\n", hdr.SrcConnectionID)' \
            "$VENDOR_DIR/connection.go"
        MODIFIED=$((MODIFIED + 1))
    fi

    # Add logging after handshakeConfirmed = true
    if grep -q "c.handshakeConfirmed = true" "$VENDOR_DIR/connection.go"; then
        sed -i '/c\.handshakeConfirmed = true/a\
\tfmt.Printf("[CONN] Handshake confirmed, dropping handshake packet space\\n")' \
            "$VENDOR_DIR/connection.go"
        MODIFIED=$((MODIFIED + 1))
    fi

    # Add logging to handleStreamFrame
    if grep -q "func (c \*Conn) handleStreamFrame(frame \*wire.StreamFrame) error {" "$VENDOR_DIR/connection.go"; then
        sed -i '/func (c \*Conn) handleStreamFrame(frame \*wire\.StreamFrame) error {/a\
\tfmt.Printf("[CONN] Received STREAM frame: stream_id=%d, offset=%d, length=%d, fin=%t\\n", frame.StreamID, frame.Offset, len(frame.Data), frame.Fin)' \
            "$VENDOR_DIR/connection.go"
        MODIFIED=$((MODIFIED + 1))
    fi

    echo -e "${GREEN}  ✓ connection.go modified (${MODIFIED} changes)${NC}"
    MODIFIED=0
    echo

    # 2. crypto_stream_manager.go
    echo -e "${YELLOW}Adding debug logging to crypto_stream_manager.go...${NC}"

    # Add logging at start of HandleCryptoFrame
    if grep -q "func (m \*cryptoStreamManager) HandleCryptoFrame" "$VENDOR_DIR/crypto_stream_manager.go"; then
        sed -i '/func (m \*cryptoStreamManager) HandleCryptoFrame(frame \*wire\.CryptoFrame, encLevel protocol\.EncryptionLevel) error {/,/switch encLevel {/ {
            /switch encLevel {/ i\
\tfmt.Printf("[CRYPTO_MGR] Handling CRYPTO frame: enc_level=%s, offset=%d, length=%d\\n", encLevel, frame.Offset, len(frame.Data))
        }' "$VENDOR_DIR/crypto_stream_manager.go"
        MODIFIED=$((MODIFIED + 1))
    fi

    # Add logging to each encryption level case
    sed -i '/case protocol\.EncryptionInitial:/a\
\t\tfmt.Printf("[CRYPTO_MGR] Processing Initial CRYPTO frame\\n")' \
        "$VENDOR_DIR/crypto_stream_manager.go" 2>/dev/null && MODIFIED=$((MODIFIED + 1)) || true

    sed -i '/case protocol\.EncryptionHandshake:/a\
\t\tfmt.Printf("[CRYPTO_MGR] Processing Handshake CRYPTO frame\\n")' \
        "$VENDOR_DIR/crypto_stream_manager.go" 2>/dev/null && MODIFIED=$((MODIFIED + 1)) || true

    sed -i '/case protocol\.Encryption1RTT:/a\
\t\tfmt.Printf("[CRYPTO_MGR] Processing 1-RTT CRYPTO frame\\n")' \
        "$VENDOR_DIR/crypto_stream_manager.go" 2>/dev/null && MODIFIED=$((MODIFIED + 1)) || true

    echo -e "${GREEN}  ✓ crypto_stream_manager.go modified (${MODIFIED} changes)${NC}"
    MODIFIED=0
    echo

    # 3. packet_unpacker.go
    echo -e "${YELLOW}Adding debug logging to packet_unpacker.go...${NC}"

    # Add logging to UnpackLongHeader
    sed -i '/func (u \*packetUnpacker) UnpackLongHeader(hdr \*wire\.Header, data \[\]byte) (\*unpackedPacket, error) {/,/var encLevel protocol\.EncryptionLevel/ {
        /var encLevel protocol\.EncryptionLevel/ a\
\tfmt.Printf("[UNPACKER] Unpacking long header packet: type=%s, version=%s, dest_conn_id=%s, src_conn_id=%s, data_len=%d\\n", hdr.Type, hdr.Version, hdr.DestConnectionID, hdr.SrcConnectionID, len(data))
    }' "$VENDOR_DIR/packet_unpacker.go" && MODIFIED=$((MODIFIED + 1)) || true

    # Add logging for Initial packet type
    sed -i '/case protocol\.PacketTypeInitial:/,/encLevel = protocol\.EncryptionInitial/ {
        /encLevel = protocol\.EncryptionInitial/ a\
\t\tfmt.Printf("[UNPACKER] Processing Initial packet\\n")
    }' "$VENDOR_DIR/packet_unpacker.go" && MODIFIED=$((MODIFIED + 1)) || true

    # Add logging for Handshake packet type
    sed -i '/case protocol\.PacketTypeHandshake:/,/encLevel = protocol\.EncryptionHandshake/ {
        /encLevel = protocol\.EncryptionHandshake/ a\
\t\tfmt.Printf("[UNPACKER] Processing Handshake packet\\n")
    }' "$VENDOR_DIR/packet_unpacker.go" && MODIFIED=$((MODIFIED + 1)) || true

    # Add logging to UnpackShortHeader
    sed -i '/func (u \*packetUnpacker) UnpackShortHeader(rcvTime monotime\.Time, data \[\]byte)/a\
\tfmt.Printf("[UNPACKER] Unpacking short header packet: data_len=%d\\n", len(data))' \
        "$VENDOR_DIR/packet_unpacker.go" && MODIFIED=$((MODIFIED + 1)) || true

    echo -e "${GREEN}  ✓ packet_unpacker.go modified (${MODIFIED} changes)${NC}"
    MODIFIED=0
    echo

    # 4. packet_packer.go
    echo -e "${YELLOW}Adding debug logging to packet_packer.go...${NC}"

    # Add logging to packCoalescedPacket
    sed -i '/func (p \*packetPacker) packCoalescedPacket(onlyAck bool, maxPacketSize protocol\.ByteCount, now monotime\.Time, v protocol\.Version)/,/var ($/ {
        /var ($/ a\
\tfmt.Printf("[PACKER] Packing coalesced packet: only_ack=%t, max_size=%d\\n", onlyAck, maxPacketSize)
    }' "$VENDOR_DIR/packet_packer.go" && MODIFIED=$((MODIFIED + 1)) || true

    # Add logging to sealPacket
    sed -i '/func (p \*packetPacker) sealPacket(/a\
\tfmt.Printf("[PACKER] Sealing packet: pn=%d, key_phase=%d\\n", pn, kp)' \
        "$VENDOR_DIR/packet_packer.go" && MODIFIED=$((MODIFIED + 1)) || true

    echo -e "${GREEN}  ✓ packet_packer.go modified (${MODIFIED} changes)${NC}"
    MODIFIED=0
    echo

    # 5. transport.go
    echo -e "${YELLOW}Adding debug logging to transport.go...${NC}"

    # Add logging to init function
    sed -i '/func (t \*Transport) init(allowActiveListening bool, tlsConf \*tls\.Config, quicConf \*Config)/,/if t\.Conn == nil {/ {
        /if t\.Conn == nil {/ i\
\tfmt.Printf("[TRANSPORT] Initializing transport on %s\\n", t.Conn.LocalAddr())
    }' "$VENDOR_DIR/transport.go" && MODIFIED=$((MODIFIED + 1)) || true

    # Add logging to handlePacket
    sed -i '/func (t \*Transport) handlePacket(p receivedPacket) {/a\
\tfmt.Printf("[TRANSPORT] Handling packet: size=%d, from=%s\\n", len(p.data), p.remoteAddr)' \
        "$VENDOR_DIR/transport.go" && MODIFIED=$((MODIFIED + 1)) || true

    echo -e "${GREEN}  ✓ transport.go modified (${MODIFIED} changes)${NC}"
    echo

    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Debug logging successfully added!${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Parse command line arguments
case "${1:-}" in
    -r|--restore)
        restore_vendor
        ;;
    -h|--help)
        usage
        ;;
    "")
        check_vendor
        add_debug_logging
        ;;
    *)
        echo -e "${RED}ERROR: Unknown option: $1${NC}"
        echo
        usage
        ;;
esac

echo -e "${GREEN}Done!${NC}"
