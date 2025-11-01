#!/bin/bash

set -e

# This script adds debug logging directly to the vendor/quic-go files
# After running this, you can use generate-patches.sh to create patch files

VENDOR_DIR="vendor/quic-go"

echo "Adding debug logging to quic-go files..."
echo

# Function to add logging after a specific line
add_after_line() {
    local file="$1"
    local search_pattern="$2"
    local insert_text="$3"
    local temp_file="${file}.tmp"

    awk -v pattern="$search_pattern" -v text="$insert_text" '
    {
        print
        if ($0 ~ pattern && !inserted) {
            print text
            inserted=1
        }
    }
    ' "$file" > "$temp_file"

    mv "$temp_file" "$file"
}

# 1. connection.go - Add debug logging
echo "Modifying connection.go..."

# Note: Due to the complexity of the file, I'll use sed for targeted insertions
# Add logging to receivedFirstPacket
sed -i '/c\.receivedFirstPacket = true/a\
\t\tfmt.Printf("[CONN] First packet received from server, switching to new conn ID: %s\\n", hdr.SrcConnectionID)' \
    "$VENDOR_DIR/connection.go"

# Add logging to handleHandshakeConfirmed
sed -i '/c\.handshakeConfirmed = true/a\
\tfmt.Printf("[CONN] Handshake confirmed, dropping handshake packet space\\n")' \
    "$VENDOR_DIR/connection.go"

echo "✓ connection.go modified"
echo

# 2. crypto_stream_manager.go - Add debug logging
echo "Modifying crypto_stream_manager.go..."

# Add logging at the start of HandleCryptoFrame
sed -i '/func (m \*cryptoStreamManager) HandleCryptoFrame/,/switch encLevel/ {
    /switch encLevel/ i\
\tfmt.Printf("[CRYPTO_MGR] Handling CRYPTO frame: enc_level=%s, offset=%d, length=%d\\n", encLevel, frame.Offset, len(frame.Data))
}' "$VENDOR_DIR/crypto_stream_manager.go"

# Add logging to each case in HandleCryptoFrame
sed -i '/case protocol\.EncryptionInitial:/a\
\t\tfmt.Printf("[CRYPTO_MGR] Processing Initial CRYPTO frame\\n")' \
    "$VENDOR_DIR/crypto_stream_manager.go"

sed -i '/case protocol\.EncryptionHandshake:/a\
\t\tfmt.Printf("[CRYPTO_MGR] Processing Handshake CRYPTO frame\\n")' \
    "$VENDOR_DIR/crypto_stream_manager.go"

# Add logging to Drop function
sed -i '/func (m \*cryptoStreamManager) Drop/,/switch encLevel/ {
    /switch encLevel/ i\
\tfmt.Printf("[CRYPTO_MGR] Dropping encryption level: %s\\n", encLevel)
}' "$VENDOR_DIR/crypto_stream_manager.go"

echo "✓ crypto_stream_manager.go modified"
echo

# 3. packet_unpacker.go - Add debug logging
echo "Modifying packet_unpacker.go..."

# Add logging at start of UnpackLongHeader
sed -i '/func (u \*packetUnpacker) UnpackLongHeader/,/var encLevel/ {
    /var encLevel/ a\
\tfmt.Printf("[UNPACKER] Unpacking long header packet: type=%s, version=%s, dest_conn_id=%s, src_conn_id=%s, data_len=%d\\n", hdr.Type, hdr.Version, hdr.DestConnectionID, hdr.SrcConnectionID, len(data))
}' "$VENDOR_DIR/packet_unpacker.go"

# Add logging for Initial packet case
sed -i '/case protocol\.PacketTypeInitial:/a\
\t\tfmt.Printf("[UNPACKER] Getting Initial opener\\n")' \
    "$VENDOR_DIR/packet_unpacker.go"

# Add logging for Handshake packet case
sed -i '/case protocol\.PacketTypeHandshake:/a\
\t\tfmt.Printf("[UNPACKER] Getting Handshake opener\\n")' \
    "$VENDOR_DIR/packet_unpacker.go"

echo "✓ packet_unpacker.go modified"
echo

# 4. packet_packer.go - Add debug logging
echo "Modifying packet_packer.go..."

# Add logging to packCoalescedPacket
sed -i '/func (p \*packetPacker) packCoalescedPacket/,/{/ {
    /{/ a\
\tfmt.Printf("[PACKER] Packing coalesced packet: only_ack=%t, max_size=%d\\n", onlyAck, maxPacketSize)
}' "$VENDOR_DIR/packet_packer.go"

echo "✓ packet_packer.go modified"
echo

# 5. transport.go - Add debug logging
echo "Modifying transport.go..."

# Add logging to init function
sed -i '/func (t \*Transport) init/,/if t\.Conn == nil/ {
    /if t\.Conn == nil/ i\
\tfmt.Printf("[TRANSPORT] Initializing transport on %s\\n", t.Conn.LocalAddr())
}' "$VENDOR_DIR/transport.go"

echo "✓ transport.go modified"
echo

echo "Debug logging added successfully!"
echo "You can now:"
echo "1. Test the modified library"
echo "2. Run ./generate-patches.sh to create patch files"
echo "3. Use ./apply-patches.sh to apply patches to fresh vendor copies"
