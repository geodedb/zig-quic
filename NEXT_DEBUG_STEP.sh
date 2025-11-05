#!/bin/bash
# Next debugging step: Capture and analyze packet data
# This will help us compare actual wire bytes with what we're extracting

set -e

echo "=== QUIC 1-RTT Decryption Debug - Packet Capture ==="
echo ""
echo "This script will:"
echo "1. Start packet capture on localhost"
echo "2. Run the Go client test"
echo "3. Save packet capture for analysis"
echo "4. Show you how to inspect it"
echo ""

# Check if running as root for tcpdump
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script needs to run as root for tcpdump"
    echo "Please run: sudo $0"
    exit 1
fi

# Create capture directory
mkdir -p debug_captures
cd debug_captures

CAPTURE_FILE="quic_1rtt_$(date +%Y%m%d_%H%M%S).pcap"

echo "Starting packet capture..."
echo "Capture file: $CAPTURE_FILE"
echo ""

# Start tcpdump in background
tcpdump -i lo -w "$CAPTURE_FILE" 'port 4433' 2>/dev/null &
TCPDUMP_PID=$!

# Wait for tcpdump to start
sleep 2

echo "Running Go client test..."
cd ..
timeout 15 make e2e-test-go 2>&1 | tee "debug_captures/test_output.log" || true

# Stop tcpdump
echo ""
echo "Stopping packet capture..."
sleep 1
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo ""
echo "=== Capture Complete ==="
echo ""
echo "Files created:"
echo "  - debug_captures/$CAPTURE_FILE (packet capture)"
echo "  - debug_captures/test_output.log (test output)"
echo ""
echo "Next steps:"
echo ""
echo "1. View with Wireshark:"
echo "   wireshark debug_captures/$CAPTURE_FILE"
echo ""
echo "2. Or use tshark to extract details:"
echo "   tshark -r debug_captures/$CAPTURE_FILE -V"
echo ""
echo "3. Filter for Application (1-RTT) packets:"
echo "   tshark -r debug_captures/$CAPTURE_FILE -Y 'quic.header_form == 0'"
echo ""
echo "4. To see the encrypted payload:"
echo "   tshark -r debug_captures/$CAPTURE_FILE -V | grep -A 20 'Payload'"
echo ""
echo "5. Compare packet bytes with our debug output:"
echo "   grep '=== RECEIVED 1-RTT PACKET ===' debug_captures/test_output.log -A 50"
echo ""
echo "=== What to Look For ==="
echo ""
echo "In Wireshark, for the first 1-RTT packet FROM CLIENT:"
echo "  1. Packet Number: Should be close to what we extracted (715254683)"
echo "  2. Protected Payload offset: Where does ciphertext actually start?"
echo "  3. Tag: Last 16 bytes - does it match our extraction?"
echo "  4. If Wireshark can decrypt (with keys):"
echo "     - Compare decrypted payload"
echo "     - Check if our nonce/AAD matches"
echo ""
echo "To provide TLS keys to Wireshark:"
echo "  1. Extract from server log: grep 'CLIENT_TRAFFIC_SECRET' debug_captures/test_output.log"
echo "  2. Save to file: ~/.wireshark/tls_keys.txt"
echo "  3. Format: CLIENT_HANDSHAKE_TRAFFIC_SECRET <32-byte-hex> <64-byte-hex>"
echo ""
echo "=== Analysis Checklist ==="
echo ""
echo "[ ] Compare encrypted packet bytes with our debug 'Packet first 32 bytes'"
echo "[ ] Verify DCID extraction (should be bytes 1-8 after header)"
echo "[ ] Verify PN extraction (should be 4 bytes after DCID)"
echo "[ ] Verify ciphertext starts at byte: 1 + dcid_len + pn_len = 1 + 8 + 4 = 13"
echo "[ ] Verify tag is last 16 bytes of packet"
echo "[ ] Check if there's any padding we're missing"
echo ""
echo "Done!"
