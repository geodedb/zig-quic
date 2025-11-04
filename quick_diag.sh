#!/usr/bin/env bash
#
# Quick diagnostic: Run existing test-go-client against test_quic_server
# and analyze the 1-RTT communication failure
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================"
echo "Quick 1-RTT Diagnostic"
echo "========================================"
echo ""

cleanup() {
    pkill -f "test_quic_server|test-go-client" || true
}
trap cleanup EXIT

# Check for existing binaries/scripts
if [ ! -f "test-go-client.go" ]; then
    echo -e "${RED}✗ test-go-client.go not found${NC}"
    exit 1
fi

# Find or build server
SERVER_BIN=$(find .zig-cache -name "test_quic_server" -type f 2>/dev/null | head -1)
if [ -z "$SERVER_BIN" ]; then
    echo -e "${YELLOW}Server binary not found, trying to build...${NC}"
    # Use zig build if available
    if zig build 2>&1 | grep -q "error"; then
        echo -e "${RED}✗ Build failed${NC}"
        exit 1
    fi
    SERVER_BIN=$(find .zig-cache -name "test_quic_server" -type f 2>/dev/null | head -1)
fi

if [ -z "$SERVER_BIN" ] || [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}✗ Cannot find server binary${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Server: $SERVER_BIN${NC}"

# Start server with logging
echo -e "${BLUE}Starting server...${NC}"
$SERVER_BIN --port 4433 > /tmp/quick_server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Server died${NC}"
    cat /tmp/quick_server.log
    exit 1
fi

echo -e "${GREEN}✓ Server running (PID $SERVER_PID)${NC}"
echo ""

# Run Go client
echo -e "${BLUE}Running Go client...${NC}"
timeout 10 go run -mod=mod test-go-client.go > /tmp/quick_client.log 2>&1 || true
echo ""

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Analyze
echo "========================================"
echo "ANALYSIS"
echo "========================================"
echo ""

echo -e "${YELLOW}[Client Side]${NC}"
if grep -q "Success!" /tmp/quick_client.log; then
    echo -e "${GREEN}✓✓✓ CLIENT GOT RESPONSE - TEST PASSED!${NC}"
    grep "Received:" /tmp/quick_client.log
    exit 0
else
    echo -e "${RED}✗ Client did not receive response${NC}"
    if grep -qi "timeout\|deadline" /tmp/quick_client.log; then
        echo "  Reason: Timeout"
    fi
    echo "  Last 5 lines of client log:"
    tail -5 /tmp/quick_client.log
fi

echo ""
echo -e "${YELLOW}[Server Side - RX]${NC}"

# Check if server received the STREAM frame
if grep -qi "stream0 opened rx\|received.*bytes from stream" /tmp/quick_server.log; then
    echo -e "${GREEN}✓ Server RECEIVED client data${NC}"
    grep -i "stream0\|received.*bytes" /tmp/quick_server.log | head -3
else
    echo -e "${RED}✗ Server did NOT receive client STREAM frame${NC}"
    echo "  Checking for decrypt activity..."
    if grep -qi "decodeShortProtected\|decoded 1-RTT" /tmp/quick_server.log; then
        echo -e "${YELLOW}  → Found decrypt attempts${NC}"
        grep -i "decodeShort\|decoded 1-RTT" /tmp/quick_server.log | head -5
    else
        echo -e "${RED}  → No 1-RTT decrypt attempts found${NC}"
    fi
fi

echo ""
echo -e "${YELLOW}[Server Side - TX]${NC}"

# Check if server tried to send response
if grep -qi "writeStream\|sending.*frames\|encodeShort" /tmp/quick_server.log; then
    echo -e "${GREEN}✓ Server ATTEMPTED to send response${NC}"
    grep -i "writeStream\|sending.*frames" /tmp/quick_server.log | head -5
else
    echo -e "${RED}✗ Server did NOT attempt to send response${NC}"
fi

echo ""
echo -e "${YELLOW}[Packet Number Tracking]${NC}"
if grep -qi "pn=\|packet_number\|truncated PN" /tmp/quick_server.log; then
    echo "Server PN activity:"
    grep -i "pn=\|packet_number\|truncated PN" /tmp/quick_server.log | head -10
fi

echo ""
echo -e "${YELLOW}[Errors/Warnings]${NC}"
if grep -qi "error\|failed\|invalid\|warning" /tmp/quick_server.log; then
    echo "Found issues:"
    grep -i "error\|failed\|invalid\|warning" /tmp/quick_server.log | head -10
else
    echo "No explicit errors found"
fi

echo ""
echo "========================================"
echo "VERDICT"
echo "========================================"

RX_OK=$(grep -qi "stream0 opened rx" /tmp/quick_server.log && echo "1" || echo "0")
TX_OK=$(grep -qi "writeStream\|sending.*frames" /tmp/quick_server.log && echo "1" || echo "0")
CLIENT_OK=$(grep -q "Success!" /tmp/quick_client.log && echo "1" || echo "0")

if [ "$CLIENT_OK" = "1" ]; then
    echo -e "${GREEN}✓✓✓ FULL SUCCESS${NC}"
elif [ "$RX_OK" = "1" ] && [ "$TX_OK" = "1" ]; then
    echo -e "${YELLOW}Server RX/TX both active but client got nothing${NC}"
    echo -e "${RED}→ Likely: Server sends wrong DCID or uses wrong keys${NC}"
    echo "   Check: shortHeaderDcid(), tx_key_phase, pn_app_tx"
elif [ "$RX_OK" = "1" ]; then
    echo -e "${YELLOW}Server receives but doesn't send${NC}"
    echo -e "${RED}→ Likely: writeStream not called or keys not ready${NC}"
else
    echo -e "${RED}Server not receiving client STREAM frames${NC}"
    echo -e "${RED}→ Likely: 1-RTT decrypt fails or STREAM not parsed${NC}"
    echo "   Check: decodeShortProtected, largest_pn, app_rx_keys"
fi

echo ""
echo "Logs:"
echo "  Server: /tmp/quick_server.log"
echo "  Client: /tmp/quick_client.log"
echo ""
echo "Next: cat /tmp/quick_server.log | grep -E '(STREAM|decode|write)'"
echo ""

exit 1
