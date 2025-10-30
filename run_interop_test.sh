#!/bin/bash

# Comprehensive QUIC Interoperability Test Script
# Tests Zig QUIC Server against quic-go client

set -e

# Configuration
SERVER_BIN="./zig-out/bin/quic-server"
CLIENT_GO="./test-go-client.go"
SERVER_ADDR="127.0.0.1:4433"
TEST_DIR="/home/benji/src/spyder/quic"
LOG_DIR="$TEST_DIR/test-logs"
PCAP_FILE="$LOG_DIR/quic-test.pcap"
SSLKEYLOG_FILE="$LOG_DIR/sslkeylog.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}QUIC Interoperability Test${NC}"
echo -e "${BLUE}Zig Server <-> quic-go Client${NC}"
echo -e "${BLUE}========================================${NC}"

# Create log directory
mkdir -p "$LOG_DIR"
cd "$TEST_DIR"

# Clean up previous logs
rm -f "$LOG_DIR"/*.log "$PCAP_FILE" "$SSLKEYLOG_FILE"

echo -e "\n${YELLOW}[1/6] Setting up environment...${NC}"
echo "Log directory: $LOG_DIR"
echo "PCAP file: $PCAP_FILE"
echo "SSL keylog: $SSLKEYLOG_FILE"

# Check if server binary exists
if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}Error: Server binary not found at $SERVER_BIN${NC}"
    exit 1
fi

# Check if Go client exists
if [ ! -f "$CLIENT_GO" ]; then
    echo -e "${RED}Error: Go client not found at $CLIENT_GO${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[2/6] Starting packet capture...${NC}"
# Start tcpdump in background
sudo tcpdump -i lo -w "$PCAP_FILE" -s 65535 "udp port 4433" > "$LOG_DIR/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
echo "tcpdump PID: $TCPDUMP_PID"
sleep 1

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"

    # Kill server if running
    if [ ! -z "$SERVER_PID" ]; then
        echo "Stopping server (PID: $SERVER_PID)"
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi

    # Stop tcpdump
    if [ ! -z "$TCPDUMP_PID" ]; then
        echo "Stopping tcpdump (PID: $TCPDUMP_PID)"
        sudo kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

echo -e "\n${YELLOW}[3/6] Starting Zig QUIC server...${NC}"
"$SERVER_BIN" --insecure > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
echo "Waiting for server to start..."
sleep 2

# Check if server is still running
if ! ps -p $SERVER_PID > /dev/null; then
    echo -e "${RED}Error: Server failed to start!${NC}"
    echo "Server log:"
    cat "$LOG_DIR/server.log"
    exit 1
fi

echo -e "${GREEN}Server started successfully${NC}"

echo -e "\n${YELLOW}[4/6] Building and running quic-go client...${NC}"
echo "Setting QUIC_GO_LOG_LEVEL=debug"
echo "Setting SSLKEYLOGFILE=$SSLKEYLOG_FILE"

# Run the Go client with detailed logging
QUIC_GO_LOG_LEVEL=debug SSLKEYLOGFILE="$SSLKEYLOG_FILE" go run "$CLIENT_GO" > "$LOG_DIR/client.log" 2>&1
CLIENT_EXIT_CODE=$?

echo -e "\n${YELLOW}[5/6] Waiting for packet capture to flush...${NC}"
sleep 2

echo -e "\n${YELLOW}[6/6] Test execution complete${NC}"
echo "Client exit code: $CLIENT_EXIT_CODE"

# Display results
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}TEST RESULTS${NC}"
echo -e "${BLUE}========================================${NC}"

if [ $CLIENT_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}SUCCESS: Client connected successfully!${NC}"
else
    echo -e "${RED}FAILURE: Client connection failed (exit code: $CLIENT_EXIT_CODE)${NC}"
fi

echo -e "\n${YELLOW}Server log (last 50 lines):${NC}"
tail -50 "$LOG_DIR/server.log"

echo -e "\n${YELLOW}Client log:${NC}"
cat "$LOG_DIR/client.log"

# Check if SSLKEYLOG was generated
if [ -f "$SSLKEYLOG_FILE" ]; then
    echo -e "\n${GREEN}SSL keylog file generated successfully${NC}"
    echo "Lines in keylog: $(wc -l < $SSLKEYLOG_FILE)"
else
    echo -e "\n${YELLOW}Warning: SSL keylog file not generated${NC}"
fi

# Check packet capture
if [ -f "$PCAP_FILE" ]; then
    PCAP_SIZE=$(stat -c%s "$PCAP_FILE")
    echo -e "\n${GREEN}Packet capture completed${NC}"
    echo "PCAP file size: $PCAP_SIZE bytes"

    # Try to get basic packet info
    echo -e "\n${YELLOW}Packet capture summary:${NC}"
    sudo tcpdump -r "$PCAP_FILE" -n 2>/dev/null | head -50 || echo "Could not read pcap details"
else
    echo -e "\n${RED}Error: Packet capture file not found${NC}"
fi

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}Log files available in: $LOG_DIR${NC}"
echo -e "${BLUE}========================================${NC}"
ls -lh "$LOG_DIR"

exit $CLIENT_EXIT_CODE
