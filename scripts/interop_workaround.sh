#!/usr/bin/env bash
set -euo pipefail

# QUIC Interoperability Test Runner - Docker Workaround Version
# Works around Docker Compose network management issues

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
cd "$ROOT"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== QUIC Interoperability Test Suite (Workaround) ===${NC}"

# Build if needed
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    echo -e "${YELLOW}Building Zig QUIC implementation...${NC}"
    docker build -t zig-qns:local -f examples/interop/zig-qns/Dockerfile .
fi

# Clean up any existing test resources
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    docker rm -f qns-sim qns-server qns-client 2>/dev/null || true
    docker network rm qns-net-left qns-net-right 2>/dev/null || true
}

# Ensure cleanup on exit
trap cleanup EXIT

# Initial cleanup
cleanup

# Create networks with specific subnets
echo -e "${YELLOW}Creating test networks...${NC}"
docker network create --subnet=193.167.0.0/24 qns-net-left
docker network create --subnet=193.167.100.0/24 qns-net-right

# Start simulator
echo -e "${YELLOW}Starting network simulator...${NC}"
docker run -d \
    --name qns-sim \
    --network qns-net-left \
    --cap-add NET_ADMIN \
    martenseemann/quic-network-simulator \
    /bin/sh -c "sleep 3600"

# Wait for container to be ready
sleep 2

# Connect simulator to both networks
docker network connect --ip 193.167.100.2 qns-net-right qns-sim

# Function to run a single test
run_test() {
    local server_impl=$1
    local client_impl=$2
    local testcase=$3
    
    echo -e "\n${YELLOW}Testing: ${server_impl} (server) <-> ${client_impl} (client) - ${testcase}${NC}"
    
    # Determine images
    local server_image
    local client_image
    
    case $server_impl in
        zig) server_image="zig-qns:local" ;;
        quic-go) server_image="martenseemann/quic-go-interop:latest" ;;
        ngtcp2) server_image="ghcr.io/ngtcp2/ngtcp2-interop:latest" ;;
        *) echo "Unknown server: $server_impl"; return 1 ;;
    esac
    
    case $client_impl in
        zig) client_image="zig-qns:local" ;;
        quic-go) client_image="martenseemann/quic-go-interop:latest" ;;
        ngtcp2) client_image="ghcr.io/ngtcp2/ngtcp2-interop:latest" ;;
        *) echo "Unknown client: $client_impl"; return 1 ;;
    esac
    
    # Start server
    docker run -d \
        --name qns-server \
        --network qns-net-right \
        --ip 193.167.100.100 \
        --hostname server \
        --cap-add NET_ADMIN \
        -v "${ROOT}/examples/interop/quic-network-simulator/www:/www:ro" \
        -e ROLE=server \
        -e TESTCASE="$testcase" \
        --add-host "client4:193.167.0.100" \
        "$server_image" >/dev/null 2>&1
    
    # Wait for server to start
    sleep 2
    
    # Start client
    docker run -d \
        --name qns-client \
        --network qns-net-left \
        --ip 193.167.0.100 \
        --hostname client \
        --cap-add NET_ADMIN \
        -v "${ROOT}/examples/interop/quic-network-simulator/downloads:/downloads" \
        -e ROLE=client \
        -e TESTCASE="$testcase" \
        -e REQUESTS="https://server4/index.html" \
        --add-host "server4:193.167.100.100" \
        "$client_image" >/dev/null 2>&1
    
    # Wait for test to complete
    local timeout=30
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if ! docker ps | grep -q qns-client; then
            break
        fi
        sleep 1
        ((elapsed++))
    done
    
    # Check results
    local client_exit_code=$(docker inspect qns-client --format='{{.State.ExitCode}}' 2>/dev/null || echo "999")
    
    # Check for successful download
    local success=false
    if docker exec qns-server ls /www/index.html >/dev/null 2>&1; then
        if docker exec qns-client ls /downloads/index.html >/dev/null 2>&1; then
            success=true
        fi
    fi
    
    # For handshake test, just check if connection was established
    if [[ "$testcase" == "handshake" ]]; then
        if docker logs qns-server 2>&1 | grep -q "accepted connection\|handshake complete"; then
            success=true
        elif docker logs qns-client 2>&1 | grep -q "handshake complete"; then
            success=true
        fi
    fi
    
    if [[ "$success" == "true" ]]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        # Show logs for debugging
        echo "Server logs:"
        docker logs qns-server 2>&1 | tail -10 || true
        echo "Client logs:"
        docker logs qns-client 2>&1 | tail -10 || true
        return 1
    fi
    
    # Cleanup containers for next test
    docker rm -f qns-server qns-client 2>/dev/null || true
}

# Create test www directory if it doesn't exist
mkdir -p examples/interop/quic-network-simulator/www
echo "<html><body>Test file</body></html>" > examples/interop/quic-network-simulator/www/index.html

# Run tests
PASSED=0
FAILED=0

# Test matrix
TESTS=(
    "zig quic-go handshake"
    "quic-go zig handshake"
    "zig zig handshake"
)

for test in "${TESTS[@]}"; do
    IFS=' ' read -r server client testcase <<< "$test"
    if run_test "$server" "$client" "$testcase"; then
        ((PASSED++))
    else
        ((FAILED++))
    fi
    # Clean up between tests
    docker rm -f qns-server qns-client 2>/dev/null || true
done

# Summary
echo -e "\n${GREEN}=== Test Results ===${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [[ $FAILED -eq 0 ]]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed${NC}"
    exit 1
fi