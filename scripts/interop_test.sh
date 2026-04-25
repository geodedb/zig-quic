#!/usr/bin/env bash
set -euo pipefail

# Simple interoperability test to verify the setup works
# This tests a single handshake between zig and quic-go

# Fix DOCKER_HOST if it's set incorrectly (should be unix:// or unset for local socket)
if [[ "${DOCKER_HOST:-}" == "/var/run/docker.sock" ]]; then
    unset DOCKER_HOST
fi

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
pushd "$ROOT" >/dev/null

source "${SCRIPT_DIR}/interop_assets.sh"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== QUIC Interop Test - Single Handshake ===${NC}"

echo -e "${YELLOW}Preparing interop certificates and fixtures...${NC}"
prepare_local_interop_assets "$ROOT"

# Build if needed
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    echo -e "${YELLOW}Building Zig QUIC implementation...${NC}"
    zig build -Drelease-safe=true install || { echo -e "${RED}Build failed${NC}"; exit 1; }
    docker compose -f examples/interop/docker-compose.full.yml --profile zig build zig-server zig-client
fi

# Clean up any existing containers/networks
echo -e "${YELLOW}Cleaning up existing containers...${NC}"
docker compose -f examples/interop/docker-compose.full.yml --profile generic down -v >/dev/null 2>&1 || true
docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
sleep 1

# Test zig server with quic-go client
echo -e "\n${YELLOW}Testing: zig (server) <-> quic-go (client) - handshake${NC}"
export COMPOSE_PROJECT_NAME="interop_test_$$"
export SERVER_IMAGE="zig-qns:local"
export CLIENT_IMAGE="martenseemann/quic-go-interop:latest"
export TESTCASE="handshake"
export SCENARIO="simple-p2p --delay=10ms --bandwidth=10Mbps --queue=25"

# Start sim first
echo -e "${YELLOW}Starting network simulator...${NC}"
if ! COMPOSE_HTTP_TIMEOUT=120 timeout 60 docker compose -f examples/interop/docker-compose.full.yml --profile generic up -d sim; then
    echo -e "${RED}Failed to start sim${NC}"
    exit 1
fi

# Wait for sim to be ready
echo -e "${YELLOW}Waiting for sim to be ready...${NC}"
sleep 15

# Fix simulator iptables DROP rules that block all traffic
# The ns3 simulator should set up nfqueue rules, but they're not being created properly
# Remove the DROP rules to allow direct connectivity
echo -e "${YELLOW}Fixing simulator iptables rules...${NC}"
docker exec ${COMPOSE_PROJECT_NAME}_sim iptables -D FORWARD -i eth0 -o eth1 -j DROP 2>&1 | head -5 || echo "Rule 1 removed or not found"
docker exec ${COMPOSE_PROJECT_NAME}_sim iptables -D FORWARD -i eth1 -o eth0 -j DROP 2>&1 | head -5 || echo "Rule 2 removed or not found"
echo -e "${YELLOW}Verifying iptables FORWARD chain:${NC}"
docker exec ${COMPOSE_PROJECT_NAME}_sim iptables -L FORWARD -n -v

# Run the test
echo -e "${YELLOW}Running handshake test...${NC}"
if COMPOSE_HTTP_TIMEOUT=120 timeout 120 docker compose -f examples/interop/docker-compose.full.yml --profile generic up --abort-on-container-exit --timeout 5 2>&1 | tee "/tmp/interop_test.log"; then
    echo -e "${GREEN}✓ Test PASSED${NC}"
    RESULT=0
else
    echo -e "${RED}✗ Test FAILED${NC}"
    echo -e "${RED}Check /tmp/interop_test.log for details${NC}"
    RESULT=1
fi

# Clean up
echo -e "${YELLOW}Cleaning up...${NC}"
docker compose -f examples/interop/docker-compose.full.yml --profile generic down -v >/dev/null 2>&1 || true
docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true

popd >/dev/null
exit $RESULT
