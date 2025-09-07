#!/usr/bin/env bash
set -euo pipefail

# Comprehensive interoperability verification script
# Tests the Zig QUIC implementation against multiple implementations

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
pushd "$ROOT" >/dev/null

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== QUIC Interop Verification Suite ===${NC}"
echo -e "${BLUE}Testing Zig QUIC implementation interoperability${NC}\n"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"
if ! command -v zig &> /dev/null; then
    echo -e "${RED}Error: zig not found in PATH${NC}"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker not found in PATH${NC}"
    exit 1
fi

ZIG_VERSION=$(zig version)
echo -e "Zig version: ${GREEN}${ZIG_VERSION}${NC}"

# Build the implementation
echo -e "\n${YELLOW}Building Zig QUIC implementation...${NC}"
if zig build -Drelease-safe=true install; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Check that binaries exist
echo -e "\n${YELLOW}Verifying binaries...${NC}"
BINARIES=("qns-endpoint" "quic-client" "quic-server")
for bin in "${BINARIES[@]}"; do
    if [[ -f "zig-out/bin/$bin" ]]; then
        echo -e "${GREEN}✓ $bin found${NC}"
    else
        echo -e "${RED}✗ $bin missing${NC}"
        exit 1
    fi
done

# Build Docker image
echo -e "\n${YELLOW}Building Docker image for QNS...${NC}"
if docker compose -f examples/interop/docker-compose.full.yml --profile zig build zig-server zig-client; then
    echo -e "${GREEN}✓ Docker image built${NC}"
else
    echo -e "${RED}✗ Docker image build failed${NC}"
    exit 1
fi

# Verify Docker image exists
if docker images | grep -q "zig-qns.*local"; then
    echo -e "${GREEN}✓ zig-qns:local image exists${NC}"
else
    echo -e "${RED}✗ zig-qns:local image not found${NC}"
    exit 1
fi

# Test matrix
declare -A TEST_RESULTS
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a single test
run_single_test() {
    local server=$1
    local client=$2
    local testcase=$3
    local test_name="${server}_${client}_${testcase}"
    
    ((TOTAL_TESTS++))
    echo -e "\n${YELLOW}Test #${TOTAL_TESTS}: ${server} (server) <-> ${client} (client) - ${testcase}${NC}"
    
    # Clean up any existing containers
    docker compose -f examples/interop/docker-compose.full.yml --profile generic down -v >/dev/null 2>&1 || true
    docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
    sleep 1
    
    # Set up test environment
    export COMPOSE_PROJECT_NAME="interop_verify_${test_name}_$$"
    export TESTCASE="$testcase"
    
    # Map implementation to Docker image
    local server_image
    local client_image
    
    case $server in
        zig) server_image="zig-qns:local" ;;
        quic-go) server_image="martenseemann/quic-go-interop:latest" ;;
        ngtcp2) server_image="ghcr.io/ngtcp2/ngtcp2-interop:latest" ;;
        quiche) server_image="cloudflare/quiche-qns:latest" ;;
        *) echo -e "${RED}Unknown server: $server${NC}"; return 1 ;;
    esac
    
    case $client in
        zig) client_image="zig-qns:local" ;;
        quic-go) client_image="martenseemann/quic-go-interop:latest" ;;
        ngtcp2) client_image="ghcr.io/ngtcp2/ngtcp2-interop:latest" ;;
        quiche) client_image="cloudflare/quiche-qns:latest" ;;
        *) echo -e "${RED}Unknown client: $client${NC}"; return 1 ;;
    esac
    
    export SERVER_IMAGE="$server_image"
    export CLIENT_IMAGE="$client_image"
    
    # Start sim first
    if ! COMPOSE_HTTP_TIMEOUT=120 timeout 60 docker compose -f examples/interop/docker-compose.full.yml --profile generic up -d sim >/dev/null 2>&1; then
        echo -e "${RED}✗ Failed to start sim${NC}"
        TEST_RESULTS[$test_name]="FAILED (sim start)"
        ((FAILED_TESTS++))
        return 1
    fi
    
    # Wait for sim
    sleep 5
    
    # Run the test
    local log_file="/tmp/interop_verify_${test_name}.log"
    if COMPOSE_HTTP_TIMEOUT=120 timeout 120 docker compose -f examples/interop/docker-compose.full.yml --profile generic up --abort-on-container-exit --timeout 5 &> "$log_file"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        TEST_RESULTS[$test_name]="PASSED"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo -e "${YELLOW}  Log: $log_file${NC}"
        # Check for common issues
        if grep -q "wait-for-it.sh: timeout" "$log_file"; then
            echo -e "${YELLOW}  Issue: Sim readiness timeout${NC}"
        elif grep -q "handshake timeout" "$log_file"; then
            echo -e "${YELLOW}  Issue: Handshake timeout${NC}"
        elif grep -q "connection refused" "$log_file"; then
            echo -e "${YELLOW}  Issue: Connection refused${NC}"
        fi
        TEST_RESULTS[$test_name]="FAILED"
        ((FAILED_TESTS++))
    fi
    
    # Clean up
    docker compose -f examples/interop/docker-compose.full.yml --profile generic down -v >/dev/null 2>&1 || true
    docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
}

# Run core interop tests
echo -e "\n${BLUE}=== Running Core Interop Tests ===${NC}"

# Test 1: Zig as server
run_single_test "zig" "quic-go" "handshake"
run_single_test "zig" "quic-go" "transfer"

# Test 2: Zig as client
run_single_test "quic-go" "zig" "handshake"
run_single_test "quic-go" "zig" "transfer"

# Test 3: Additional implementations if requested
if [[ "${EXTENDED:-0}" == "1" ]]; then
    echo -e "\n${BLUE}=== Running Extended Tests ===${NC}"
    run_single_test "zig" "ngtcp2" "handshake"
    run_single_test "ngtcp2" "zig" "handshake"
    run_single_test "zig" "quiche" "handshake"
    run_single_test "quiche" "zig" "handshake"
fi

# Print summary
echo -e "\n${BLUE}=== Test Results Summary ===${NC}"
echo -e "Total tests: ${TOTAL_TESTS}"
echo -e "${GREEN}Passed: ${PASSED_TESTS}${NC}"
echo -e "${RED}Failed: ${FAILED_TESTS}${NC}"

# Detailed results
echo -e "\n${BLUE}=== Detailed Results ===${NC}"
for test_name in "${!TEST_RESULTS[@]}"; do
    result="${TEST_RESULTS[$test_name]}"
    if [[ "$result" == "PASSED" ]]; then
        echo -e "${GREEN}✓${NC} $test_name: $result"
    else
        echo -e "${RED}✗${NC} $test_name: $result"
    fi
done | sort

# Exit code
if [[ $FAILED_TESTS -gt 0 ]]; then
    echo -e "\n${RED}Some tests failed. Check /tmp/interop_verify_*.log for details.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
fi

popd >/dev/null