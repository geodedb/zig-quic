#!/usr/bin/env bash
set -euo pipefail

# Full interoperability test runner for Zig QUIC implementation
# Tests against all available QUIC implementations using docker-compose

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repository root is the parent directory of scripts/
ROOT="${SCRIPT_DIR}/.."
pushd "$ROOT" >/dev/null

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== QUIC Interoperability Test Suite ===${NC}"

# Build the Zig implementation (skip if already exists and SKIP_BUILD=1)
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    echo -e "${YELLOW}Building Zig QUIC implementation...${NC}"
    zig build -Drelease-safe=true install || { echo -e "${RED}Host build failed. Ensure Zig 0.15.1 and run again.${NC}"; exit 1; }
    docker compose -f examples/interop/docker-compose.full.yml --profile zig build zig-server zig-client
else
    echo -e "${YELLOW}Skipping build (SKIP_BUILD=1)...${NC}"
fi

# Pull all other implementation images
echo -e "${YELLOW}Pulling other QUIC implementation images...${NC}"
docker compose -f examples/interop/docker-compose.full.yml pull

# Ensure no leftover networks from previous runs that might conflict with IP pools
if docker network ls --format '{{.Name}}' | grep -q '^interop_rightnet$'; then
    docker network rm interop_rightnet >/dev/null 2>&1 || true
fi
if docker network ls --format '{{.Name}}' | grep -q '^interop_leftnet$'; then
    docker network rm interop_leftnet >/dev/null 2>&1 || true
fi

# Proactively prune any docker networks that already use the QNS subnets to avoid
# 'Pool overlaps with other one on this address space' errors. Can be skipped
# by setting SKIP_QNS_NET_PRUNE=1.
if [[ "${SKIP_QNS_NET_PRUNE:-0}" != "1" ]]; then
    echo -e "${YELLOW}Pruning pre-existing networks with QNS subnets (193.167.0.0/24, 193.167.100.0/24)...${NC}"
    QNS_SUBNET_REGEX='193\.167\.0\.0/24|193\.167\.100\.0/24|fd00:cafe:cafe:0::/64|fd00:cafe:cafe:100::/64'
    while read -r nid; do
        [[ -z "$nid" ]] && continue
        if docker network inspect "$nid" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -Eq "$QNS_SUBNET_REGEX"; then
            nname=$(docker network inspect "$nid" --format '{{.Name}}')
            echo -e " - Removing conflicting network: $nname"
            docker network rm "$nid" >/dev/null 2>&1 || echo -e "${RED}   Failed to remove $nname (in use)${NC}"
        fi
    done < <(docker network ls -q)
fi


# Test cases to run
TESTCASES=("handshake" "transfer" "retry" "http3" "keyupdate")

# Results tracking
declare -A RESULTS
PASSED=0
FAILED=0
SKIPPED=0

# Function to run a single test
run_test() {
    local server=$1
    local client=$2
    local testcase=$3
    local key="${server}_${client}_${testcase}"
    
    echo -e "\n${YELLOW}Testing: ${server} (server) <-> ${client} (client) - ${testcase}${NC}"
    export COMPOSE_PROJECT_NAME="interop_${server}_${client}_${testcase}_$$"
    
    # Set up environment variables
    export SERVER=$server
    export CLIENT=$client
    export TESTCASE=$testcase
    
    # Determine which profiles to use
    local profiles=""
    if [[ "$server" == "zig" ]]; then
        profiles="zig"
    else
        profiles="$server"
    fi
    if [[ "$client" == "zig" ]]; then
        if [[ -n "$profiles" ]]; then
            profiles="${profiles},zig"
        else
            profiles="zig"
        fi
    else
        if [[ -n "$profiles" ]]; then
            profiles="${profiles},${client}"
        else
            profiles="$client"
        fi
    fi
    
    # Special handling for nginx (server-only)
    if [[ "$server" == "nginx" && "$client" != "zig" ]]; then
        echo -e "${YELLOW}Skipping: nginx is server-only${NC}"
        RESULTS[$key]="SKIPPED"
        ((SKIPPED++))
        return
    fi
    
    # Ensure clean slate for this project name
    docker compose -f examples/interop/docker-compose.full.yml --profile $profiles down -v >/dev/null 2>&1 || true
    docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
    sleep 1
    # Bring up the simulator first, then client+server to avoid race on sim readiness
    if ! COMPOSE_HTTP_TIMEOUT=120 timeout 120 docker compose -f examples/interop/docker-compose.full.yml --profile $profiles up -d sim; then echo -e "${RED}Failed to start sim${NC}"; fi
    sleep 3
    # Run the test with timeout
    if COMPOSE_HTTP_TIMEOUT=120 timeout 240 docker compose -f examples/interop/docker-compose.full.yml --profile $profiles up --abort-on-container-exit --timeout 5 2>&1 | tee "/tmp/interop_${key}.log"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        RESULTS[$key]="PASSED"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        RESULTS[$key]="FAILED"
        ((FAILED++))
    fi
    
    # Clean up containers and networks
    docker compose -f examples/interop/docker-compose.full.yml --profile $profiles down -v >/dev/null 2>&1 || true
    # Also try to remove networks if they still exist
    docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
    sleep 1
}

# Function to test using generic profile with image variables
run_generic_test() {
    local server_impl=$1
    local client_impl=$2
    local testcase=$3
    local key="${server_impl}_${client_impl}_${testcase}"
    
    echo -e "\n${YELLOW}Testing: ${server_impl} (server) <-> ${client_impl} (client) - ${testcase}${NC}"
    export COMPOSE_PROJECT_NAME="interop_${server_impl}_${client_impl}_${testcase}_$$"
    
    # Map implementation names to Docker images
    local server_image
    local client_image
    
    case $server_impl in
        zig) server_image="zig-qns:local" ;;
        quic-go) server_image="martenseemann/quic-go-interop:latest" ;;
        ngtcp2) server_image="ghcr.io/ngtcp2/ngtcp2-interop:latest" ;;
        quiche) server_image="cloudflare/quiche-qns:latest" ;;
        picoquic) server_image="privateoctopus/picoquic:latest" ;;
        aioquic) server_image="aiortc/aioquic-qns:latest" ;;
        msquic) server_image="ghcr.io/microsoft/msquic/qns:main" ;;
        nginx) server_image="ghcr.io/nginx/nginx-quic-qns:latest" ;;
        mvfst) server_image="ghcr.io/facebook/proxygen/mvfst-interop:latest" ;;
        kwik) server_image="peterdoornbosch/kwik_n_flupke-interop" ;;
        neqo) server_image="ghcr.io/mozilla/neqo-qns:latest" ;;
        xquic) server_image="ghcr.io/alibaba/xquic/xquic-interop:latest" ;;
        lsquic) server_image="litespeedtech/lsquic-qir:latest" ;;
        haproxy) server_image="haproxytech/haproxy-qns:latest" ;;
        quinn) server_image="stammw/quinn-interop:latest" ;;
        s2n-quic) server_image="ghcr.io/aws/s2n-quic/s2n-quic-qns:latest" ;;
        go-x-net) server_image="us-central1-docker.pkg.dev/golang-interop-testing/quic/go-x-net:latest" ;;
        *) echo "Unknown server implementation: $server_impl"; return 1 ;;
    esac
    
    case $client_impl in
        zig) client_image="zig-qns:local" ;;
        quic-go) client_image="martenseemann/quic-go-interop:latest" ;;
        ngtcp2) client_image="ghcr.io/ngtcp2/ngtcp2-interop:latest" ;;
        quiche) client_image="cloudflare/quiche-qns:latest" ;;
        picoquic) client_image="privateoctopus/picoquic:latest" ;;
        aioquic) client_image="aiortc/aioquic-qns:latest" ;;
        msquic) client_image="ghcr.io/microsoft/msquic/qns:main" ;;
        chrome) client_image="martenseemann/chrome-quic-interop-runner" ;;
        mvfst) client_image="ghcr.io/facebook/proxygen/mvfst-interop:latest" ;;
        kwik) client_image="peterdoornbosch/kwik_n_flupke-interop" ;;
        neqo) client_image="ghcr.io/mozilla/neqo-qns:latest" ;;
        xquic) client_image="ghcr.io/alibaba/xquic/xquic-interop:latest" ;;
        lsquic) client_image="litespeedtech/lsquic-qir:latest" ;;
        quinn) client_image="stammw/quinn-interop:latest" ;;
        s2n-quic) client_image="ghcr.io/aws/s2n-quic/s2n-quic-qns:latest" ;;
        go-x-net) client_image="us-central1-docker.pkg.dev/golang-interop-testing/quic/go-x-net:latest" ;;
        *) echo "Unknown client implementation: $client_impl"; return 1 ;;
    esac
    
    # Set up environment variables
    export SERVER_IMAGE="$server_image"
    export CLIENT_IMAGE="$client_image"
    export TESTCASE="$testcase"
    
    # Ensure clean slate for this project name
    docker compose -f examples/interop/docker-compose.full.yml --profile generic down -v >/dev/null 2>&1 || true
    docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
    sleep 1
    # Bring up the simulator first, then client+server to avoid race on sim readiness
    if ! COMPOSE_HTTP_TIMEOUT=120 timeout 120 docker compose -f examples/interop/docker-compose.full.yml --profile generic up -d sim; then echo -e "${RED}Failed to start sim${NC}"; fi
    sleep 10
    # Run the test with timeout
    if COMPOSE_HTTP_TIMEOUT=120 timeout 240 docker compose -f examples/interop/docker-compose.full.yml --profile generic up --abort-on-container-exit --timeout 5 2>&1 | tee "/tmp/interop_${key}.log"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        RESULTS[$key]="PASSED"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        RESULTS[$key]="FAILED"
        ((FAILED++))
    fi
    
    # Clean up containers and networks
    docker compose -f examples/interop/docker-compose.full.yml --profile generic down -v >/dev/null 2>&1 || true
    # Also try to remove networks if they still exist
    docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
}

# Main test execution
echo -e "\n${GREEN}=== Running Interoperability Tests ===${NC}"

# Test mode selection
MODE=${1:-basic}

if [[ "$MODE" == "full" ]]; then
    # Full matrix: test zig against all implementations in both directions
    ALL_IMPLS=("quic-go" "ngtcp2" "mvfst" "quiche" "kwik" "picoquic" "aioquic" "neqo" "msquic" "xquic" "lsquic" "quinn" "s2n-quic" "go-x-net")
    
    for impl in "${ALL_IMPLS[@]}"; do
        for testcase in "${TESTCASES[@]}"; do
            # Zig as server
            run_generic_test "zig" "$impl" "$testcase"
            # Zig as client
            run_generic_test "$impl" "zig" "$testcase"
        done
    done
    
    # Test server-only implementations
    for testcase in "${TESTCASES[@]}"; do
        run_generic_test "nginx" "zig" "$testcase"
        run_generic_test "haproxy" "zig" "$testcase"
    done
    
    # Test client-only implementations
    for testcase in "${TESTCASES[@]}"; do
        run_generic_test "zig" "chrome" "$testcase"
    done
    
elif [[ "$MODE" == "quick" ]]; then
    # Quick test: just handshake and transfer against major implementations
    QUICK_IMPLS=("quic-go" "ngtcp2" "quiche")
    QUICK_TESTS=("handshake" "transfer")
    
    for impl in "${QUICK_IMPLS[@]}"; do
        for testcase in "${QUICK_TESTS[@]}"; do
            run_generic_test "zig" "$impl" "$testcase"
            run_generic_test "$impl" "zig" "$testcase"
        done
    done
    
else
    # Basic mode: test against quic-go only
    for testcase in "${TESTCASES[@]}"; do
        run_generic_test "zig" "quic-go" "$testcase"
        run_generic_test "quic-go" "zig" "$testcase"
    done
fi

# Print results summary
echo -e "\n${GREEN}=== Test Results Summary ===${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED${NC}"

# Print detailed results
echo -e "\n${GREEN}=== Detailed Results ===${NC}"
for key in "${!RESULTS[@]}"; do
    result=${RESULTS[$key]}
    case $result in
        PASSED) echo -e "${GREEN}✓${NC} $key" ;;
        FAILED) echo -e "${RED}✗${NC} $key" ;;
        SKIPPED) echo -e "${YELLOW}⊘${NC} $key" ;;
    esac
done | sort

# Exit with appropriate code
if [[ $FAILED -gt 0 ]]; then
    echo -e "\n${RED}Some tests failed. Check /tmp/interop_*.log for details.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
fi

popd >/dev/null