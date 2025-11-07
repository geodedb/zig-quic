#!/bin/bash

# RFC Compliance Test Runner for QUIC Modular Architecture
# Runs all RFC compliance unit tests and reports results

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test categories
CONNECTION_TESTS=(
    "test_types"
    "test_crypto_buffer"
    "test_packet_number"
    "test_ack"
    "test_stream"
    "test_connection_id"
)

FRAME_TESTS=(
    "test_types"
)

ENDPOINT_TESTS=(
    "test_types"
)

# Function to run a specific test
run_test() {
    local test_name="$1"
    local category="$2"

    echo -e "${BLUE}Running: ${category}/${test_name}${NC}"

    if zig build test --test-filter "$test_name" 2>&1 | grep -q "All.*tests passed"; then
        echo -e "${GREEN}✓ PASS: ${test_name}${NC}"
        return 0
    else
        echo -e "${RED}✗ FAIL: ${test_name}${NC}"
        return 1
    fi
}

# Main execution
echo "========================================"
echo "RFC Compliance Test Suite"
echo "========================================"
echo ""

total_tests=0
passed_tests=0
failed_tests=0

echo -e "${YELLOW}=== Connection Module Tests ===${NC}"
for test in "${CONNECTION_TESTS[@]}"; do
    total_tests=$((total_tests + 1))
    if run_test "$test" "connection"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    echo ""
done

echo -e "${YELLOW}=== Frame Module Tests ===${NC}"
for test in "${FRAME_TESTS[@]}"; do
    total_tests=$((total_tests + 1))
    if run_test "$test" "frame"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    echo ""
done

echo -e "${YELLOW}=== Endpoint Module Tests ===${NC}"
for test in "${ENDPOINT_TESTS[@]}"; do
    total_tests=$((total_tests + 1))
    if run_test "$test" "endpoint"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    echo ""
done

# Summary
echo "========================================"
echo "Test Results Summary"
echo "========================================"
echo -e "Total:  ${total_tests}"
echo -e "${GREEN}Passed: ${passed_tests}${NC}"
if [ $failed_tests -gt 0 ]; then
    echo -e "${RED}Failed: ${failed_tests}${NC}"
else
    echo -e "Failed: ${failed_tests}"
fi
echo ""

pass_rate=$((passed_tests * 100 / total_tests))
echo "Pass Rate: ${pass_rate}%"
echo ""

if [ $failed_tests -eq 0 ]; then
    echo -e "${GREEN}All RFC compliance tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the output above.${NC}"
    exit 1
fi
