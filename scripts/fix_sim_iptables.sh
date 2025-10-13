#!/usr/bin/env bash
set -euo pipefail

# Fix network simulator iptables DROP rules
#
# The quic-network-simulator uses iptables DROP rules to force traffic through ns3,
# but the nfqueue rules that redirect to ns3 are not being set up properly in some scenarios.
# This script removes the DROP rules to allow direct connectivity for testing.
#
# Usage:
#   ./fix_sim_iptables.sh <sim_container_name>

SIM_CONTAINER="${1:-}"

if [[ -z "$SIM_CONTAINER" ]]; then
    echo "Usage: $0 <sim_container_name>"
    echo "Example: $0 interop_test_12345_sim"
    exit 1
fi

# Fix DOCKER_HOST if needed
if [[ "${DOCKER_HOST:-}" == "/var/run/docker.sock" ]]; then
    unset DOCKER_HOST
fi

echo "Checking iptables rules in $SIM_CONTAINER..."
docker exec "$SIM_CONTAINER" iptables -L FORWARD -n -v

echo "Removing DROP rules that block traffic between eth0 and eth1..."
docker exec "$SIM_CONTAINER" iptables -D FORWARD -i eth0 -o eth1 -j DROP 2>/dev/null || echo "Rule eth0->eth1 not found"
docker exec "$SIM_CONTAINER" iptables -D FORWARD -i eth1 -o eth0 -j DROP 2>/dev/null || echo "Rule eth1->eth0 not found"

echo "Updated iptables rules:"
docker exec "$SIM_CONTAINER" iptables -L FORWARD -n -v

echo "Done! Traffic should now flow between client and server."
