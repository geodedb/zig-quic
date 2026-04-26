#!/usr/bin/env bash
# scripts/interop_control_test.sh
#
# Zero-zig control test: run quic-go <-> quic-go over the local
# docker-compose.full.yml sim. If this passes, the docker-compose +
# sim setup is functional and any downstream failure of
# scripts/interop_verify.sh points at a zig-quic issue. If this
# fails, the failure is in the infrastructure (docker networking /
# ns-3 simulator / host netfilter / startup race), not in zig-quic.
#
# Exit codes:
#   0 — handshake completed, transfer succeeded
#   1 — handshake or transfer timed out (any of several pre-existing
#       infra issues documented in the bug triage)
#   2 — setup error (sim failed to start, images missing, etc.)
#   3 — pre-flight host config blocker detected (see HOST_SETUP below)
#
# Prereqs:
#   scripts/interop_local_bootstrap.sh has been run at least once.
#
# HOST_SETUP — bridge-netfilter must NOT silently drop intra-bridge UDP:
#
#   Docker ≥ 29 on some kernels (seen on 6.12 Debian 13) silently drops
#   intra-bridge UDP whose L3 destination is outside the bridge subnet —
#   which is exactly what happens when a QUIC client routes to the server
#   via the sim's IP (next-hop MAC = sim, dst IP = server on *other* bridge).
#   The packets never reach the sim's eth0; no counter in iptables FORWARD /
#   DOCKER-USER / DOCKER-FORWARD ever increments; the sim pcap shows zero
#   UDP Initials. Client sees 'Downloading files failed: timeout: no recent
#   network activity'.
#
#   The minimal host-side fix is:
#       sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
#   (transient; reverts on reboot. To persist: /etc/sysctl.d/99-docker.conf.)
#
#   This script runs a pre-flight probe (below) and bails early with
#   exit=3 and a clear message if the host is in the broken config, rather
#   than producing a 90-second timeout that looks like a zig-quic bug.
#
# Usage:
#   scripts/interop_control_test.sh             # handshake test
#   TESTCASE=transfer scripts/interop_control_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
cd "$ROOT"

TESTCASE="${TESTCASE:-handshake}"
export COMPOSE_PROJECT_NAME="interop_control_$$"

QUIC_GO_IMAGE="${QUIC_GO_IMAGE:-martenseemann/quic-go-interop:latest}"
export SERVER_IMAGE="${QUIC_GO_IMAGE}"
export CLIENT_IMAGE="${QUIC_GO_IMAGE}"
export TESTCASE
export SCENARIO="${SCENARIO:-simple-p2p --delay=10ms --bandwidth=10Mbps --queue=25}"

LOG="/tmp/interop_control_test_${TESTCASE}.log"
COMPOSE=(docker compose -f examples/interop/docker-compose.full.yml --profile generic)

# shellcheck disable=SC2317 # invoked by the EXIT trap.
cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[control] scenario: $SCENARIO"
echo "[control] testcase: $TESTCASE"
echo "[control] image:    $QUIC_GO_IMAGE"

# Pre-flight: detect the bridge-nf-call-iptables=1 silent-drop blocker.
# We only READ /proc/sys; we never modify it (see HOST_SETUP above).
BRNF="/proc/sys/net/bridge/bridge-nf-call-iptables"
if [[ -r "$BRNF" ]]; then
  if [[ "$(cat "$BRNF" 2>/dev/null)" == "1" ]]; then
    cat >&2 <<'EOF'
[control] HOST_SETUP blocker detected: net.bridge.bridge-nf-call-iptables=1.
[control]
[control] On this host/kernel combo, that setting causes the docker bridges to
[control] silently drop intra-bridge UDP packets whose L3 destination is not
[control] within the bridge subnet -- exactly the QUIC client→sim→server path.
[control] The quic-go handshake would time out in ~45s with 'no recent network
[control] activity' and zero UDP packets in the sim pcap.
[control]
[control] To run this reproducer on this host, ONE of:
[control]   (transient)  sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
[control]   (persist)    echo 'net.bridge.bridge-nf-call-iptables=0' \
[control]                    | sudo tee /etc/sysctl.d/99-docker-interop.conf \
[control]                  && sudo sysctl -p /etc/sysctl.d/99-docker-interop.conf
[control]
[control] This script refuses to modify host firewall state on its own.
[control] Set INTEROP_SKIP_BRNF_CHECK=1 to bypass this check (at your own risk).
EOF
    if [[ "${INTEROP_SKIP_BRNF_CHECK:-0}" != "1" ]]; then
      exit 3
    fi
    echo "[control] INTEROP_SKIP_BRNF_CHECK=1 set -- proceeding anyway." >&2
  fi
fi

"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
docker network rm interop_leftnet interop_rightnet >/dev/null 2>&1 || true

echo "[control] starting sim..."
if ! timeout 60 "${COMPOSE[@]}" up -d sim >/dev/null 2>&1; then
  echo "[control] sim failed to start" >&2
  exit 2
fi
sleep 15
# Sim default-DROP iptables workaround (mirrors scripts/interop_verify.sh:141-142).
docker exec "${COMPOSE_PROJECT_NAME}_sim" iptables  -D FORWARD -i eth0 -o eth1 -j DROP 2>/dev/null || true
docker exec "${COMPOSE_PROJECT_NAME}_sim" iptables  -D FORWARD -i eth1 -o eth0 -j DROP 2>/dev/null || true
docker exec "${COMPOSE_PROJECT_NAME}_sim" ip6tables -D FORWARD -i eth0 -o eth1 -j DROP 2>/dev/null || true
docker exec "${COMPOSE_PROJECT_NAME}_sim" ip6tables -D FORWARD -i eth1 -o eth0 -j DROP 2>/dev/null || true

echo "[control] running ${TESTCASE}..."
if timeout 90 "${COMPOSE[@]}" up --abort-on-container-exit --timeout 5 server client &> "$LOG"; then
  if grep -qE 'timeout: no recent network activity|Downloading files failed' "$LOG"; then
    echo "[control] FAIL: handshake timed out (see $LOG)" >&2
    exit 1
  fi
  echo "[control] PASS (log: $LOG)"
  exit 0
fi
echo "[control] FAIL: compose exit non-zero or wall timeout (see $LOG)" >&2
tail -15 "$LOG" | sed 's/\x1b\[[0-9;]*m//g'
exit 1
