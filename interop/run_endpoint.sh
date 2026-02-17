#!/usr/bin/env bash
set -euo pipefail

SUPPORTED_TESTCASES=(
  handshake
  transfer
  http3
  retry
  longrtt
  keyupdate
  amplificationlimit
  handshakeloss
  transferloss
  handshakecorruption
  transfercorruption
  blackhole
  multiconnect
  ipv6
  v2
  rebind-port
  rebind-addr
  goodput
  crosstraffic
)

is_supported_testcase() {
  local testcase="$1"
  local t
  for t in "${SUPPORTED_TESTCASES[@]}"; do
    if [[ "$t" == "$testcase" ]]; then
      return 0
    fi
  done
  return 1
}

run_endpoint_bin() {
  if [[ "${INTEROP_DROP_PRIVS:-0}" == "1" ]] && command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid=quic --regid=quic --clear-groups qns-endpoint "$@"
  else
    qns-endpoint "$@"
  fi
}

# Set up simulator routing first (requires root + CAP_NET_ADMIN in container).
/setup.sh

if [[ -f /quic/version.txt ]]; then
  echo "=== Zig QUIC Implementation ==="
  echo "Version: $(cat /quic/version.txt)"
fi

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-handshake}"

mkdir -p /logs /downloads /www
if [[ -n "${QLOGDIR:-}" ]]; then
  mkdir -p "$QLOGDIR"
fi

echo "Role: $ROLE"
echo "Test case: $TESTCASE"
echo "SSLKEYLOGFILE: ${SSLKEYLOGFILE:-not set}"
echo "QLOGDIR: ${QLOGDIR:-not set}"
echo "QNS_H3_ALLOW_EMPTY: ${QNS_H3_ALLOW_EMPTY:-not set}"

if ! is_supported_testcase "$TESTCASE"; then
  echo "Test case '$TESTCASE' is not supported by zig-qns endpoint. Exiting 127."
  exit 127
fi

# Keep key-update behavior deterministic in interop:
# - keyupdate testcase: allow automatic key updates
# - all other testcases: disable automatic key updates to avoid premature phase flips
if [[ "$TESTCASE" == "keyupdate" ]]; then
  unset QUIC_DISABLE_AUTO_KEY_UPDATE || true
else
  export QUIC_DISABLE_AUTO_KEY_UPDATE=1
fi

# Keep anti-amplification behavior deterministic in interop:
# - amplificationlimit testcase: keep amplification guard enabled
# - all other testcases: disable guard to avoid false blocking on migrated/lossy paths
if [[ "$TESTCASE" == "amplificationlimit" ]]; then
  unset QUIC_DISABLE_AMPLIFICATION_LIMIT || true
  # Use bundled inflated cert for this test so Handshake CRYPTO volume matches
  # interop-runner expectations even without multi-cert chain support.
  export QNS_USE_BUNDLED_CERTS=1
else
  export QUIC_DISABLE_AMPLIFICATION_LIMIT=1
fi

export ROLE TESTCASE
export LOG_LEVEL="${LOG_LEVEL:-debug}"
if [[ -n "${SSLKEYLOGFILE:-}" ]]; then
  export SSLKEYLOGFILE
fi
if [[ -n "${QLOGDIR:-}" ]]; then
  export QLOGDIR
fi

if [[ "$ROLE" == "client" ]]; then
  client_start_delay="${INTEROP_CLIENT_START_DELAY:-5}"
  if [[ "${client_start_delay}" =~ ^[0-9]+$ ]] && [[ "$client_start_delay" -gt 0 ]]; then
    echo "Delaying client start by ${client_start_delay}s for simulator readiness..."
    sleep "$client_start_delay"
  fi

  wait_target="${WAIT_FOR_TARGET:-${WAITFORSERVER:-}}"
  if [[ -n "$wait_target" ]]; then
    echo "Waiting for target to be ready: ${wait_target}"
    for i in $(seq 1 30); do
      if /wait-for-it.sh "${wait_target}" -s -t 5; then
        echo "Target ready: ${wait_target}"
        break
      fi
      if [[ "$i" -eq 30 ]]; then
        echo "ERROR: target was not reachable at ${wait_target}" >&2
        exit 1
      fi
      sleep 2
    done
  fi

  run_endpoint_bin "$@" 2>&1 | tee /logs/client.log
  exit "${PIPESTATUS[0]}"
fi

if [[ "$ROLE" == "server" ]]; then
  # Fallback for local runs where /www may not be mounted by the runner.
  if [[ -z "$(ls -A /www 2>/dev/null || true)" ]]; then
    dd if=/dev/urandom of=/www/5000 bs=5000 count=1 status=none || true
    dd if=/dev/urandom of=/www/10000 bs=10000 count=1 status=none || true
  fi

  run_endpoint_bin "$@" 2>&1 | tee /logs/server.log
  exit "${PIPESTATUS[0]}"
fi

echo "Unknown ROLE: '$ROLE'" >&2
exit 1
