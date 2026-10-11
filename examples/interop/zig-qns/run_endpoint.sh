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

drop_to_quic() {
  if [[ "$(id -un)" == "quic" ]]; then
    "$@"
    return
  fi
  if command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid=quic --regid=quic --clear-groups -- "$@"
    return
  fi
  if [[ "${INTEROP_ALLOW_ROOT_ENDPOINT:-0}" == "1" ]]; then
    echo "WARNING: setpriv unavailable; running endpoint as $(id -un) because INTEROP_ALLOW_ROOT_ENDPOINT=1" >&2
    "$@"
    return
  fi
  echo "ERROR: setpriv is required to drop qns-endpoint privileges; set INTEROP_ALLOW_ROOT_ENDPOINT=1 only for local debugging." >&2
  exit 126
}

run_endpoint_bin() {
  # Drop to the unprivileged 'quic' user created in the Dockerfile.
  drop_to_quic qns-endpoint "$@"
}

prepare_server_tls() {
  local key=""
  if [[ -z "${QNS_USE_BUNDLED_CERTS:-}" ]] &&
     [[ -e /certs/cert.pem || -e /certs/priv.key || -e /certs/key.pem ]]; then
    if [[ -f /certs/priv.key ]]; then
      key=/certs/priv.key
    else
      key=/certs/key.pem
    fi
    # Only the root entrypoint opens the mounted private key. The child gets
    # read-only descriptors, and all writes happen as quic in its private dir.
    drop_to_quic /prepare_tls.sh mounted 3</certs/cert.pem 4<"$key"
  else
    drop_to_quic /prepare_tls.sh fallback
  fi
  # qns-endpoint must use the privately staged material, not the root-only mount.
  export QNS_USE_BUNDLED_CERTS=1
}

if [[ "${INTEROP_PRIVILEGE_CHECK:-0}" == "1" ]]; then
  drop_to_quic id -un
  exit 0
fi

# Exercise the same credential path without configuring simulator networking.
if [[ "${INTEROP_TLS_CHECK:-0}" == "1" ]]; then
  prepare_server_tls
  drop_to_quic openssl pkey -in /quic/certs/key.pem -noout
  drop_to_quic stat -c '%U:%G %a' /quic/certs/key.pem
  drop_to_quic openssl x509 -in /quic/certs/cert.pem -noout -fingerprint -sha256
  drop_to_quic openssl x509 -in /quic/certs/cert.pem -noout -ext basicConstraints
  exit 0
fi

/setup.sh
umask 007

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
# Preserve the mount's group so the invoking user can inspect artifacts.
# Setgid propagates that group to endpoint-created output without world access.
if [[ "$(id -u)" == 0 ]]; then
  chown quic /logs /downloads
  chmod 2770 /logs /downloads
  if [[ -n "${QLOGDIR:-}" ]]; then
    chown quic "$QLOGDIR"
    chmod 2770 "$QLOGDIR"
  fi
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

if [[ "$ROLE" == "server" ]]; then
  prepare_server_tls
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
  if [[ -w /www && -z "$(ls -A /www 2>/dev/null || true)" ]]; then
    dd if=/dev/urandom of=/www/5000 bs=5000 count=1 status=none || true
    dd if=/dev/urandom of=/www/10000 bs=10000 count=1 status=none || true
  fi

  run_endpoint_bin "$@" 2>&1 | tee /logs/server.log
  exit "${PIPESTATUS[0]}"
fi

echo "Unknown ROLE: '$ROLE'" >&2
exit 1
