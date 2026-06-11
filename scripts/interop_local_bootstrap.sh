#!/usr/bin/env bash
# scripts/interop_local_bootstrap.sh
#
# Initialise the examples/interop/quic-interop-runner and
# examples/interop/quic-network-simulator layout that
# scripts/interop_local.sh / interop_verify.sh / interop_full.sh expect.
#
# Mirrors the CI before_script in .gitlab-ci.yml:433-446 (interop-test job)
# so that developer-host interop runs hit the same layout as CI.
#
# Idempotent: safe to re-run. Existing checkouts at the pinned SHA are left
# in place.
#
# Usage:
#   scripts/interop_local_bootstrap.sh
#
# After a successful run:
#   - examples/interop/quic-interop-runner checked out at the pinned SHA
#   - examples/interop/quic-network-simulator/{logs,www,downloads} populated
#   - www/{index.html,5000,10000} filled with deterministic-in-size random
#     test payloads matching the CI layout
#
# Rollback:
#   rm -rf examples/interop/quic-interop-runner \
#          examples/interop/quic-network-simulator
#
# Both directories are developer-local state, never committed.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
cd "$ROOT"

# Pinned commit. Keep in lock-step with the QUIC_INTEROP_RUNNER_COMMIT value in
# .gitlab-ci.yml (search for QUIC_INTEROP_RUNNER_COMMIT under the interop-test
# job). Bump both values together when upgrading.
QUIC_INTEROP_RUNNER_COMMIT="93303cc97699d0b71651265b066fedbf6a84d4ec"

RUNNER_DIR="examples/interop/quic-interop-runner"
QNS_DIR="examples/interop/quic-network-simulator"

echo "[bootstrap] interop runner pinned commit: ${QUIC_INTEROP_RUNNER_COMMIT}"

if [[ -d "${RUNNER_DIR}/.git" ]]; then
  current_sha="$(git -C "${RUNNER_DIR}" rev-parse HEAD 2>/dev/null || echo none)"
  if [[ "${current_sha}" == "${QUIC_INTEROP_RUNNER_COMMIT}" ]]; then
    echo "[bootstrap] ${RUNNER_DIR} already at pinned SHA; skipping fetch"
  else
    echo "[bootstrap] ${RUNNER_DIR} at ${current_sha}; refetching to pinned SHA"
    git -C "${RUNNER_DIR}" fetch --depth 1 origin "${QUIC_INTEROP_RUNNER_COMMIT}"
    git -C "${RUNNER_DIR}" checkout --detach FETCH_HEAD
  fi
else
  echo "[bootstrap] initialising ${RUNNER_DIR}"
  mkdir -p "${RUNNER_DIR}"
  git init "${RUNNER_DIR}"
  git -C "${RUNNER_DIR}" remote add origin https://github.com/quic-interop/quic-interop-runner.git
  git -C "${RUNNER_DIR}" fetch --depth 1 origin "${QUIC_INTEROP_RUNNER_COMMIT}"
  git -C "${RUNNER_DIR}" checkout --detach FETCH_HEAD
fi

got_sha="$(git -C "${RUNNER_DIR}" rev-parse HEAD)"
if [[ "${got_sha}" != "${QUIC_INTEROP_RUNNER_COMMIT}" ]]; then
  echo "[bootstrap] ERROR: ${RUNNER_DIR} HEAD=${got_sha} != pinned ${QUIC_INTEROP_RUNNER_COMMIT}" >&2
  exit 1
fi

echo "[bootstrap] ensuring ${QNS_DIR} layout"
mkdir -p "${QNS_DIR}/logs/sim"
mkdir -p "${QNS_DIR}/logs/server"
mkdir -p "${QNS_DIR}/logs/client"
mkdir -p "${QNS_DIR}/www"
mkdir -p "${QNS_DIR}/downloads"

# Bind-mount perms: the zig-qns container runs qns-endpoint as the
# unprivileged 'quic' user (UID 999 inside the image). When the host's
# logs/ and downloads/ are bind-mounted into the container, host ownership
# (the invoking developer's UID) is exposed -- 'quic' typically cannot
# write. World-writable on the host is the pragmatic local-dev fix; CI
# runs as root inside Docker-in-Docker and is unaffected.
chmod -R a+rwX "${QNS_DIR}/logs" "${QNS_DIR}/downloads" 2>/dev/null || true

# Seed test payloads (same sizes as CI). Regenerate every run so a corrupted
# prior payload does not silently poison the test.
dd if=/dev/urandom of="${QNS_DIR}/www/index.html" bs=1024  count=1 2>/dev/null
dd if=/dev/urandom of="${QNS_DIR}/www/5000"       bs=5000  count=1 2>/dev/null
dd if=/dev/urandom of="${QNS_DIR}/www/10000"      bs=10000 count=1 2>/dev/null

# Generate interop CA + server leaf and install under quic-interop-runner/certs
# so strict clients (s2n-quic et al.) can validate a trust chain. Logic is
# copied from scripts/interop_full.sh:prepare_local_interop_assets.
CERT_DIR="${RUNNER_DIR}/certs"
mkdir -p "${CERT_DIR}"
if command -v openssl >/dev/null 2>&1; then
  echo "[bootstrap] generating interop CA + server cert"
  CERT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/qns-certs.XXXXXX")"
  (
    set -euo pipefail
    openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_TMP}/ca.key"
    cat > "${CERT_TMP}/ca.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=zig-quic-interop-ca
O=zig-quic interop
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
authorityKeyIdentifier=keyid:always
subjectKeyIdentifier=hash
EOF
    openssl req -x509 -new -key "${CERT_TMP}/ca.key" -sha256 -days 3650 \
      -out "${CERT_TMP}/ca.pem" -config "${CERT_TMP}/ca.cnf"

    openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_TMP}/server.key"
    cat > "${CERT_TMP}/server.cnf" <<'EOF'
[req]
distinguished_name=dn
req_extensions=v3_req
prompt=no
[dn]
CN=server
O=zig-quic interop
[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt
[alt]
DNS.1=server
DNS.2=server4
DNS.3=server6
DNS.4=server46
EOF
    openssl req -new -key "${CERT_TMP}/server.key" -out "${CERT_TMP}/server.csr" \
      -config "${CERT_TMP}/server.cnf"
    openssl x509 -req \
      -in "${CERT_TMP}/server.csr" \
      -CA "${CERT_TMP}/ca.pem" \
      -CAkey "${CERT_TMP}/ca.key" \
      -CAcreateserial \
      -out "${CERT_TMP}/server.crt" \
      -days 3650 -sha256 \
      -extensions v3_req \
      -extfile "${CERT_TMP}/server.cnf"
  ) >/dev/null 2>&1

  if [[ -s "${CERT_TMP}/server.crt" && -s "${CERT_TMP}/server.key" && -s "${CERT_TMP}/ca.pem" ]]; then
    install -m 0644 "${CERT_TMP}/server.crt" "${CERT_DIR}/cert.pem"
    install -m 0600 "${CERT_TMP}/server.key" "${CERT_DIR}/key.pem"
    install -m 0600 "${CERT_TMP}/server.key" "${CERT_DIR}/priv.key"
    install -m 0644 "${CERT_TMP}/ca.pem"     "${CERT_DIR}/ca.pem"
    echo "[bootstrap] interop certs installed at ${CERT_DIR}/{cert,key,priv,ca}.{pem,key}"
  else
    echo "[bootstrap] WARN: openssl cert generation failed; falling back to tests/certs/"
    install -m 0644 tests/certs/cert.pem "${CERT_DIR}/cert.pem"
    install -m 0644 tests/certs/cert.pem "${CERT_DIR}/ca.pem"
    install -m 0600 tests/certs/key.pem  "${CERT_DIR}/key.pem"
    install -m 0600 tests/certs/key.pem  "${CERT_DIR}/priv.key"
  fi
  rm -rf "${CERT_TMP}"
else
  echo "[bootstrap] openssl not found; using static tests/certs/ fixtures"
  install -m 0644 tests/certs/cert.pem "${CERT_DIR}/cert.pem"
  install -m 0644 tests/certs/cert.pem "${CERT_DIR}/ca.pem"
  install -m 0600 tests/certs/key.pem  "${CERT_DIR}/key.pem"
  install -m 0600 tests/certs/key.pem  "${CERT_DIR}/priv.key"
fi

# World-readable so the container's `quic` user can read the cert/key files.
chmod -R a+rX "${CERT_DIR}" 2>/dev/null || true
find "${CERT_DIR}" -type f \( -name "*.key" -o -name "priv.key" -o -name "key.pem" \) -exec chmod 600 {} + 2>/dev/null || true

echo "[bootstrap] done."
echo
echo "Next steps:"
echo "  - scripts/interop_test.sh       # single-handshake verification"
echo "  - scripts/interop_verify.sh     # full 4-test matrix"
echo "  - scripts/interop_full.sh basic # docker-compose run"
