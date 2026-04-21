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

# Seed test payloads (same sizes as CI). Regenerate every run so a corrupted
# prior payload does not silently poison the test.
dd if=/dev/urandom of="${QNS_DIR}/www/index.html" bs=1024  count=1 2>/dev/null
dd if=/dev/urandom of="${QNS_DIR}/www/5000"       bs=5000  count=1 2>/dev/null
dd if=/dev/urandom of="${QNS_DIR}/www/10000"      bs=10000 count=1 2>/dev/null

echo "[bootstrap] done."
echo
echo "Next steps:"
echo "  - scripts/interop_test.sh       # single-handshake verification"
echo "  - scripts/interop_verify.sh     # full 4-test matrix"
echo "  - scripts/interop_full.sh basic # docker-compose run"
