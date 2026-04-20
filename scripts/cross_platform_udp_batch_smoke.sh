#!/usr/bin/env bash
# Cross-platform compile-only smoke for the UDP transport surface.
#
# Pre-Phase-3 this script also compiled bench/udp_batch_bench.zig against
# macOS/Windows targets. Phase 3 retired the bench/ tree and moved the
# UDP-batch benchmark under benchmarks/integration/udp_batch.zig, which is
# already gated to Linux-only (sendmmsg). Cross-platform compile coverage
# for the production UDP transport now lives entirely in the build.zig
# `cross-smoke` step (see build.zig:cross_smoke_step — it addObject's
# endpoint/transport, endpoint/udp_transport, and endpoint/endpoint for
# each target).
set -euo pipefail

targets=(
  x86_64-macos-none
  aarch64-macos-none
  x86_64-windows-gnu
  aarch64-windows-gnu
)

echo "[cross-platform-udp-batch] starting compile-only matrix"
for target in "${targets[@]}"; do
  # addObject produces object files only (no linking), so no system
  # libraries are needed on the builder host.
  echo "[cross-platform-udp-batch] zig build cross-smoke -Dtarget=${target}"
  zig build cross-smoke -Dtarget="${target}"
done

echo "[cross-platform-udp-batch] PASS"
