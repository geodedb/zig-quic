#!/usr/bin/env bash
set -euo pipefail

targets=(
  x86_64-macos-none
  aarch64-macos-none
  x86_64-windows-gnu
  aarch64-windows-gnu
)

bench_files=(
  bench/udp_batch_bench.zig
)

echo "[cross-platform-udp-batch] starting compile-only matrix"
for target in "${targets[@]}"; do
  # Use the build system's cross-smoke step so module dependencies resolve correctly.
  # addObject produces object files only (no linking), so no system libraries are needed.
  echo "[cross-platform-udp-batch] zig build cross-smoke -Dtarget=${target}"
  zig build cross-smoke -Dtarget="${target}"

  for bench_file in "${bench_files[@]}"; do
    echo "[cross-platform-udp-batch] zig build-exe ${bench_file} -fno-emit-bin -target ${target}"
    zig build-exe "${bench_file}" -fno-emit-bin -target "${target}" -O ReleaseFast
  done
done

echo "[cross-platform-udp-batch] PASS"
