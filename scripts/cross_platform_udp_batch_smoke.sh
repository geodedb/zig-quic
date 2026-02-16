#!/usr/bin/env bash
set -euo pipefail

targets=(
  x86_64-macos-none
  aarch64-macos-none
  x86_64-windows-gnu
  aarch64-windows-gnu
)

files=(
  src/quic/endpoint/transport.zig
  src/quic/endpoint/udp_transport.zig
  src/quic/endpoint.zig
)
bench_files=(
  bench/udp_batch_bench.zig
)

echo "[cross-platform-udp-batch] starting compile-only matrix"
for target in "${targets[@]}"; do
  for file in "${files[@]}"; do
    echo "[cross-platform-udp-batch] zig test ${file} --test-no-exec -target ${target}"
    zig test "${file}" --test-no-exec -target "${target}"
  done
  for bench_file in "${bench_files[@]}"; do
    echo "[cross-platform-udp-batch] zig build-exe ${bench_file} -fno-emit-bin -target ${target}"
    zig build-exe "${bench_file}" -fno-emit-bin -target "${target}" -O ReleaseFast
  done
done

echo "[cross-platform-udp-batch] PASS"
