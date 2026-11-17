#!/usr/bin/env bash
# Compile the bench suite (zig build bench-build) for every release target
# (SONNY-6669). The suite stopped compiling for macOS and Windows when Zig
# 0.16 removed std.time.Timer and nothing noticed: CI only built it for
# Linux. Usage: scripts/bench_cross_compile.sh [target...]
set -euo pipefail

targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
  targets=(x86_64-linux-gnu aarch64-linux-gnu x86_64-macos aarch64-macos x86_64-windows aarch64-windows)
fi

failed=()
for t in "${targets[@]}"; do
  echo "=== bench-build -Dtarget=${t}"
  if zig build bench-build -Dtarget="${t}" --prefix "zig-out/bench-cross/${t}" --summary failures; then
    echo "=== PASS ${t}"
  else
    echo "=== FAIL ${t}"
    failed+=("${t}")
  fi
done

if [ "${#failed[@]}" -ne 0 ]; then
  echo "bench suite does not compile for: ${failed[*]}" >&2
  exit 1
fi
echo "bench suite compiles for: ${targets[*]}"
