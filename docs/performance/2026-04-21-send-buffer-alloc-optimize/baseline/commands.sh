#!/usr/bin/env bash
# Baseline capture commands for session send-buffer-alloc-optimize.
#
# git SHA:       4770a34355bca3a2362b7096a1db41999bf2932b (main)
# captured UTC:  2026-04-21T12:23:19Z .. 2026-04-21T12:27:52Z
# host:          haleth (Linux 6.12.74+deb13+1-amd64 x86_64, Xeon E5-2680 v4, schedutil)
# zig:           0.16.0 (mise shim)
# tier:          micro (compiled, ReleaseFast via build.zig:1940)
#
# Protocol: 1 discarded warmup + 10 measured rounds (default bench-optimize settings).
# Each invocation builds from a clean cache (see `rm` line) and writes its own
# ResultDocument JSON. Post-processing aggregates medians across rounds.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Clean build state (both dirs are gitignored; zig rebuilds from source)
rm -rf zig-out .zig-cache

# --- Warmup (discarded) ---
zig build bench -- --suite=send_buffer_alloc \
    --output=docs/performance/2026-04-21-send-buffer-alloc-optimize/baseline/raw/warmup_discarded.json

# --- 10 measured rounds ---
for i in 01 02 03 04 05 06 07 08 09 10; do
    zig build bench -- --suite=send_buffer_alloc \
        --output=docs/performance/2026-04-21-send-buffer-alloc-optimize/baseline/raw/round_${i}.json
done
