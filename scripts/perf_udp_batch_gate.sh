#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[udp-batch-gate] Non-Linux host detected; skipping."
  exit 0
fi

ITERS=${UDP_BATCH_ITERS:-20000}
BATCH=${UDP_BATCH_BATCH:-16}
PAYLOAD=${UDP_BATCH_PAYLOAD:-1200}
SYSCALL_REDUCTION_MIN=${UDP_BATCH_SYSCALL_REDUCTION_MIN:-4.0}
SPEEDUP_MIN=${UDP_BATCH_SPEEDUP_MIN:-0.95}

cmd=(zig run bench/udp_batch_bench.zig -- --mode both --iters "$ITERS" --batch "$BATCH" --payload "$PAYLOAD")
echo "[udp-batch-gate] Running: ${cmd[*]}"

out="$("${cmd[@]}" 2>&1)"
echo "$out"

single_spp="$(awk -F'syscalls_per_packet=' '/mode=single/{print $2}' <<<"$out" | awk '{print $1}' | head -n1)"
batch_spp="$(awk -F'syscalls_per_packet=' '/mode=batch/{print $2}' <<<"$out" | awk '{print $1}' | head -n1)"
speedup="$(awk -F'speedup=' '/comparison/{print $2}' <<<"$out" | awk '{print $1}' | head -n1)"

if [[ -z "${single_spp}" || -z "${batch_spp}" || -z "${speedup}" ]]; then
  echo "[udp-batch-gate] Failed to parse benchmark output" >&2
  exit 1
fi

syscall_reduction="$(awk -v s="$single_spp" -v b="$batch_spp" 'BEGIN { if (b == 0) { print 9999 } else { printf "%.4f", s / b } }')"
echo "[udp-batch-gate] single_spp=${single_spp} batch_spp=${batch_spp} reduction=${syscall_reduction} speedup=${speedup}"

awk -v r="$syscall_reduction" -v min="$SYSCALL_REDUCTION_MIN" 'BEGIN { exit !(r >= min) }' || {
  echo "[udp-batch-gate] syscall reduction regression: ${syscall_reduction} < ${SYSCALL_REDUCTION_MIN}" >&2
  exit 1
}

awk -v s="$speedup" -v min="$SPEEDUP_MIN" 'BEGIN { exit !(s >= min) }' || {
  echo "[udp-batch-gate] throughput regression: speedup ${speedup} < ${SPEEDUP_MIN}" >&2
  exit 1
}

echo "[udp-batch-gate] PASS"
