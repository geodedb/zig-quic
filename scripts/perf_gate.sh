#!/usr/bin/env bash
# Deterministic performance regression gate for CI.
set -euo pipefail

BENCH_CMD=${BENCH_CMD:-"zig build bench"}
VARINT_NS_MAX=${VARINT_NS_MAX:-250}
PACING_NS_MAX=${PACING_NS_MAX:-400}
HP_DECODE_TOTAL_NS_MAX=${HP_DECODE_TOTAL_NS_MAX:-800000000}
INTO_ALLOCS_MAX=${INTO_ALLOCS_MAX:-0}

bench_log="$(mktemp /tmp/quic-bench-gate.XXXXXX.log)"
trap 'rm -f "$bench_log"' EXIT

echo "[perf-gate] Running benchmark command: ${BENCH_CMD}"
eval "${BENCH_CMD}" 2>&1 | tee "${bench_log}"

extract_first() {
    local pattern="$1"
    local field="$2"
    local line
    line="$(grep -E "${pattern}" "${bench_log}" | head -n 1 || true)"
    if [[ -z "${line}" ]]; then
        echo "[perf-gate] Missing expected benchmark line matching: ${pattern}" >&2
        return 1
    fi
    echo "${line}" | sed -E "${field}"
}

float_gt() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'
}

float_ne() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a != b) }'
}

varint_ns="$(extract_first "^varint encode:" 's/.*: ([0-9]+(\.[0-9]+)?) ns\/op.*/\1/')"
pacing_ns="$(extract_first "^pacing delay compute:" 's/.*: ([0-9]+(\.[0-9]+)?) ns\/op.*/\1/')"
hp_decode_total_ns="$(extract_first "^hp decode timing:" 's/.*: ([0-9]+) ns total.*/\1/')"
into_encode_allocs="$(extract_first "^short-header allocs/op:" 's/.*into encode=([0-9]+(\.[0-9]+)?), into decode=([0-9]+(\.[0-9]+)?).*/\1/')"
into_decode_allocs="$(extract_first "^short-header allocs/op:" 's/.*into encode=([0-9]+(\.[0-9]+)?), into decode=([0-9]+(\.[0-9]+)?).*/\3/')"

echo "[perf-gate] Parsed metrics:"
echo "  varint_ns=${varint_ns} (max ${VARINT_NS_MAX})"
echo "  pacing_ns=${pacing_ns} (max ${PACING_NS_MAX})"
echo "  hp_decode_total_ns=${hp_decode_total_ns} (max ${HP_DECODE_TOTAL_NS_MAX})"
echo "  into_encode_allocs=${into_encode_allocs} (must equal ${INTO_ALLOCS_MAX})"
echo "  into_decode_allocs=${into_decode_allocs} (must equal ${INTO_ALLOCS_MAX})"

if float_gt "${varint_ns}" "${VARINT_NS_MAX}"; then
    echo "[perf-gate] varint encode regression: ${varint_ns} > ${VARINT_NS_MAX}" >&2
    exit 1
fi
if float_gt "${pacing_ns}" "${PACING_NS_MAX}"; then
    echo "[perf-gate] pacing delay compute regression: ${pacing_ns} > ${PACING_NS_MAX}" >&2
    exit 1
fi
if float_gt "${hp_decode_total_ns}" "${HP_DECODE_TOTAL_NS_MAX}"; then
    echo "[perf-gate] hp decode regression: ${hp_decode_total_ns} > ${HP_DECODE_TOTAL_NS_MAX}" >&2
    exit 1
fi
if float_ne "${into_encode_allocs}" "${INTO_ALLOCS_MAX}"; then
    echo "[perf-gate] allocation regression: into encode allocs/op=${into_encode_allocs}" >&2
    exit 1
fi
if float_ne "${into_decode_allocs}" "${INTO_ALLOCS_MAX}"; then
    echo "[perf-gate] allocation regression: into decode allocs/op=${into_decode_allocs}" >&2
    exit 1
fi

echo "[perf-gate] PASS"
