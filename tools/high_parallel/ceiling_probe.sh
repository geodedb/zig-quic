#!/usr/bin/env bash
set -u

usage() {
    cat <<'EOF'
usage: ceiling_probe.sh [local|docker] [sizes...]

Runs the high-parallel scale regression at increasing connection counts and
stops on the first failing size. If no sizes are provided, it uses
QUIC_CEILING_SIZES or a conservative default sweep.

Environment:
  QUIC_HEAVY_DURATION_MS     sustained dirty/poll window, default 1000
  QUIC_HEAVY_DIRTY_THREADS   dirty worker threads, default 8
  QUIC_HEAVY_DIRTY_ROUNDS    minimum dirty rounds, default 8
  QUIC_CEILING_SIZES         space-separated sizes when no CLI sizes are given
  QUIC_CEILING_LOG           output log path
EOF
}

mode="${1:-local}"
case "$mode" in
    local|docker)
        shift || true
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        echo "unknown mode: $mode" >&2
        usage >&2
        exit 2
        ;;
esac

if [ "$#" -gt 0 ]; then
    sizes=("$@")
else
    # shellcheck disable=SC2206
    sizes=(${QUIC_CEILING_SIZES:-20000 50000 100000 200000 300000})
fi

duration_ms="${QUIC_HEAVY_DURATION_MS:-1000}"
dirty_threads="${QUIC_HEAVY_DIRTY_THREADS:-8}"
dirty_rounds="${QUIC_HEAVY_DIRTY_ROUNDS:-8}"
log_path="${QUIC_CEILING_LOG:-/tmp/quic-high-parallel-ceiling-$(date +%Y%m%d-%H%M%S).log}"

highest=0
failed_at=0

run_local() {
    local count="$1"
    env \
        QUIC_HEAVY_SCALE=1 \
        QUIC_HEAVY_CONNECTIONS="$count" \
        QUIC_HEAVY_DURATION_MS="$duration_ms" \
        QUIC_HEAVY_DIRTY_THREADS="$dirty_threads" \
        QUIC_HEAVY_DIRTY_ROUNDS="$dirty_rounds" \
        zig build test -Dtest-filter=high_parallel_scale
}

run_docker() {
    local count="$1"
    env \
        QUIC_HEAVY_CONNECTIONS="$count" \
        QUIC_HEAVY_DURATION_MS="$duration_ms" \
        QUIC_HEAVY_DIRTY_THREADS="$dirty_threads" \
        QUIC_HEAVY_DIRTY_ROUNDS="$dirty_rounds" \
        docker compose -f tools/high_parallel/docker-compose.yml up \
            --build \
            --abort-on-container-exit \
            --exit-code-from high-parallel-scale
}

cleanup() {
    if [ "$mode" = "docker" ]; then
        docker compose -f tools/high_parallel/docker-compose.yml down -v >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

{
    echo "mode=$mode"
    echo "duration_ms=$duration_ms dirty_threads=$dirty_threads dirty_rounds=$dirty_rounds"
    echo "sizes=${sizes[*]}"
    echo "log_path=$log_path"
} | tee "$log_path"

for count in "${sizes[@]}"; do
    start_s="$(date +%s)"
    echo "==> start count=$count at $(date -Is)" | tee -a "$log_path"

    if [ "$mode" = "docker" ]; then
        cleanup
        if run_docker "$count" >>"$log_path" 2>&1; then
            cleanup
            status=0
        else
            cleanup
            status=$?
        fi
    else
        if run_local "$count" >>"$log_path" 2>&1; then
            status=0
        else
            status=$?
        fi
    fi

    end_s="$(date +%s)"
    elapsed=$((end_s - start_s))
    if [ "$status" -eq 0 ]; then
        highest="$count"
        echo "PASS count=$count elapsed_s=$elapsed" | tee -a "$log_path"
    else
        failed_at="$count"
        echo "FAIL count=$count elapsed_s=$elapsed status=$status" | tee -a "$log_path"
        break
    fi
done

echo "highest_passed=$highest failed_at=$failed_at log_path=$log_path" | tee -a "$log_path"

if [ "$failed_at" -ne 0 ]; then
    exit 1
fi
