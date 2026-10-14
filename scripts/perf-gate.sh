#!/usr/bin/env bash
# scripts/perf-gate.sh
# Unified tiered performance gate for zig-quic.
#
# Replaces (and absorbs the contracts of):
#   - scripts/perf_gate.sh               (absolute gates: varint/pacing/hp/alloc
#                                         -> now in benchmarks/compare.zig's
#                                         absolute_gates table)
#   - scripts/perf_udp_batch_gate.sh     (batch vs single ratio -> implemented
#                                         below as a post-compare jq check)
#
# Three invocation modes:
#
#   1. Paired-commit (recommended):
#      scripts/perf-gate.sh --baseline-commit=<sha> [--suite=<name>]
#        Checks out <sha> in a temp git worktree, builds + runs the suite
#        there to capture baseline JSON, then runs the same suite on the
#        working-tree HEAD and invokes `zig build bench-compare`.
#        Cleans up the worktree on exit. PERF_GATE_ROUNDS=N (default 1)
#        captures both sides N times, alternating which side runs first
#        (odd rounds: baseline then HEAD; even rounds: HEAD then baseline),
#        so a slower second slot (turbo decay, a neighbour waking up)
#        cannot bias one side. Every round stays a real paired
#        observation; nothing is merged across rounds. All pairs go to a
#        single `bench-compare` call, which FAILs a row only when the
#        regression reproduces: every HEAD round is worse than every
#        baseline round, and the median change exceeds the threshold and
#        the absolute floor. See "Noise tolerance" in
#        docs/PERFORMANCE_TARGETS.md.
#
#   2. Manual (two pre-captured JSONs):
#      scripts/perf-gate.sh --baseline=<path.json> --current=<path.json>
#        Direct compare without re-running. If --current is omitted and
#        --baseline points at benchmarks/results/baseline.json, the script
#        runs the current HEAD and compares.
#
#   3. Phased (legacy phase naming, retrofit for step-by-step workflows):
#      scripts/perf-gate.sh <step-name> <before|after>
#        `before` captures baseline JSON to
#          benchmarks/results/paired/<step>-before.json.
#        `after` captures current JSON to
#          benchmarks/results/paired/<step>-after.json and writes a
#          markdown diff to benchmarks/results/paired/<step>-diff.md.
#
# Zig version pinning: every mode resolves zig via `mise x zig@0.16.0 -- zig`
# if mise is on PATH. Falls back to ambient `zig` with a WARNING if its
# version != 0.16.0. Exits 3 if no zig is available.
#
# Exit codes:
#   0  all PASS (including WARN)
#   1  FAIL / ABSOLUTE-FAIL regression
#   2  environment mismatch (from compare.zig) OR invocation error
#   3  missing dependency (zig, jq, etc.)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

RESULTS_DIR="benchmarks/results"
PAIRED_DIR="$RESULTS_DIR/paired"
DEFAULT_BASELINE="$RESULTS_DIR/baseline.json"

log() { echo "[perf-gate] $*" >&2; }
die_invoke() { log "ERROR: $*"; exit 2; }
die_missing() { log "ERROR: $*"; exit 3; }

# ---------------------------------------------------------------------------
# Zig version pinning
# ---------------------------------------------------------------------------
ZIG_RUNNER=()
resolve_zig() {
    if [[ -n "${ZIG:-}" ]]; then
        ZIG_RUNNER=("$ZIG")
        return
    fi
    if command -v mise >/dev/null 2>&1; then
        ZIG_RUNNER=(mise x zig@0.16.0 -- zig)
        return
    fi
    if command -v zig >/dev/null 2>&1; then
        ZIG_RUNNER=(zig)
        local actual
        actual="$(zig version 2>/dev/null || echo unknown)"
        if [[ "$actual" != "0.16.0" ]]; then
            log "WARNING: ambient zig is $actual, project requires 0.16.0. Numbers may not compare cleanly."
        fi
        return
    fi
    die_missing "no zig found. Install mise + zig@0.16.0, or set ZIG=/path/to/zig."
}

require_jq() {
    command -v jq >/dev/null 2>&1 || die_missing "jq is required (apt-get install jq / brew install jq)."
}

# ---------------------------------------------------------------------------
# Bench capture
# ---------------------------------------------------------------------------
# run_bench <suite> <out.json>
run_bench() {
    local suite="$1"
    local out="$2"
    mkdir -p "$(dirname "$out")"
    log "running zig build bench --suite=$suite --output=$out"
    "${ZIG_RUNNER[@]}" build bench -- --suite="$suite" --output="$out"
}

# ---------------------------------------------------------------------------
# Post-compare ratio gate (absorbs scripts/perf_udp_batch_gate.sh).
# compare.zig handles per-variant regression; this handles the cross-variant
# ratio (batch/single throughput speedup on integration/udp_batch). Runs on
# Linux only; skipped on macOS/Windows where sendmmsg is unavailable and the
# udp_batch bench emits placeholder rows.
# ---------------------------------------------------------------------------
UDP_BATCH_SPEEDUP_MIN="${UDP_BATCH_SPEEDUP_MIN:-0.95}"

udp_batch_ratio_gate() {
    local current_json="$1"
    if [[ "$(uname -s)" != "Linux" ]]; then
        log "udp-batch ratio gate: non-Linux host, skipping."
        return 0
    fi
    if [[ ! -f "$current_json" ]]; then
        log "udp-batch ratio gate: $current_json not found, skipping."
        return 0
    fi
    require_jq

    local single batch
    single="$(jq -r '
        [.rows[]? | select(.scenario_name == "integration/udp_batch" and .variant == "single") | .throughput_ops_per_sec][0] // empty
    ' "$current_json")"
    batch="$(jq -r '
        [.rows[]? | select(.scenario_name == "integration/udp_batch" and .variant == "batch") | .throughput_ops_per_sec][0] // empty
    ' "$current_json")"

    if [[ -z "$single" || -z "$batch" || "$single" == "null" || "$batch" == "null" ]]; then
        log "udp-batch ratio gate: single/batch rows not found in $current_json, skipping."
        return 0
    fi

    local speedup
    speedup="$(awk -v b="$batch" -v s="$single" 'BEGIN { if (s == 0) { print 9999 } else { printf "%.4f", b / s } }')"
    log "udp-batch ratio gate: single=$single batch=$batch speedup=$speedup (min=$UDP_BATCH_SPEEDUP_MIN)"

    if awk -v v="$speedup" -v min="$UDP_BATCH_SPEEDUP_MIN" 'BEGIN { exit !(v >= min) }'; then
        log "udp-batch ratio gate: PASS"
        return 0
    fi
    log "udp-batch ratio gate: FAIL (speedup $speedup < $UDP_BATCH_SPEEDUP_MIN)"
    return 1
}

# ---------------------------------------------------------------------------
# Compare two captured JSON files via `zig build bench-compare`.
# Returns compare.zig's exit code verbatim.
# ---------------------------------------------------------------------------
run_compare() {
    local baseline="$1"
    local current="$2"
    [[ -f "$baseline" ]] || die_invoke "baseline JSON not found: $baseline"
    [[ -f "$current" ]] || die_invoke "current JSON not found: $current"

    log "running bench-compare --baseline=$baseline --current=$current"
    local compare_rc=0
    "${ZIG_RUNNER[@]}" build bench-compare -- --baseline="$baseline" --current="$current" || compare_rc=$?
    log "bench-compare exit=$compare_rc"

    # Run ratio gate on the CURRENT JSON (batch vs single on this host).
    local ratio_rc=0
    udp_batch_ratio_gate "$current" || ratio_rc=$?

    if [[ $compare_rc -ne 0 ]]; then
        return $compare_rc
    fi
    if [[ $ratio_rc -ne 0 ]]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Multi-round compare: one bench-compare call with every round's pair, so
# compare.zig can require a regression to reproduce across rounds. The
# udp-batch ratio gate runs per round and fails only when a strict
# majority of rounds fail it (it is a ratio within one capture, so there
# is no baseline side to separate from).
# args: <baseline1> <current1> [<baseline2> <current2> ...]
# ---------------------------------------------------------------------------
run_compare_rounds() {
    local -a compare_args=()
    local -a currents=()
    while [[ $# -ge 2 ]]; do
        [[ -f "$1" ]] || die_invoke "baseline JSON not found: $1"
        [[ -f "$2" ]] || die_invoke "current JSON not found: $2"
        compare_args+=("--baseline=$1" "--current=$2")
        currents+=("$2")
        shift 2
    done
    local rounds=${#currents[@]}

    log "running bench-compare over $rounds paired rounds"
    local compare_rc=0
    "${ZIG_RUNNER[@]}" build bench-compare -- "${compare_args[@]}" || compare_rc=$?
    log "bench-compare exit=$compare_rc"

    local ratio_fails=0 current
    for current in "${currents[@]}"; do
        udp_batch_ratio_gate "$current" || ratio_fails=$((ratio_fails + 1))
    done
    if [[ $ratio_fails -gt 0 ]]; then
        log "udp-batch ratio gate: failed in $ratio_fails/$rounds rounds"
    fi

    if [[ $compare_rc -ne 0 ]]; then
        return $compare_rc
    fi
    if [[ $((ratio_fails * 2)) -gt $rounds ]]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Mode 1: Paired-commit (temp worktree for baseline capture)
# ---------------------------------------------------------------------------
mode_paired_commit() {
    local baseline_ref="$1"
    local suite="$2"

    git rev-parse --verify "$baseline_ref^{commit}" >/dev/null 2>&1 \
        || die_invoke "baseline commit '$baseline_ref' not found."

    local sha short_sha worktree
    sha="$(git rev-parse "$baseline_ref^{commit}")"
    short_sha="${sha:0:8}"
    worktree="$(mktemp -d -t "perf-gate-$short_sha-XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$worktree'; git worktree prune >/dev/null 2>&1 || true" EXIT

    log "creating worktree $worktree at $short_sha"
    git worktree add --detach "$worktree" "$sha" >/dev/null

    local baseline_json current_json
    baseline_json="$PAIRED_DIR/$short_sha-baseline.json"
    current_json="$PAIRED_DIR/HEAD-current.json"
    mkdir -p "$PAIRED_DIR"

    # Keep each round as a paired observation. Selecting the best throughput
    # and lowest latency across different rounds can invent a measurement
    # that never occurred, so rounds are never merged. Instead compare.zig
    # sees every pair and fails a row only if its regression reproduces
    # across rounds (every HEAD round worse than every baseline round, and
    # a median change beyond threshold and floor). On the shared CI runners
    # a single round flags 1-10 random rows per run (different rows each
    # time) while a real regression shifts every round.
    local rounds="${PERF_GATE_ROUNDS:-1}"
    [[ "$rounds" =~ ^[1-9][0-9]*$ ]] || die_invoke "PERF_GATE_ROUNDS must be a positive integer, got '$rounds'."

    if [[ "$rounds" -eq 1 ]]; then
        log "capturing baseline ($short_sha) — suite=$suite"
        (cd "$worktree" && "${ZIG_RUNNER[@]}" build bench -- --suite="$suite" --output="$PROJECT_ROOT/$baseline_json")

        log "capturing current (HEAD) — suite=$suite"
        run_bench "$suite" "$current_json"
    else
        local r round_baseline round_current
        local -a pairs=()
        for ((r = 1; r <= rounds; r++)); do
            round_baseline="$PAIRED_DIR/$short_sha-baseline.r$r.json"
            round_current="$PAIRED_DIR/HEAD-current.r$r.json"
            if ((r % 2 == 1)); then
                log "round $r/$rounds: capturing baseline ($short_sha) first — suite=$suite"
                (cd "$worktree" && "${ZIG_RUNNER[@]}" build bench -- --suite="$suite" --output="$PROJECT_ROOT/$round_baseline")
                log "round $r/$rounds: capturing current (HEAD) — suite=$suite"
                run_bench "$suite" "$round_current"
            else
                log "round $r/$rounds: capturing current (HEAD) first — suite=$suite"
                run_bench "$suite" "$round_current"
                log "round $r/$rounds: capturing baseline ($short_sha) — suite=$suite"
                (cd "$worktree" && "${ZIG_RUNNER[@]}" build bench -- --suite="$suite" --output="$PROJECT_ROOT/$round_baseline")
            fi
            pairs+=("$round_baseline" "$round_current")
        done
        run_compare_rounds "${pairs[@]}"
        return $?
    fi

    run_compare "$baseline_json" "$current_json"
}

# ---------------------------------------------------------------------------
# Mode 2: Manual (pre-captured JSONs, or current-HEAD vs baseline path)
# ---------------------------------------------------------------------------
mode_manual() {
    local baseline="$1"
    local current="$2"
    local suite="$3"

    if [[ -z "$current" ]]; then
        current="$PAIRED_DIR/HEAD-current.json"
        log "--current omitted; capturing current HEAD to $current"
        run_bench "$suite" "$current"
    fi
    run_compare "$baseline" "$current"
}

# ---------------------------------------------------------------------------
# Mode 3: Phased (<step-name> before|after)
# ---------------------------------------------------------------------------
mode_phased() {
    local step="$1"
    local phase="$2"
    local suite="$3"

    [[ "$phase" == "before" || "$phase" == "after" ]] \
        || die_invoke "phase must be 'before' or 'after', got '$phase'."

    mkdir -p "$PAIRED_DIR"
    local before_json after_json diff_md
    before_json="$PAIRED_DIR/$step-before.json"
    after_json="$PAIRED_DIR/$step-after.json"
    diff_md="$PAIRED_DIR/$step-diff.md"

    if [[ "$phase" == "before" ]]; then
        log "phased $step before: capturing baseline"
        run_bench "$suite" "$before_json"
        log "phased $step before: wrote $before_json"
        return 0
    fi

    # phase == after
    [[ -f "$before_json" ]] || die_invoke "missing $before_json — run '$step before' first."
    log "phased $step after: capturing current"
    run_bench "$suite" "$after_json"

    # Run compare (prints the standard status table) and ratio gate.
    local compare_rc=0
    run_compare "$before_json" "$after_json" || compare_rc=$?

    # Emit a markdown diff (always; independent of pass/fail status so
    # reviewers have a receipt either way).
    require_jq
    {
        echo "# Perf diff — $step"
        echo
        echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Baseline: $before_json"
        echo "Current:  $after_json"
        echo
        echo "## Rows (suite=$suite)"
        echo
        echo "| scenario | variant | ops/s before | ops/s after | d % | p95 before (ns) | p95 after (ns) | d p95 % |"
        echo "|---|---|---:|---:|---:|---:|---:|---:|"
        jq -r --slurpfile bef "$before_json" '
            .rows as $aft
          | ($bef[0].rows // []) as $bfr
          | $aft[]
          | . as $a
          | ($bfr | map(select(.scenario_name == $a.scenario_name and .variant == $a.variant))) as $matches
          | if ($matches | length) == 0 then
              [$a.scenario_name, $a.variant, "n/a", ($a.throughput_ops_per_sec|tostring), "n/a", "n/a", ($a.latency_p95_ns|tostring), "n/a"]
            else
              $matches[0] as $b
              | [
                  $a.scenario_name,
                  $a.variant,
                  ($b.throughput_ops_per_sec | tostring),
                  ($a.throughput_ops_per_sec | tostring),
                  (if $b.throughput_ops_per_sec == 0 then "div/0"
                   else (((($a.throughput_ops_per_sec - $b.throughput_ops_per_sec) / $b.throughput_ops_per_sec) * 100) | tostring) + "%"
                   end),
                  ($b.latency_p95_ns | tostring),
                  ($a.latency_p95_ns | tostring),
                  (if $b.latency_p95_ns == 0 then "div/0"
                   else (((($a.latency_p95_ns - $b.latency_p95_ns) / $b.latency_p95_ns) * 100) | tostring) + "%"
                   end)
                ]
            end
          | "| " + join(" | ") + " |"
        ' "$after_json"
        echo
        echo "## Review checklist"
        echo
        echo "Per plan thresholds (docs/superpowers/plans/2026-04-20-perf-bench-suite-and-gating.md):"
        echo "- Throughput regression beyond tier budget -> FAIL."
        echo "- p95 latency regression beyond tier budget -> FAIL."
        echo "- Absolute gates (varint/pacing/hp/alloc) enforced by compare.zig."
        echo "- UDP batch/single speedup < ${UDP_BATCH_SPEEDUP_MIN}x -> FAIL."
    } > "$diff_md"
    log "wrote diff to $diff_md"

    return $compare_rc
}

# ---------------------------------------------------------------------------
# Arg parse + dispatch
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF >&2
Usage:
  scripts/perf-gate.sh --baseline-commit=<sha> [--suite=<name>]
  scripts/perf-gate.sh --baseline=<path.json> [--current=<path.json>] [--suite=<name>]
  scripts/perf-gate.sh <step-name> <before|after> [--suite=<name>]

Environment:
  ZIG=<path>                  override zig binary (bypasses mise)
  UDP_BATCH_SPEEDUP_MIN=0.95  batch/single throughput ratio floor
  PERF_GATE_ROUNDS=1          paired rounds for --baseline-commit (alternating
                              order; a row fails only if it reproduces)
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 2
fi

BASELINE_COMMIT=""
BASELINE_PATH=""
CURRENT_PATH=""
SUITE="all"
POSITIONAL=()

for arg in "$@"; do
    case "$arg" in
        --baseline-commit=*) BASELINE_COMMIT="${arg#*=}" ;;
        --baseline=*)        BASELINE_PATH="${arg#*=}" ;;
        --current=*)         CURRENT_PATH="${arg#*=}" ;;
        --suite=*)           SUITE="${arg#*=}" ;;
        -h|--help)           usage; exit 0 ;;
        --*)                 die_invoke "unknown flag: $arg" ;;
        *)                   POSITIONAL+=("$arg") ;;
    esac
done

resolve_zig

if [[ -n "$BASELINE_COMMIT" ]]; then
    [[ ${#POSITIONAL[@]} -eq 0 ]] || die_invoke "positional args not allowed with --baseline-commit"
    [[ -z "$BASELINE_PATH" && -z "$CURRENT_PATH" ]] || die_invoke "--baseline/--current not allowed with --baseline-commit"
    mode_paired_commit "$BASELINE_COMMIT" "$SUITE"
    exit $?
fi

if [[ -n "$BASELINE_PATH" ]]; then
    [[ ${#POSITIONAL[@]} -eq 0 ]] || die_invoke "positional args not allowed with --baseline"
    mode_manual "$BASELINE_PATH" "$CURRENT_PATH" "$SUITE"
    exit $?
fi

if [[ ${#POSITIONAL[@]} -eq 2 ]]; then
    mode_phased "${POSITIONAL[0]}" "${POSITIONAL[1]}" "$SUITE"
    exit $?
fi

# --current alone with default baseline
if [[ -n "$CURRENT_PATH" && -f "$DEFAULT_BASELINE" ]]; then
    mode_manual "$DEFAULT_BASELINE" "$CURRENT_PATH" "$SUITE"
    exit $?
fi

usage
exit 2
