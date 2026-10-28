# Performance Targets

Last updated: 2026-04-20

## Tier Threshold Table (v2 — 2026-04-20)

Relative regression thresholds applied by `scripts/perf-gate.sh` +
`benchmarks/compare.zig`. A scenario FAILs if the observed delta exceeds
the tier %-threshold **and** the 3× baseline-stddev noise floor **and**
the tier's absolute noise floor, and (with several paired rounds) the
regression reproduces across rounds; see [Noise tolerance](#noise-tolerance). The
`wait_bound_fraction_permille` column is an annotation-only budget
(logged, not gated) for integration scenarios that track how much of the
total wall-clock sat in `poll`-bound waits vs. the inner hot path.

| Tier | Throughput regression | Latency p95 regression | Allocation regression | Noise floor | Absolute floor | wait_bound_fraction_permille |
|---|---|---|---|---|---|---|
| Micro (`micro/`) | -15% | -10% | Zero-delta hard gate | 3x stddev | p95 > 3 ns, per-op > 1 ns | -100‰ |
| Integration (`integration/`) | -20% | -25% | -30% | 3x stddev | 0 | -200‰ |
| External (`external/`) | -25% | -30% | N/A | 3x stddev | 0 | -300‰ |

Micro-tier scenarios may ALSO carry absolute gates; see
"CI Performance Budgets" below. Absolute gates trigger ABSOLUTE-FAIL
regardless of baseline delta.

## Purpose

This document defines the repository's minimum performance contract for QUIC hot paths and CI regression gating.

## Workload Profiles

The repository uses these bounded reference profiles for regression checks:

1. Microbench profile (CI-safe)

- Command: `zig build bench`
- Focus: packet encode/decode hot path, pacing arithmetic, header-protection decode path.
- Data sizes: short-header payloads and handshake payloads used by `bench/main.zig`.

1. Functional profile (correctness under performance changes)

- Command: `zig build test`
- Focus: protocol correctness and no-regression behavior with optimized code paths.

1. Full graph profile (periodic)

- Command: `zig build -Dfull-test-graph=true test`
- Focus: broad integration coverage for refactors touching core packet/recovery/transport code.

## CI Performance Budgets

`scripts/perf-gate.sh` is the unified tiered A/B regression gate (Phase 7
Task 7.1). It runs `zig build bench` to capture current-HEAD JSON and
invokes `zig build bench-compare` against
`benchmarks/results/baseline.json`. Absolute upper bounds are enforced by
`benchmarks/compare.zig`'s `absolute_gates` table:

- `micro/varint / encode` — `latency_p99_ns <= 250`
- `micro/pacing / delay_compute` — `latency_p99_ns <= 400`
- `micro/header_protection / decode` — `latency_p99_ns <= 400000`
- `micro/frame_serialization / short_header_encode` — `alloc_bytes == 0`
- `micro/frame_serialization / short_header_decode` — `alloc_bytes == 0`

Note: `micro/send_buffer_alloc` measures the `ArrayList(u8)` growth in the
packet-assembly layer (issue #163) and intentionally does NOT carry an
absolute gate. `alloc_bytes` is non-zero at the current baseline (see
"Integration Tier Targets" table below for per-variant baseline numbers),
so any absolute gate would perma-fail. A future #163 fix that replaces
the per-call `ArrayList.empty` with a preallocated reusable buffer will
show up as a negative delta through the standard micro-tier threshold
gate (-15% significant, -10% pass/warn, zero-delta hard gate).

Thresholds are intentionally conservative to avoid host-noise flakiness
while still catching material regressions.

## Noise tolerance

The CI gate (`quality-zig-gates`) runs `--suite=micro` in paired-commit
mode on shared AWS Spot runners with `PERF_GATE_ROUNDS=5`. Under the old
rule (any round that FAILs any row fails the job) it failed on almost
every run from June to October 2026, each time on different rows: p95
values moving by 1 ns on 5-20 ns rows, and random 10-250% swings on
single rounds. Two mechanisms now separate that noise from regressions.

1. **Absolute floors** (`latency_floor_ns`, `throughput_floor_ns` in
   `benchmarks/compare.zig`). A p95 regression only counts when the p95
   grew by **more than 3 ns**; a throughput regression only counts when
   the per-op time (`1e9 / ops_per_sec`) grew by **more than 1 ns**.
   Micro latencies are batch-averaged over 256 ops and truncated to
   whole nanoseconds, so a single quantum is +5-20% on a 5-20 ns row
   (p95 floor = three quanta). Throughput is the median of six timed runs
   and is not quantised; its 1 ns floor keeps 1-2 ns ops (`varint`,
   `pacing`) from failing on sub-nanosecond code-alignment shifts. The
   %-thresholds still apply in full above the floors, so a 1000 ns row
   still fails at +10%. Rows that breach a %-threshold but stay inside
   the floor print as `NOISE` and do not gate. Integration and external
   tiers keep floors of 0.
2. **Reproduction across alternating rounds.** With `PERF_GATE_ROUNDS=N`
   (N > 1), `scripts/perf-gate.sh` captures N baseline/HEAD pairs,
   alternating which side runs first, and passes all pairs to one
   `bench-compare` call. A row FAILs only if **every HEAD round is worse
   than every baseline round** (the two sides' ranges do not overlap; an
   exact one-sided rank test at p = 1/20 for 3 rounds per side and
   p = 1/252 for 5)
   **and** the median-to-median change exceeds the tier %-threshold and
   the absolute floor. A single noisy round, or a tail latency that
   flips between modes on a shared runner (e.g.
   `send_buffer_alloc/multi_stream_batch` p95 194/272/199 ns vs
   192/374/374 ns on identical sources), overlaps the other side and
   cannot fail the gate. `ABSOLUTE-FAIL` needs a strict majority of
   rounds, and so does the UDP batch ratio gate; `WAIT-BOUND-FAIL` uses
   the same separation rule. Rounds are never merged into a synthetic
   best-of row; each round's own table is still printed. With one round
   the verdict is that round's verdict.

   CI uses **5 rounds**. The micro suite checks about 70 row/metric pairs
   per run, so at 3 rounds (p = 1/20 each) a few pairs separate by chance
   on identical code, and after the thresholds that still produced a
   false FAIL in about half of the runs (main schedule 2948905825:
   `frame_serialization/ack` p95 455 -> 1078 ns in all three rounds on
   unchanged bench sources; MRs !76 and !80 on `connection_lookup/1000`
   and `aead/chacha20_poly1305`, code neither touches). At 5 rounds
   chance separation drops to 1/252 per pair, about 0.3 pairs per run
   before the thresholds apply.

Self-test: `zig build test-bench-compare` (run by `quality-zig-gates`
before the gate) replays the per-round rows from four CI jobs that failed
on noise (`tests/fixtures/perf_gate_ci_noise.tsv`, 140 rows x 3 rounds)
and requires all of them to pass. It then injects a regression into the
recorded HEAD side in every round: +25% must fail on representative rows
of every micro family in every job, and +50% must be caught on at least
95% of rows above the floor (132/132 when written; +25%: 116/132; +15%:
81/132, since a change smaller than the runner's round-to-round spread
cannot be separated from noise with three rounds; five rounds narrow
both ranges). `scripts/test_perf_rounds.py` covers the shell
driver (alternating order, every pair compared, no synthesized rows).

`scripts/perf-gate.sh` also enforces the Linux UDP batching guardrail as
a post-compare ratio check (absorbed from the retired
`scripts/perf_udp_batch_gate.sh`):

- Reads `integration/udp_batch` rows for `single` + `batch` variants
- Computes `speedup = batch / single` (throughput_ops_per_sec)
- Requires `speedup >= 0.95x` (default; override via
  `UDP_BATCH_SPEEDUP_MIN=<float>`)
- Skipped on non-Linux hosts (bench emits placeholder rows there)

`scripts/cross_platform_udp_batch_smoke.sh` enforces compile-only
portability guardrails for the batched transport path by driving the
`zig build cross-smoke` step (see `build.zig:cross_smoke_step`):

- Compiles `src/quic/endpoint/transport.zig`,
  `src/quic/endpoint/udp_transport.zig`, and `src/quic/endpoint.zig` via
  `addObject` (no linking) for each target
- Targets matrix:
  - `x86_64-macos-none`
  - `aarch64-macos-none`
  - `x86_64-windows-gnu`
  - `aarch64-windows-gnu`
- Verifies that Linux batched syscalls remain behind fallback-safe
  abstractions and compile cleanly for non-Linux targets

Native runtime smoke coverage is also available on non-Linux runners:

- `runtime-smoke-macos` (tags: `dedicated`, `macos`, `arm`; the devnw dedicated Apple Silicon runners)
- `runtime-smoke-windows-saas` (tag: `saas-windows-medium-amd64`)
- Both run `src/quic/endpoint/test_udp_batch_runtime_smoke.zig` via:
  - `scripts/native_runtime_smoke.sh` (macOS)
  - `scripts/native_runtime_smoke.ps1` (Windows)
- Enable by setting CI variable `ENABLE_NATIVE_RUNTIME_SMOKE=true`

## Validation Commands

- Unified perf gate (manual mode): `scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json`
- Unified perf gate (paired-commit mode): `scripts/perf-gate.sh --baseline-commit=<sha>`
- Unified perf gate (phased mode): `scripts/perf-gate.sh <step-name> before` then `... after`
- Local cross-platform compile matrix gate: `scripts/cross_platform_udp_batch_smoke.sh`
- Native runtime smoke (portable): `zig build test -- --test-filter udp_batch_runtime_smoke`
- Baseline bench JSON capture: `zig build bench -- --suite=all --output=benchmarks/results/baseline.json`

## Change Management

Any PR that changes packet encoding/decoding, recovery ACK processing, event-loop polling, or CI benchmark logic must:

1. Run `scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json`.
2. Include updated benchmark evidence in MR notes when thresholds are adjusted.
3. Update this document if workloads or budgets change.

## Integration Tier Targets (Aspirational)

Measured from v2 baseline capture (2026-04-20). Revised only alongside a
`docs/PERFORMANCE_TRACKING.md` entry explaining the change.

| Scenario | Variant | Target | Measured at baseline |
|---|---|---|---|
| `integration/poll_overhead` | `100c` | p99 < 50µs | p99=8µs (well under target; #182 still manifests at 10Kc) |
| `integration/poll_overhead` | `10Kc` | p99 < 500µs (post-#182 fix) | p99=674µs (currently exceeds; regression-gate tracks) |
| `integration/conn_scale` | `1c` | > 10K handshakes/sec (loopback, no TLS) | 361M ops/s (iter-normalized setup throughput, not true handshake rate — see file doc) |
| `integration/handshake_e2e` | `serial` | > 500 handshakes/sec | 382 hs/s (under target; full TLS 1.3 handshake overhead) |
| `integration/handshake_e2e` | `10p` | p99 < 20ms | p99=14.8ms (under target) |
| `integration/stream_throughput` | `1KB-c1` | > 100 MB/s | 5562 ops/s × 1KB ≈ 5.6 MB/s (under target; server-thread bound — see file doc) |
| `integration/datagram_batch` | `batch_16` | mutex_hold <= 2x `batch_1` (post-#126 fix) | mutex_hold_wall_ns ratio currently ~3x (tracks #126 signal) |
| `integration/flush_cadence` | `burst_flush` | burst / single ratio <= 1.5x (post-flush-cadence fix, geode) | *currently 9.85x* |
| `integration/udp_batch` | `batch` | syscall reduction >= 4.0x vs `single` | *preserved from legacy `perf_udp_batch_gate.sh`* |
| `integration/udp_batch` | `batch` | throughput speedup >= 0.95x vs `single` | *preserved from legacy `perf_udp_batch_gate.sh`* |
| `micro/send_buffer_alloc` | `stream_only` | `alloc_bytes` ↘ 0 post-#163 fix | `alloc_count=1`, `alloc_bytes=129` per op at 2026-04-20 baseline |
| `micro/send_buffer_alloc` | `stream_plus_ack` | `alloc_bytes` ↘ 0 post-#163 fix | `alloc_count=1`, `alloc_bytes=129` per op |
| `micro/send_buffer_alloc` | `crypto_handshake` | `alloc_bytes` ↘ 0 post-#163 fix | `alloc_count=5`, `alloc_bytes=1097` per op (includes `encodeInitialProtected` output buffer) |
| `micro/send_buffer_alloc` | `initial_padded` | `alloc_bytes` ↘ 0 post-#163 fix | `alloc_count=6`, `alloc_bytes=3382` per op (CRYPTO + PADDING to 1024B plaintext + protected buffer) |
| `micro/send_buffer_alloc` | `pto_probe` | `alloc_bytes` ↘ 0 post-#163 fix | `alloc_count=5`, `alloc_bytes=3382` per op (PING + PADDING + protected buffer) |
| `micro/send_buffer_alloc` | `multi_stream_batch` | `alloc_bytes` ↘ 0 post-#163 fix | `alloc_count=2`, `alloc_bytes=343` per op (4× STREAM frame growth) |

## External Tier Targets (Informational)

Cross-implementation comparison. External targets are **not gated
independently** of the tier-% + noise-floor regression rule. Populated
at the 2026-04-20 re-capture (commit `9cbf3ac` era). Numbers reflect
full-suite context (external handshakes run AFTER integration tier
saturates FDs/CPU, producing ~10× slower latencies than isolated-tier
runs — honest measurement, not noise).

| Scenario | Variant | Measured p50 | Notes |
|---|---|---|---|
| `external/quic-go/handshake` | `loopback` | 1285 ms | Median handshake time vs. quic-go (isolated: 109 ms) |
| `external/quinn/handshake` | `loopback` | 1298 ms | Median handshake time vs. quinn (isolated: 103 ms) |
| `external/aioquic/handshake` | `loopback` | 1533 ms | Median handshake time vs. aioquic (isolated: 335 ms) |

## Revision Protocol (v2)

Targets in this document are revised only when all three of the
following hold:

1. A `docs/PERFORMANCE_TRACKING.md` decision-log entry explains the
   reason (new measurement reveals tighter achievable target; platform
   change invalidates the prior number; fixed issue closes the
   regression that motivated a wider threshold; etc.).
2. A fresh baseline is captured AFTER the revision and committed to
   `benchmarks/results/baseline.json`.
3. The MR body includes the `scripts/perf-gate.sh` diff table and links
   to the `docs/PERFORMANCE_TRACKING.md` entry.

"Temporary" waivers are not permitted. If a target cannot be met, revise
it; do not bypass the gate.
