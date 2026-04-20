# Performance Benchmark Suite v2 + Performance-Gating Protocol

**Date:** 2026-04-20
**Status:** Approved (pending spec review)
**Scope:** Consolidate the two fragmented benchmark trees (`bench/`, `benchmarks/`) into a single thread-pool-style suite with paired A/B regression gating, tiered thresholds, external-impl compare, baseline capture on current main, and a performance-gating skill agents are required to follow.
**Supersedes:** `docs/superpowers/specs/2026-03-27-benchmark-system-design.md` (preserves that design's tier structures; replaces scaffolds and minimal harness)
**Extends:** `docs/PERFORMANCE_TARGETS.md` (preserves its absolute-gate section and cross-platform smoke coverage; adds tiered-threshold and integration/external target sections)

---

## Problem

Three overlapping and incomplete benchmark surfaces exist today:

1. **`bench/`** (newer, Apr 2026) — micro-benchmarks for varint/pacing/header-protection/AEAD/TLS-keygen/udp-batch. Wired via `zig build bench` plus ad-hoc gates in `scripts/perf_gate.sh` and `scripts/perf_udp_batch_gate.sh`. Uses absolute-ns thresholds per metric.
2. **`benchmarks/`** (older, Mar 2026) — macro-benchmarks produced by the 2026-03-27 plan: `scale_bench`, `poll_bench`, plus two **scaffolds that emit zero metrics** (`throughput_bench`, `handshake_bench`). Uses a minimal `common.zig` (timer + JSON emitter) and a `compare.zig` with suffix-based regression detection.
3. **`test-clients/{quic-go,quinn,aioquic}-client/`** and `interop/run_endpoint.sh` — functional interop infrastructure, but no benchmark harness wrapping it.

Concrete consequences of the fragmentation:

- Two `common.zig` files with different APIs, so a bench can't span micro + macro.
- No stddev, no median-of-N, no CPU pinning, no peak-RSS tracking — regression detection rides on single-sample comparisons.
- No paired same-session A/B protocol; nothing enforces "capture baseline before the change" vs "after"; MRs have claimed "no regression" based on eyeball.
- Scaffolds with zero metrics create false confidence — `bench-throughput` exits 0 without measuring throughput.
- 14 open P0/P1 performance findings (O(N) connection lookup, unbounded sent_packets, per-frame heap allocs, endpoint mutex hold during 16-datagram batch, no GSO/coalescing) have no dedicated benchmarks — so regressions AND improvements for them are invisible to the gate.
- `scripts/perf_gate.sh` and `scripts/perf_udp_batch_gate.sh` enforce different protocols; agents pick whichever matches their change.
- No documented "performance work protocol" for agents — `docs/PERFORMANCE_TARGETS.md` covers absolute thresholds and Change Management rules, but does not specify the paired-A/B procedure or tiered thresholds for integration/external work. Agents skip baseline capture under time pressure and claim wins without A/B evidence.

The thread-pool project (`../thread-pool`) solved an analogous problem with a cohesive pattern. This design adapts that pattern to QUIC's subsystem shape and adds the enforcement layer (skill + docs extensions) so future agents follow the protocol rather than re-deriving it.

---

## Goals

1. **One benchmark tree** under `benchmarks/`, split into `micro/`, `integration/`, `external/`, `results/`.
2. **Shared harness** with stddev, median-of-N, CPU pinning, RSS tracking, paired-run metadata — ported from thread-pool's `common.zig`, extended with QUIC-specific fields.
3. **Tiered regression thresholds** — micro −15%/−10%, integration −20%/−25%, external −25%/−30% (throughput / latency p95), with 3× stddev noise floor on every tier.
4. **Paired A/B protocol** enforced by `scripts/perf-gate.sh` — refuses to compare runs with different zig_version/cpu/os.
5. **Six new benchmarks** targeting open P0/P1 hot paths: `frame_serialization` (#163), `connection_lookup` (#154), `loss_detection_scan` (#90), `handshake_e2e` (replaces scaffold), `stream_throughput` (replaces scaffold), `datagram_batch` (#126).
6. **External-impl compare** wrapping existing `test-clients/{quic-go,quinn,aioquic}-client/` for cross-implementation handshake + throughput comparison.
7. **Performance-gating skill** at `.claude/skills/quic-performance-gating/SKILL.md`, discovered by agents when they touch `src/quic/`, `src/h3/`, `benchmarks/`, or mention perf in intent.
8. **Extended `docs/PERFORMANCE_TARGETS.md`** with tiered thresholds + integration/external target tables (preserves existing absolute-gate section and cross-platform smoke coverage). **Two new docs**: `docs/PERFORMANCE_TRACKING.md` (A/B protocol + dated decision log) and `docs/BENCHMARKS.md` (operator manual).
9. **`CLAUDE.md`** at repo root with "Performance Work Protocol" pointer section (repo has no existing CLAUDE.md — this is a new file with only the perf section plus standard project-context headers).
10. **Baselines captured** on current `main` (HEAD at time of capture, embedded in JSON metadata).

## Prerequisites

**Zig 0.16.0 upgrade.** The repository currently pins `minimum_zig_version = "0.15.1"` in `build.zig.zon`. This design adopts thread-pool's `common.zig` harness which uses Zig 0.16.0-only APIs (`std.Io`, `std.ArrayList(T).empty` + `.append(allocator, item)`, `std.process.run(allocator, io, opts)`, `std.json.Stringify.valueAlloc`, `std.Io.Dir.cwd()`). The library was scheduled for 0.16.0 migration; completing it is Phase 0 of the implementation plan. Every downstream phase assumes 0.16.0.

Migration surface (non-exhaustive; discovered iteratively via compile errors):

- `std.heap.GeneralPurposeAllocator` → `std.heap.DebugAllocator` or `std.heap.smp_allocator`
- `std.ArrayList(T).init(alloc)` / `.append(item)` → `std.ArrayList(T).empty` / `.append(allocator, item)` / `.toOwnedSlice(allocator)`
- `std.fs.cwd().createFile(path, opts)` → `std.Io.Dir.cwd().createFile(io, path, opts)` (threaded I/O via `init.io` in main)
- `std.io.getStdOut().writer()` → `std.Io.File.stdout()` + `.writeStreamingAll(io, bytes)`
- `std.process.ArgIterator.initWithAllocator(allocator)` → `init.minimal.args.toSlice(allocator)` (main takes `std.process.Init`)
- `std.process.Child.run(.{ .allocator, .argv })` → `std.process.run(allocator, io, .{ .argv, .stdout_limit, .stderr_limit })`
- `std.json.stringify(value, opts, writer)` → `std.json.Stringify.valueAlloc(allocator, value, opts)`
- `std.mem.Allocator.VTable` shape unchanged, but `alloc`/`resize`/`remap`/`free` signatures shifted — custom allocators (e.g. `bench/main.zig`'s `CountingAllocator`) need audit
- `main` signature: `pub fn main() !void` → `pub fn main(init: std.process.Init) !void` (init.io, init.minimal.args)

Dependencies (`build.zig.zon`) — verify each dep's pinned commit is 0.16.0-compatible; bump if not:

- `tls` (git+<https://gitlab.com/devnw/zig/tls.git>)
- All other transitive deps listed in the zon

This upgrade is a prerequisite, not a sidebar — the benchmark harness won't compile without it.

## Non-Goals

- New congestion-control algorithms, ECN support, GSO implementation, or any of the underlying perf fixes — this design captures and gates those, it does not implement them.
- Cross-hardware baseline comparison — the gate compares runs with matching environment metadata only. Local baseline vs CI baseline are separate artifacts.
- Benchmarks for every subsystem — this design covers the top-six P0/P1 gaps plus existing coverage. Remaining subsystems (flow control, 0-RTT resumption, PTO polling, ECN feedback, H3/QPACK) are deferred.
- External-impl performance beyond handshake+throughput — congestion-control cross-impl is out of scope.
- Replacing the cross-platform compile-matrix smoke scripts (`scripts/cross_platform_udp_batch_smoke.sh`, `scripts/native_runtime_smoke.{sh,ps1}`) — they remain intact; the new gate composes with them rather than absorbing them.

---

## Architecture

### 1. Directory Layout

```text
benchmarks/
  common.zig              # Shared harness (port from thread-pool; extended ResultRow)
  compare.zig             # Tiered-threshold regression comparator
  bench_runner.zig        # Main entry; --suite=<name> --output=<path>

  micro/
    varint.zig            # FROM bench/main.zig (varint section)
    pacing.zig            # FROM bench/main.zig (pacing section)
    header_protection.zig # FROM bench/main.zig + NEW hp-encode coverage
    aead.zig              # FROM bench/bench_tls_aead.zig
    tls_keygen.zig        # FROM bench/bench_tls_handshake.zig
    frame_serialization.zig   # NEW — per-frame encode ns + allocation budget (#163)
    connection_lookup.zig     # NEW — O(N) vs O(1) at 10/100/1K/10K conns (#154)
    loss_detection_scan.zig   # NEW — ACK-path sent_packets scan cost (#90)

  integration/
    poll_overhead.zig     # FROM benchmarks/poll_bench.zig (rewired onto new harness)
    conn_scale.zig        # FROM benchmarks/scale_bench.zig (rewired)
    udp_batch.zig         # FROM bench/udp_batch_bench.zig
    handshake_e2e.zig     # NEW — real-UDP Initial→Handshake-complete latency (replaces scaffold)
    stream_throughput.zig # NEW — real-UDP streaming MB/s (replaces scaffold)
    datagram_batch.zig    # NEW — endpoint-mutex hold time under 16-datagram RX (#126)

  external/
    harness.zig           # Spawns test-clients/* against Zig server via interop/run_endpoint.sh
    scenarios.zig         # {quic-go,quinn,aioquic} × {handshake, throughput}

  results/
    baseline.json         # Current-main baseline (local hardware)
    latest.json           # Most recent run (overwritten)
    external-baseline.json
    external-latest.json
    README.md             # Format + workflow doc

scripts/
  perf-gate.sh            # NEW — tiered, paired-A/B, zig-version-pinned
  perf_gate.sh            # DELETE after migration (contents absorbed into perf-gate.sh as micro cases)
  perf_udp_batch_gate.sh  # DELETE after migration (absorbed)
  cross_platform_udp_batch_smoke.sh  # PRESERVED — cross-platform compile matrix
  native_runtime_smoke.sh            # PRESERVED — macOS runtime smoke
  native_runtime_smoke.ps1           # PRESERVED — Windows runtime smoke

docs/
  PERFORMANCE_TARGETS.md  # EXTEND — add tiered thresholds + integration/external targets
  PERFORMANCE_TRACKING.md # NEW — A/B protocol + dated decision log
  BENCHMARKS.md           # NEW — operator manual

.claude/
  skills/
    quic-performance-gating/
      SKILL.md            # NEW — enforcement skill; RED-phase tested per superpowers:writing-skills

CLAUDE.md                 # NEW — root file with "Performance Work Protocol" section + standard context
```

**Retires:**

- `bench/` directory — contents split between `benchmarks/micro/` and `benchmarks/integration/`.
- `benchmarks/throughput_bench.zig` — replaced by `benchmarks/integration/stream_throughput.zig`.
- `benchmarks/handshake_bench.zig` — replaced by `benchmarks/integration/handshake_e2e.zig`.
- `scripts/perf_gate.sh`, `scripts/perf_udp_batch_gate.sh` — folded into new `scripts/perf-gate.sh`.

**Preserves:**

- `scripts/cross_platform_udp_batch_smoke.sh` — cross-platform compile-only guardrails; invoked separately (not part of perf-gate).
- `scripts/native_runtime_smoke.{sh,ps1}` — macOS/Windows runtime smoke via GitLab SaaS runners; invoked by CI job separately.
- The 7-tier scale structure from 2026-03-27 design (1c, 10c, 100c, 1Kc, 1Kc-100s, 10Kc, 10Kc-10s) for `conn_scale.zig`.
- The 5-tier handshake structure (serial, 10p, 100p, 1Kp, 10Kp) for `handshake_e2e.zig`.
- The payload×concurrency throughput grid (64B, 1KB, 64KB × c=1, c=10, c=100) for `stream_throughput.zig`.
- Loopback-vs-real-UDP separation as the micro-vs-integration divide.
- The existing `docs/PERFORMANCE_TARGETS.md` "CI Performance Budgets" section (absolute gates) — new tiered thresholds layer on top.

### 2. Harness (`benchmarks/common.zig`)

Port from `../thread-pool/benchmarks/common.zig` verbatim. The ported surface is:

- `ScenarioSpec` — config for a single scenario/variant pair (name, variant, per-scenario params)
- `ResultRow` — flat record emitted per scenario/variant run
- `runScenarios(specs, variants, output_path)` — the 7-runs / discard-1 / median-of-6 driver
- `runScenario()` — single-run executor with timing + memory capture
- `warmup()` — pre-measurement cache warmup
- `summarizeLatencies()` — converts per-op latency array → p50/p95/p99
- `parseOutputArg()` — CLI `--output=<path>` handler
- CPU affinity helpers: `pinCurrentThreadToCpu`, `cpuSocketId`, `cpusInSocket`, `socketCount`, `getCurrentAffinity`, `setAffinity`

**Extended `ResultRow`** — QUIC-specific optional fields (null unless the benchmark measures them):

```zig
pub const ResultRow = struct {
    // --- ported verbatim from thread-pool ---
    git_sha: []const u8,
    run_timestamp_unix_s: i64,
    zig_version: []const u8,
    os: []const u8,
    arch: []const u8,
    cpu: []const u8,
    scenario_name: []const u8,
    variant: []const u8,                          // "loopback" / "real_udp" / "quic-go-client" etc.
    worker_count: u32,
    submitter_count: u32,
    throughput_ops_per_sec: f64,
    throughput_stddev_ops_per_sec: f64,
    submit_latency_p50_ns: u64,
    submit_latency_p95_ns: u64,
    submit_latency_p99_ns: u64,
    completion_latency_p50_ns: u64,
    completion_latency_p95_ns: u64,
    completion_latency_p99_ns: u64,
    cpu_time_ns: u64,
    wall_time_ns: u64,
    alloc_count: u64,
    alloc_bytes: u64,
    live_bytes: u64,
    peak_live_bytes: u64,
    rss_current_bytes: u64,
    rss_peak_bytes: u64,
    rss_delta_after_warmup_bytes: i64,

    // --- NEW QUIC-specific (optional) ---
    bytes_per_sec: ?u64 = null,
    packets_per_sec: ?u64 = null,
    handshake_latency_p50_ns: ?u64 = null,
    handshake_latency_p99_ns: ?u64 = null,
    connection_count: ?u32 = null,
    streams_count: ?u32 = null,
    payload_bytes: ?u32 = null,
    retransmit_count: ?u64 = null,
    loss_rate_permille: ?u16 = null,              // loss rate × 1000, so 1% = 10
    cwnd_final_bytes: ?u64 = null,
    rtt_smoothed_ns: ?u64 = null,
    external_impl: ?[]const u8 = null,            // "quic-go" / "quinn" / "aioquic"
    hostname: ?[]const u8 = null,                 // NEW metadata for gate environment checks
    kernel: ?[]const u8 = null,
};
```

Sampling protocol (unchanged from thread-pool):

- **7 runs** per (scenario × variant) pair
- **Discard run #1** (cold caches)
- **Median of runs #2–7** reported as `throughput_ops_per_sec`
- **Stddev over the same 6 retained samples** → `throughput_stddev_ops_per_sec`
- Latency percentiles computed from the concatenated per-op latency array of the 6 retained runs

### 3. Comparator (`benchmarks/compare.zig`)

Reads two JSON files (baseline + current). For each matching (scenario_name, variant) pair:

1. **Environment check** — refuse to compare if `zig_version`, `os`, `arch`, or `cpu` differ. Exit 2 with explanatory message.
2. **Tier classification** — match `scenario_name` prefix against `micro/`, `integration/`, `external/` to select threshold.
3. **Regression calculation** — for `throughput_ops_per_sec`:

   ```text
   delta_pct = (current - baseline) / baseline × 100
   stddev_multiple = abs(current - baseline) / baseline_stddev
   gate_pct = tier_throughput_pct
   is_regression = (delta_pct < -gate_pct) AND (stddev_multiple > 3.0)
   ```

   Both conditions must be true → noise below 3× stddev is never flagged, regardless of %.
4. **Latency p95 regression** — analogous, using tier_latency_pct.
5. **Allocation regression** — integration-tier only, uses `alloc_bytes`.
6. **Absolute gates** — micro-tier scenarios with published absolute targets (varint ≤250ns, pacing ≤400ns, hp_decode total ≤800M ns, short-header allocs = 0) also hard-fail if the absolute target is breached, regardless of delta vs baseline. These targets come from the existing `docs/PERFORMANCE_TARGETS.md` "CI Performance Budgets" section (preserved verbatim).
7. **Output** — markdown table with per-scenario status: PASS / WARN (within 3× stddev) / FAIL / ABSOLUTE-FAIL. Exit non-zero on any FAIL or ABSOLUTE-FAIL.

**Tier threshold table** (authoritative — also published in `docs/PERFORMANCE_TARGETS.md`):

| Tier | Throughput regression | Latency p95 regression | Allocation regression | Noise floor |
|---|---|---|---|---|
| Micro (`micro/`) | −15% | −10% | Zero-delta hard gate | 3× stddev |
| Integration (`integration/`) | −20% | −25% | −30% | 3× stddev |
| External (`external/`) | −25% | −30% | N/A | 3× stddev |

Micro retains absolute gates on top of relative thresholds; integration/external use relative only.

### 4. Bench Runner (`benchmarks/bench_runner.zig`)

Single executable dispatched by `--suite=<name>` argument:

```text
zig build bench -- --suite=all --output=benchmarks/results/latest.json
zig build bench -- --suite=micro --output=/tmp/micro.json
zig build bench -- --suite=integration
zig build bench -- --suite=external
zig build bench -- --suite=varint
zig build bench -- --suite=handshake_e2e --output=before.json
```

`--suite=<name>` selects either a group (`all`, `micro`, `integration`, `external`) or a single scenario (any file stem under `micro/` or `integration/`). External suite is gated behind a runtime check for docker + the required test-clients — exits with guidance if they're missing.

`--output=<path>` writes the JSON result array. Default: stdout.

`--list` — lists all available suites and scenarios, exits 0.

The runner imports every scenario file and dispatches through a comptime-generated `switch` on suite name. Adding a new benchmark = add the file + add one case in the switch.

### 5. New Benchmarks (detail)

#### 5.1 `micro/frame_serialization.zig` — issue #163

**Measures:** encode time + heap allocations for every QUIC frame type: STREAM, ACK, PADDING, CRYPTO, RESET_STREAM, STOP_SENDING, PING, GOAWAY (HTTP/3), WINDOW_UPDATE, MAX_STREAM_ID, CONNECTION_CLOSE.

**One scenario per frame type**, variants: `encode`, `decode`, `roundtrip`. Per-scenario metrics: `ops_per_sec`, latency p50/p95/p99, `alloc_count`, `alloc_bytes`.

**Absolute gates** — none initially (alloc budget will be set after baseline). The first run establishes the alloc budget per frame type; subsequent runs hard-fail if `alloc_count` exceeds baseline + 0.

**Why a separate file vs folding into existing `varint.zig`/`pacing.zig`:** frame serialization touches the full `frame_mod` encode path including length-prefixed payloads, varint-encoded fields, and tag handling — it's a different surface than isolated varint encoding.

#### 5.2 `micro/connection_lookup.zig` — issue #154

**Measures:** cost of `endpoint.findConnectionByDcid()` (or equivalent lookup) at 10, 100, 1K, 10K active connections. Baseline captures O(N) today; regression gate catches re-introduction after the planned O(1) HashMap fix lands.

**One scenario, 4 variants** (conn_count = 10/100/1K/10K). Per-scenario metrics: `ops_per_sec`, latency p50/p95/p99 for a lookup op.

**Setup:** populate endpoint with N connections, pick a random DCID, measure 100K lookups.

**Absolute gate** — none initially. After the HashMap fix lands, a per-variant ceiling (p99 < 500ns at all scales) will be added to `docs/PERFORMANCE_TARGETS.md`.

#### 5.3 `micro/loss_detection_scan.zig` — issue #90

**Measures:** cost of ACK processing as a function of `sent_packets` size. Before #90 lands (unbounded ArrayList + full scan), this benchmark captures the O(N) cost; after the fix, the gate enforces O(1)/O(log N) behavior.

**One scenario, 4 variants** (sent_packets = 100/1K/10K/100K). Metrics: `ops_per_sec` for processAck, latency p50/p95/p99.

**Setup:** populate sent_packets with N entries, emit an ACK range covering a mid-section, measure.

#### 5.4 `integration/handshake_e2e.zig` — replaces scaffold

**Measures:** real-UDP Initial→Handshake-complete latency, following the 2026-03-27 design's 5-tier structure.

**Five scenarios** (one per tier): `serial`, `10p`, `100p`, `1Kp`, `10Kp`. Variants: single `loopback-tls` to start; `real-udp-tls` if we can set up certs via the existing `create_test_certs.sh` pattern.

**Per-scenario metrics:** `handshake_latency_p50_ns`, `handshake_latency_p99_ns`, `ops_per_sec` (handshakes/sec), `alloc_bytes` per handshake.

**Setup:** spawn a Zig server thread using the pattern from `cmd/quic-server.zig` + `create_test_certs.sh`, then N parallel client threads issuing handshakes to completion. Aggregate after join.

**Why this replaces the 2026-03-27 scaffold:** the scaffold emitted `{handshake_avg_ms: 0}` placeholder data with a comment "requires TLS cert generation". The cert path exists in `create_test_certs.sh` and `cmd/quic-server.zig` already — this benchmark wires them up.

#### 5.5 `integration/stream_throughput.zig` — replaces scaffold

**Measures:** real-UDP stream-level MB/s and pps, following the 2026-03-27 design's payload×concurrency grid.

**Six scenarios** from (64B, 1KB, 64KB) × (c=1, c=10, c=100). Variant: `loopback-tls` initially, `real-udp-tls` after.

**Per-scenario metrics:** `bytes_per_sec`, `packets_per_sec`, `latency p50/p95/p99_ns`, `cwnd_final_bytes`, `rtt_smoothed_ns`, `retransmit_count`.

#### 5.6 `integration/datagram_batch.zig` — issue #126

**Measures:** endpoint mutex hold time and tail-latency under 16-datagram batch RX. Captures the current behavior (mutex held for the entire batch), establishes baseline so the planned fix (per-conn queuing, mutex drop between datagrams) can be gated.

**One scenario, 3 variants** (batch_size = 1, 16, 64). Per-scenario metrics: `latency_p50/p95/p99_ns` for datagram-to-dispatch, `mutex_hold_wall_ns`, `ops_per_sec`.

**Setup:** server with N=100 active connections, client floods 1024 datagrams through the batch path, measure the lock-hold distribution via a monotonic clock wrap.

### 6. External Harness (`benchmarks/external/`)

Thin layer that **does not re-implement** clients — wraps existing `test-clients/*` via `interop/run_endpoint.sh`:

- `harness.zig` — spawns a `test-clients/*` subprocess via `std.process.Child`, drives it against a Zig server (or vice-versa where the client doubles as a server), captures stdout/stderr + exit code, emits a `ResultRow` with `external_impl = "quic-go"` etc.
- `scenarios.zig` — enumerates `{handshake, throughput} × {quic-go, quinn, aioquic}` = 6 scenarios. Each scenario runs the existing test-client's benchmark mode (or wraps it in a simple `time` harness if it lacks one).
- Runtime dependencies — docker (for aioquic), Go toolchain (for quic-go client), Rust toolchain (for quinn). Harness exits with a clear message if any are missing; integration into CI is opt-in.

**External tier threshold** is widest (−25% throughput / −30% latency) precisely because kernel + network variance dominates at the QUIC-vs-QUIC wire boundary.

### 7. Enforcement Layer

#### 7.1 `scripts/perf-gate.sh`

Replaces `scripts/perf_gate.sh` + `scripts/perf_udp_batch_gate.sh`. Coexists with (does not absorb) `scripts/cross_platform_udp_batch_smoke.sh` and `scripts/native_runtime_smoke.{sh,ps1}` — those continue as independent cross-platform smoke gates.

**Invocation:**

```bash
# Paired A/B in a single session (recommended):
scripts/perf-gate.sh --baseline-commit=<sha> --current-commit=HEAD [--suite=<name>]

# Manual comparison of pre-captured JSONs:
scripts/perf-gate.sh --baseline=<path.json> --current=<path.json>
```

**Paired mode** (`--baseline-commit`) checks out the baseline sha in a temporary worktree, builds + runs the suite, stashes the result, checks out HEAD, builds + runs, then compares. Uses `mise x zig@<version>` (or equivalent `zig` on PATH) to pin the Zig version across both runs.

**Gate logic:**

1. Environment check — refuse to compare runs with different `zig_version` / `os` / `arch` / `cpu`
2. Run `zig build bench-compare -- --baseline=X --current=Y` (which implements the tier logic from §3)
3. Pretty-print the markdown diff table
4. Exit 0 on all-PASS (including WARN), 1 on any FAIL or ABSOLUTE-FAIL, 2 on environment mismatch or invocation error

**Absorbed from old gates:**

- `perf_gate.sh`'s four absolute gates (varint ≤250ns, pacing ≤400ns, hp_decode total ≤800M ns, short-header allocs = 0) move into `compare.zig` as the micro-tier ABSOLUTE-FAIL cases, preserving the exact thresholds from `docs/PERFORMANCE_TARGETS.md`.
- `perf_udp_batch_gate.sh`'s syscall-reduction ≥4.0× + throughput-speedup ≥0.95× gates move to `integration/udp_batch.zig` as absolute gates.

**NOT absorbed:**

- `cross_platform_udp_batch_smoke.sh` remains invoked independently by CI — it's a compile-only matrix, not a perf gate.
- `native_runtime_smoke.{sh,ps1}` remain invoked independently by CI — they're runtime-correctness smoke on non-Linux platforms.
- The `.gitlab-ci.yml` jobs that invoke these scripts must be updated to also invoke `perf-gate.sh` in a separate job, not in lieu of the cross-platform jobs.

#### 7.2 Performance-Gating Skill

Location: `.claude/skills/quic-performance-gating/SKILL.md`.

**Frontmatter:**

```yaml
---
name: quic-performance-gating
description: Use when modifying files under src/quic/, src/h3/, or benchmarks/; when intent involves performance, latency, throughput, regression, optimization, or benchmark targets; when a perf-gate hook fails; when considering "this is a simple change" in a connection/stream/packet/frame/crypto/recovery hot path; when preparing an MR that claims a perf improvement.
---
```

**Iron Law:** "No performance-claiming change lands without a paired same-session A/B run against `benchmarks/results/baseline.json`."

**Required workflow (encoded as steps in the skill):**

1. Capture baseline on the parent commit (or confirm `benchmarks/results/baseline.json` matches current `main`)
2. Apply the change
3. Run `scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json --current=<new-run>.json --suite=<affected-suite>`
4. On FAIL: revert or iterate. On ABSOLUTE-FAIL: never merge; document in MR why the target needs revision.
5. On PASS: paste the diff table into MR description, append a dated entry to `docs/PERFORMANCE_TRACKING.md`

**Red flags** (STOP-and-run-gate symptoms):

- About to commit code in `src/quic/` without having run any benchmark
- About to claim performance benefit in MR body without a diff table
- "Quick fix" / "minor change" / "obvious perf win" in a hot-path file
- About to skip baseline capture because "I'll do it after the feature is done"
- About to hand-wave "similar changes have been fine in the past"

**Rationalization table** (seeded below; RED-phase testing per `superpowers:writing-skills` will extend it):

| Excuse | Reality |
|---|---|
| "This is just a small fix." | Small fixes in `src/quic/conn.zig` caused 15× QPS regressions before (2026-03 incident). Run the gate. |
| "I already profiled locally." | Profiling ≠ A/B. Profiling identifies hotspots; A/B proves regression direction and magnitude. |
| "This doesn't touch the hot path." | You don't know until benchmarks confirm. Hot paths in QUIC span conn lookup, frame encode, AEAD, and poll loop — all non-obvious entry points. |
| "The existing baseline is stale." | Then refresh it on the parent commit before your change, not after. A baseline captured after the change is not a baseline. |
| "External compare is flaky, skip it." | External tier has a wider threshold for exactly that reason. Still run. Flaky ≠ skip. |
| "CI will catch it." | CI runs the same gate. Save the feedback loop — run locally first. |
| "This is just a refactor, perf should be neutral." | "Should be" needs data. That's what the A/B proves. Refactors have caused regressions before. |
| "The benchmark is measuring the wrong thing." | Fix the benchmark in a separate MR, then run the gate on this MR. Never waive the gate to ship a change. |

**Testing per `superpowers:writing-skills`:**

- **RED phase** (baseline without skill): dispatch a subagent with the prompt *"You have 10 minutes to finish this perf MR. You added a bounds check to the packet decode path. Is this safe to commit?"* — capture verbatim rationalizations.
- **GREEN phase** (with skill loaded): re-run the same scenario, verify the subagent pauses and runs the gate.
- **REFACTOR phase**: add any novel rationalization uncovered in RED to the table, re-run GREEN until no new loopholes surface.

**CLAUDE.md integration** — the repo has no root `CLAUDE.md` today. The new file includes only a standard project header + a "Performance Work Protocol" section:

```text
## Performance Work Protocol

This repo gates performance claims behind a paired A/B run. If you change
code in src/quic/, src/h3/, or benchmarks/, or if your MR claims any perf
benefit, you MUST follow .claude/skills/quic-performance-gating/SKILL.md
and run scripts/perf-gate.sh before requesting review.

- Authoritative targets: docs/PERFORMANCE_TARGETS.md
- Protocol + decision log: docs/PERFORMANCE_TRACKING.md
- Operator manual: docs/BENCHMARKS.md
```

### 8. Build Wiring (`build.zig`)

**Added steps:**

```bash
zig build bench                         # runs all suites (default: --suite=all)
zig build bench-micro                   # --suite=micro
zig build bench-integration             # --suite=integration
zig build bench-external                # --suite=external
zig build bench -- --suite=<name> --output=<path>   # single-suite / scenario
zig build bench-compare -- --baseline=<path> --current=<path>   # regression gate
```

**Retired steps** (move to no-op aliases during migration for MR-branch compatibility, removed entirely after one release):

- `zig build bench-poll` → alias for `zig build bench -- --suite=poll_overhead`
- `zig build bench-scale` → alias for `zig build bench -- --suite=conn_scale`
- `zig build bench-throughput` → alias for `zig build bench -- --suite=stream_throughput`
- `zig build bench-handshake` → alias for `zig build bench -- --suite=handshake_e2e`

**Shared module** — `bench_common_mod` in `build.zig` points at `benchmarks/common.zig`, imported by `bench_runner` and `compare`.

**Module imports needed by bench_runner** (per-scenario wiring):

- `quic_endpoint` — Endpoint init, connectClient, pollWithStats, accept
- `quic_conn` — connection + stream types
- `quic_config` — QuicConfig
- `quic_api` — high-level API (for handshake_e2e, stream_throughput)
- `quic_frame` — frame encode/decode (for frame_serialization)
- `quic_crypto` — AEAD + HP primitives (for header_protection, aead)
- `quic_tls13` — TLS key derivation (for tls_keygen)

### 9. Baseline Capture

**When:** after all code is in place, on `main` (HEAD at capture time — recorded in JSON metadata).

**Hardware:** your local box. The gate refuses to compare across divergent environments, so local-baseline vs CI-baseline are independent artifacts with separate `*.json` files (no coercion).

**Process:**

```bash
git checkout main && git pull
zig build bench -- --suite=all --output=benchmarks/results/baseline.json
zig build bench -- --suite=external --output=benchmarks/results/external-baseline.json  # optional; needs docker + toolchains
git add benchmarks/results/baseline.json benchmarks/results/external-baseline.json
git commit -m "chore(bench): capture v2 baseline on <sha> / <cpu>"
```

The baseline commit is the reference point for the first real A/B. Every future MR's gate runs against this file until a new baseline is captured (which itself requires an entry in `docs/PERFORMANCE_TRACKING.md` explaining *why*).

### 10. Documentation

#### 10.1 `docs/PERFORMANCE_TARGETS.md` (EXTEND, do not replace)

Preserve the existing document verbatim. **Append** new sections:

- **"Tier Threshold Table"** — the 3-tier table from §3. Placed before the existing "CI Performance Budgets" section as the authoritative relative-threshold reference.
- **"Integration Targets"** — per-scenario aspirational targets for `poll_overhead`, `conn_scale`, `handshake_e2e`, `stream_throughput`, `datagram_batch`, `udp_batch`. Populated from baseline capture. "Aspirational" because they're measured-from-current not computed-from-protocol.
- **"External Targets"** — per-impl per-scenario targets for `{quic-go, quinn, aioquic} × {handshake, throughput}`.
- **"Revision Protocol"** — targets are only revised alongside a `PERFORMANCE_TRACKING.md` entry that explains the reason. The existing "Change Management" section already covers this for absolute gates; extended to cover tiered thresholds.

Existing sections preserved as-is:

- "Workload Profiles" (microbench / functional / full graph)
- "CI Performance Budgets" (the 4 absolute gates + UDP batch gate)
- Cross-platform smoke coverage reference
- "Validation Commands"
- "Change Management"

#### 10.2 `docs/PERFORMANCE_TRACKING.md` (NEW)

Sections:

1. **A/B protocol** — step-by-step (duplicated from skill so non-agent readers can follow it)
2. **MR review checklist** — "Does the MR include a diff table?", "Does the affected suite pass?", "Are absolute gates respected?"
3. **Dated decision log** — append-only. Each entry: date, commit, suite, what changed, before/after deltas, approved-by. First entry documents the initial v2 baseline capture.

#### 10.3 `docs/BENCHMARKS.md` (NEW)

Sections:

1. **Quick start** — `zig build bench`
2. **Per-suite detail** — what each suite measures, expected runtime, hardware sensitivity, external dependencies
3. **External suite setup** — docker + go + rust + python install guidance
4. **Troubleshooting** — flaky-benchmark debugging, environment-mismatch errors from gate script
5. **Adding a new benchmark** — the 4-step recipe (add file under micro/ or integration/, add switch case in bench_runner, add threshold row to PERFORMANCE_TARGETS.md if absolute gate is needed, regen baseline)

#### 10.4 `CLAUDE.md` at repo root (NEW)

Contents: minimal — standard project-context header (project name, language, main commands) + the "Performance Work Protocol" section shown in §7.2. Not a comprehensive project guide; scoped to what agents loading this repo need to know about perf discipline.

---

## Migration / Implementation Order

(Becomes the implementation plan structure — each task is a single commit.)

1. **Port `common.zig`** from thread-pool → `benchmarks/common.zig`, extend `ResultRow` with QUIC fields. Verify it builds as a module.
2. **Write `compare.zig`** with tier logic, environment check, absolute gates. Unit-test against synthetic JSONs with known deltas.
3. **Write `bench_runner.zig`** — dispatcher + CLI. Start with a single-scenario smoke test (e.g., varint) to validate wiring.
4. **Move and split `bench/main.zig`** → `benchmarks/micro/{varint,pacing,header_protection}.zig`. Wire each onto new harness.
5. **Move `bench/bench_tls_aead.zig`** → `benchmarks/micro/aead.zig`. Move `bench/bench_tls_handshake.zig` → `benchmarks/micro/tls_keygen.zig`.
6. **Move `bench/udp_batch_bench.zig`** → `benchmarks/integration/udp_batch.zig`. Absorb `perf_udp_batch_gate.sh` logic as absolute gate.
7. **Move `benchmarks/poll_bench.zig`** → `benchmarks/integration/poll_overhead.zig` onto new harness.
8. **Move `benchmarks/scale_bench.zig`** → `benchmarks/integration/conn_scale.zig` onto new harness. **Delete** the two scaffolds (`throughput_bench.zig`, `handshake_bench.zig`).
9. **Rewire `build.zig`** — add `bench`, `bench-micro`, `bench-integration`, `bench-external`, `bench-compare` steps; add retired-step aliases. Also audit `Makefile`, `.gitlab-ci.yml`, `.pre-commit-config.yaml` for references to old paths and update atomically.
10. **Write `micro/frame_serialization.zig`** (#163).
11. **Write `micro/connection_lookup.zig`** (#154).
12. **Write `micro/loss_detection_scan.zig`** (#90).
13. **Write `integration/handshake_e2e.zig`** (replaces scaffold).
14. **Write `integration/stream_throughput.zig`** (replaces scaffold).
15. **Write `integration/datagram_batch.zig`** (#126).
16. **Write `external/harness.zig` + `scenarios.zig`** — wraps `test-clients/*`.
17. **Write `scripts/perf-gate.sh`** — paired A/B + tiered logic. **Delete** `scripts/perf_gate.sh` + `scripts/perf_udp_batch_gate.sh`. Leave `cross_platform_udp_batch_smoke.sh` and `native_runtime_smoke.*` intact.
18. **Extend `docs/PERFORMANCE_TARGETS.md`** (add tiered thresholds + integration/external target sections). **Write `docs/PERFORMANCE_TRACKING.md`** and **`docs/BENCHMARKS.md`**.
19. **Write `.claude/skills/quic-performance-gating/SKILL.md`** with RED-phase subagent testing first, then iterate with rationalization-table refinements per `superpowers:writing-skills`.
20. **Add `CLAUDE.md`** at repo root with "Performance Work Protocol" pointer section.
21. **Capture baselines** — `zig build bench -- --suite=all --output=benchmarks/results/baseline.json`, and external-baseline if environment supports it.
22. **Commit baselines + first `PERFORMANCE_TRACKING.md` entry**.

Tasks 1-3 are strictly sequential (harness → comparator → runner). Tasks 4-8 can run in parallel (independent file moves). Task 9 is a single merge point after 4-8. Tasks 10-15 can run in parallel (independent new files), each pair-depending on 9. Task 16 is independent of 10-15. Tasks 17-18 can run in parallel after 16. Task 19 is the last piece of new content. Tasks 20-22 are the final commit cluster.

---

## Risks

1. **Scope creep on new benchmarks** — implementing `handshake_e2e` and `stream_throughput` requires reusing `create_test_certs.sh` + `cmd/quic-server.zig` patterns, which may surface bugs in those paths. Mitigation: if cert setup blocks > 1 hour, ship the benchmark with `loopback-tls` variant only and mark `real-udp-tls` as a follow-up.
2. **External harness fragility** — `test-clients/*` subprocess lifecycle management is the kind of thing that can hang CI. Mitigation: 60-second watchdog timeout per scenario, emit a synthetic WARN row with diagnostics on timeout rather than hang.
3. **Baseline noise on user's hardware** — power management / turbo / background processes on a dev box skew baselines. Mitigation: document the `performance` governor + `nosmt` suggestion in `docs/BENCHMARKS.md`, but don't mandate it — the 3× stddev floor absorbs moderate variance.
4. **Skill triggering too aggressively** — if the description matches every `src/quic/*` touch, agents making non-perf changes will bounce off the skill. Mitigation: description includes *"when intent involves performance..."* — the CSO keywords require either a path match OR a perf-intent signal, not both independently.
5. **Retiring old scripts breaks external CI pipelines** — `.gitlab-ci.yml` explicitly references `scripts/perf_gate.sh` and `scripts/perf_udp_batch_gate.sh`; deletion without updating the CI config breaks the pipeline. Mitigation: in step 17, the CI config update is in the same commit as the script deletion. `scripts/cross_platform_udp_batch_smoke.sh` and `scripts/native_runtime_smoke.*` are NOT deleted — only the two perf-gate scripts.
6. **The two scaffolds might have external consumers** — check `Makefile`, `.gitlab-ci.yml`, and `IMPLEMENTATION_STATUS.md` for references to `bench-throughput` / `bench-handshake` before deleting. Use the alias mechanism in step 9 as a safety net.
7. **`docs/PERFORMANCE_TARGETS.md` absolute-gate preservation** — the existing document has been stable since 2026-02-16 and is referenced by CI scripts. If the extension inadvertently changes existing absolute-gate values or section IDs, the CI pipeline fails silently. Mitigation: step 18 extends the file via additive appending only; existing sections are not reformatted or renumbered.

---

## Open Questions

None at design time. Flag-as-we-go for anything that surfaces during implementation.

---

## Appendix A: Cross-Reference to 2026-03-27 Design

| 2026-03-27 item | This design | Reason |
|---|---|---|
| `benchmarks/scale_bench.zig` (7 tiers) | **preserved** → `integration/conn_scale.zig` | Tier structure is sound; harness upgraded |
| `benchmarks/poll_bench.zig` (6 tiers) | **preserved** → `integration/poll_overhead.zig` | Same |
| `benchmarks/throughput_bench.zig` (scaffold) | **replaced** → `integration/stream_throughput.zig` with real measurement | Scaffold emitted zeros; payload×concurrency grid preserved |
| `benchmarks/handshake_bench.zig` (scaffold) | **replaced** → `integration/handshake_e2e.zig` with real measurement | Same |
| `benchmarks/common.zig` (Timer + JSON) | **superseded** by thread-pool-ported harness | Missing stddev, CPU pinning, RSS, paired-run metadata |
| `benchmarks/compare.zig` (suffix-based) | **superseded** by tier-aware comparator | Needs environment checks + stddev noise floor |
| `benchmarks/results/baseline.json` | **regenerated** after v2 harness lands | Schema change |
| `bench/` (micro, kept separate) | **consolidated** into `benchmarks/micro/` | Single tree per goal 1 |
| `scripts/perf_gate.sh` (4 absolute gates) | **absorbed** into `scripts/perf-gate.sh` micro cases | Single enforcement point |
| `scripts/perf_udp_batch_gate.sh` | **absorbed** into integration absolute gate | Same |
| `scripts/cross_platform_udp_batch_smoke.sh` | **preserved, not absorbed** | Different role (compile-only matrix, not perf) |
| `scripts/native_runtime_smoke.{sh,ps1}` | **preserved, not absorbed** | Different role (runtime smoke on non-Linux) |

## Appendix B: Cross-Reference to Open Perf Issues

| Issue | Benchmark that catches regression / proves fix |
|---|---|
| #90 unbounded sent_packets | `micro/loss_detection_scan.zig` |
| #109 no frame coalescing / GSO | `integration/stream_throughput.zig` (indirect) + `integration/udp_batch.zig` |
| #126 endpoint mutex held during batch RX | `integration/datagram_batch.zig` |
| #154 O(N) connection lookup | `micro/connection_lookup.zig` |
| #163 per-frame heap allocs | `micro/frame_serialization.zig` |
| #167 PacketBufferPool efficiency | `integration/conn_scale.zig` (indirect via RSS tracking) |
| #172 ECN bits hardcoded | Deferred (non-goal) |
| #182 O(N) PTO polling | `integration/poll_overhead.zig` (indirect) |
| #183 pacing heap alloc + no sendmmsg | `integration/udp_batch.zig` |
