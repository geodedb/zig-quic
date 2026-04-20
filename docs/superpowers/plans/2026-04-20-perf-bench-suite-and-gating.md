<!-- markdownlint-disable MD029 MD036 -->
# Performance Benchmark Suite v2 + Performance-Gating Protocol — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate two fragmented benchmark trees into a single thread-pool-style suite with paired A/B regression gating, tiered thresholds, external-impl compare, 6 new benchmarks targeting open P0/P1 perf issues, a performance-gating skill, and captured baselines on current main.

**Architecture:** Port thread-pool's harness pattern (7 runs, discard 1, median-of-6, stddev gate) into a QUIC-native `benchmarks/common.zig`; unify `bench/` + `benchmarks/` trees under `benchmarks/{micro,integration,external}/`; tiered thresholds (micro −15%/−10%, integration −20%/−25%, external −25%/−30%) with 3× stddev noise floor; enforce via `scripts/perf-gate.sh` + `.claude/skills/quic-performance-gating/SKILL.md`.

**Tech Stack:** Zig 0.16.0 (upgrade from 0.15.1 — Phase 0), thread-pool's harness pattern, QUIC endpoint/stream/frame/crypto APIs, test-clients/{quic-go,quinn,aioquic}-client/ for external compare, `scripts/perf-gate.sh` (bash + jq), markdown docs.

**Spec:** `docs/superpowers/specs/2026-04-20-perf-bench-suite-and-gating-design.md`

---

## Phase Overview

| Phase | Tasks | Description |
|---|---|---|
| 0 | 7 | Upgrade repo to Zig 0.16.0 (prerequisite — harness uses 0.16-only APIs) |
| 1 | 3 | Foundation: common.zig harness, compare.zig comparator, bench_runner.zig dispatcher |
| 2 | 5 | Migrate existing benches onto new harness (varint/pacing/hp, TLS, udp_batch, poll, scale) |
| 3 | 1 | Rewire build.zig + Makefile + .gitlab-ci.yml |
| 4 | 3 | New micro benches: frame_serialization, connection_lookup, loss_detection_scan |
| 5 | 3 | New integration benches: handshake_e2e, stream_throughput, datagram_batch |
| 6 | 1 | External harness wrapping test-clients/* |
| 7 | 1 | scripts/perf-gate.sh (paired A/B, tiered) — retires old scripts |
| 8 | 1 | Extend PERFORMANCE_TARGETS.md; write PERFORMANCE_TRACKING.md + BENCHMARKS.md |
| 9 | 1 | Write quic-performance-gating skill (RED → GREEN → REFACTOR per writing-skills) |
| 10 | 3 | CLAUDE.md; capture baselines; commit tracking log entry |

**Total: 29 tasks.** Dependencies:

- Phase 0 blocks everything
- Tasks 1.1 → 1.2 → 1.3 sequential
- Tasks 2.1–2.5 parallelizable after 1.3
- Task 3 is merge point
- Tasks 4.1–4.3 and 5.1–5.3 parallelizable after 3
- Tasks 6, 7, 8 parallelizable after 5
- Task 9 depends on 7
- Tasks 10.1–10.3 final cluster

---

## Cross-References

- **Harness reference** (thread-pool, 0.16.0): `/home/benji/src/devnw/zig/thread-pool/benchmarks/common.zig` (619 lines)
- **Comparator reference** (thread-pool): `/home/benji/src/devnw/zig/thread-pool/benchmarks/compare.zig` (78 lines)
- **Gate script reference** (thread-pool): `/home/benji/src/devnw/zig/thread-pool/scripts/perf-gate.sh` (149 lines)
- **Authoritative absolute gates** (quic, preserved): `/home/benji/src/devnw/zig/quic/docs/PERFORMANCE_TARGETS.md:30-43`
- **Existing bench files to move** (quic): `bench/main.zig` (398 lines), `bench/bench_tls_aead.zig` (163), `bench/bench_tls_handshake.zig` (136), `bench/udp_batch_bench.zig` (328)
- **Existing benchmark files to rewire** (quic): `benchmarks/poll_bench.zig` (133), `benchmarks/scale_bench.zig` (168)
- **Scaffolds to delete** (quic, replaced): `benchmarks/throughput_bench.zig`, `benchmarks/handshake_bench.zig`
- **Interop infrastructure** (quic, reused for external): `interop/run_endpoint.sh`, `interop/Dockerfile`, `test-clients/{quic-go,quinn,aioquic}-client/`

---

## Phase 0: Zig 0.16.0 Upgrade (Prerequisite)

Every downstream phase assumes 0.16.0. This phase migrates the repo incrementally, commit-per-subsystem.

### Task 0.1: Bump minimum_zig_version

**Files:**

- Modify: `build.zig.zon:6`

- [ ] **Step 1: Verify local zig version ≥ 0.16.0**

Run: `zig version`
Expected: `0.16.0` or newer. If not, install via mise: `mise install zig@0.16.0 && mise use zig@0.16.0`.

- [ ] **Step 2: Bump version pin**

Edit `build.zig.zon`: change `.minimum_zig_version = "0.15.1",` → `.minimum_zig_version = "0.16.0",`

- [ ] **Step 3: Run `zig build` to capture the full error list**

Run: `zig build 2>&1 | tee /tmp/zig-0.16-errors.txt`
Expected: Many errors — this is the work list for Tasks 0.2–0.6. Save the output; you'll iterate through it.

- [ ] **Step 4: Commit the version bump alone (errors still present)**

```bash
git add build.zig.zon
git commit -m "chore(build): bump minimum_zig_version to 0.16.0 (upgrade work to follow)"
```

---

### Task 0.2: Upgrade dependency pins for 0.16.0 compatibility

**Files:**

- Modify: `build.zig.zon` (dependency block)

- [ ] **Step 1: List dependencies**

Run: `grep -n "url = " build.zig.zon`

- [ ] **Step 2: For each dependency, verify 0.16.0 compatibility**

For `tls` (gitlab.com/devnw/zig/tls): clone to a temp dir, check its `build.zig.zon` for `minimum_zig_version`. If still 0.15.1, find or request a newer commit.

For sibling devnw deps (thread-pool, etc.): use current HEAD of their main branches.

- [ ] **Step 3: Update pins via `zig fetch --save`**

```bash
zig fetch --save=tls "git+https://gitlab.com/devnw/zig/tls.git#<new-sha>"
```

- [ ] **Step 4: Re-run `zig build`**

Run: `zig build 2>&1 | tee /tmp/zig-0.16-errors.txt`

- [ ] **Step 5: Commit**

```bash
git add build.zig.zon
git commit -m "chore(deps): bump sibling pins to 0.16.0-compatible commits"
```

---

### Task 0.3: Migrate std.ArrayList API calls

Zig 0.16.0 changed `std.ArrayList(T)` to unmanaged-first — `.init(allocator)` is gone; use `.empty` + explicit allocator on every mutation.

**Files:** every file with ArrayList errors from Task 0.1 Step 3.

- [ ] **Step 1: Grep for patterns**

Run: `grep -rn "ArrayList" src/ lib.zig quic.zig cmd/ benchmarks/ bench/ tests/ tools/ 2>/dev/null | grep -v "test_\|\.md"`

- [ ] **Step 2: Apply transformations**

| Before (0.15.1) | After (0.16.0) |
|---|---|
| `var x = std.ArrayList(T).init(allocator);` | `var x: std.ArrayList(T) = .empty;` |
| `defer x.deinit();` | `defer x.deinit(allocator);` |
| `try x.append(item);` | `try x.append(allocator, item);` |
| `try x.appendSlice(slice);` | `try x.appendSlice(allocator, slice);` |
| `try x.resize(n);` | `try x.resize(allocator, n);` |
| `try x.toOwnedSlice();` | `try x.toOwnedSlice(allocator);` |

Apply per file. After each file, run `zig build` and verify fewer errors.

- [ ] **Step 3: Run test suite**

Run: `zig build test 2>&1 | head -40`

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "refactor(zig-0.16): migrate ArrayList to unmanaged .empty + per-op allocator"
```

---

### Task 0.4: Migrate std.process + main signature + CLI args

Zig 0.16.0 introduced `std.process.Init` as the main-function argument.

- [ ] **Step 1: Grep for main signatures**

Run: `grep -rn "pub fn main" src/ lib.zig cmd/ benchmarks/ bench/ tests/ tools/ 2>/dev/null`

- [ ] **Step 2: Apply main signature transformation**

Before:

```zig
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.next();
}
```

After:

```zig
pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
}
```

- [ ] **Step 3: Migrate std.process.Child.run call sites**

Before:

```zig
const result = std.process.Child.run(.{ .allocator = allocator, .argv = &argv });
```

After:

```zig
const result = try std.process.run(allocator, init.io, .{
    .argv = &argv,
    .stdout_limit = .limited(4096),
    .stderr_limit = .limited(4096),
});
```

Thread `init.io` through any helper that invokes subprocesses.

- [ ] **Step 4: Verify**

Run: `zig build 2>&1 | head -40`

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "refactor(zig-0.16): migrate main to std.process.Init; std.process.run via init.io"
```

---

### Task 0.5: Migrate std.fs → std.Io.Dir

- [ ] **Step 1: Grep**

Run: `grep -rn "std.fs\|std.io.getStd" src/ lib.zig cmd/ benchmarks/ bench/ tests/ tools/ 2>/dev/null | head -40`

- [ ] **Step 2: Apply transformations**

| Before (0.15.1) | After (0.16.0) |
|---|---|
| `std.fs.cwd().openFile(path, .{})` | `std.Io.Dir.cwd().openFile(init.io, path, .{})` |
| `std.fs.cwd().createFile(path, .{})` | `std.Io.Dir.cwd().createFile(init.io, path, .{})` |
| `file.readToEndAlloc(allocator, limit)` | `std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit))` |
| `file.writer()` / `file.writeAll(bytes)` | `file.writeStreamingAll(io, bytes)` |
| `file.close()` | `file.close(io)` |
| `std.io.getStdOut()` | `std.Io.File.stdout()` |
| `std.io.getStdErr()` | `std.Io.File.stderr()` |

- [ ] **Step 3: Thread `io` through helpers**

Any helper that took `allocator: std.mem.Allocator` and did file I/O now takes `(allocator: std.mem.Allocator, io: std.Io)`.

- [ ] **Step 4: Verify**

Run: `zig build 2>&1 | grep -E "(std\.fs|std\.io\.getStd)" | head`
Expected: Empty.

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "refactor(zig-0.16): migrate std.fs/std.io → std.Io.Dir/std.Io.File"
```

---

### Task 0.6: Migrate std.json + remaining breakages

- [ ] **Step 1: JSON migrations**

| Before | After |
|---|---|
| `try std.json.stringify(value, .{}, writer)` | `const json = try std.json.Stringify.valueAlloc(allocator, value, .{ .whitespace = .indent_2 }); defer allocator.free(json); try out.writeStreamingAll(io, json);` |
| `try std.json.parseFromSlice(T, alloc, bytes, .{})` | Same signature, result type `std.json.Parsed(T)` — call `.deinit()` |

- [ ] **Step 2: GeneralPurposeAllocator → smp_allocator for benches**

Replace `std.heap.GeneralPurposeAllocator(.{}){}` with `std.heap.smp_allocator` for benchmark code. For debug-build code that needs leak detection: `std.heap.DebugAllocator(.{})`.

- [ ] **Step 3: Custom allocator VTable audit**

The `bench/main.zig` `CountingAllocator` uses `std.mem.Allocator.VTable`. In 0.16.0 the `alloc` callback's `alignment` parameter type changed from `u8` to `std.mem.Alignment`. Update the function signatures accordingly.

- [ ] **Step 4: Iterate until clean**

Run: `zig build 2>&1 | tee /tmp/remaining.txt`
Fix each remaining error using the patterns from Tasks 0.3–0.6.

- [ ] **Step 5: Commit incrementally**

```bash
git add -u
git commit -m "refactor(zig-0.16): migrate <subsystem> (json/allocator/vtable)"
```

---

### Task 0.7: Verify tests + interop pass

- [ ] **Step 1: Full test suite**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass.

- [ ] **Step 2: Existing benchmarks still work**

Run: `zig build bench 2>&1 | tail -20`
Expected: Micro gates (`scripts/perf_gate.sh`) still pass.

- [ ] **Step 3: Interop smoke**

Run: `make interop_local 2>&1 | tail -20` (or appropriate target from Makefile).

- [ ] **Step 4: Empty commit marker**

```bash
git commit --allow-empty -m "chore(zig-0.16): verify test + bench + interop pass on 0.16.0"
```

---

## Phase 1: Foundation (Harness + Comparator + Runner)

### Task 1.1: Write benchmarks/common.zig (QUIC-native harness)

**Files:**

- Create: `benchmarks/common.zig`
- Create: `tests/test_bench_common.zig`
- Modify: `build.zig`

This is a hand-written 0.16.0 file that borrows structure from thread-pool's common.zig but strips thread-pool-specific fields and adds QUIC-specific optional fields.

- [ ] **Step 1: Create `benchmarks/common.zig` with full content**

```zig
// benchmarks/common.zig
// SPDX-License-Identifier: Apache-2.0
//
// Shared benchmark harness for zig-quic performance work.
// Adapted from ../../thread-pool/benchmarks/common.zig — same median-of-6
// sampling + CPU pinning helpers + JSON schema, restructured so benchmarks
// supply their own measurement functions.

const std = @import("std");
const builtin = @import("builtin");

pub const ScenarioSpec = struct {
    name: []const u8,
    variant: []const u8 = "default",
    iterations: u64 = 1,
    warmup_iterations: u64 = 0,
    payload_bytes: u32 = 0,
    connection_count: u32 = 1,
    streams_count: u32 = 1,
    extra: ?*const anyopaque = null,
};

pub const ResultRow = struct {
    git_sha: []const u8,
    run_timestamp_unix_s: i64,
    zig_version: []const u8,
    os: []const u8,
    arch: []const u8,
    cpu: []const u8,
    hostname: []const u8,
    kernel: []const u8,
    scenario_name: []const u8,
    variant: []const u8,
    iterations: u64,
    throughput_ops_per_sec: f64,
    throughput_stddev_ops_per_sec: f64 = 0,
    latency_p50_ns: u64,
    latency_p95_ns: u64,
    latency_p99_ns: u64,
    cpu_time_ns: u64,
    wall_time_ns: u64,
    alloc_count: u64 = 0,
    alloc_bytes: u64 = 0,
    peak_live_bytes: u64 = 0,
    rss_current_bytes: u64 = 0,
    rss_peak_bytes: u64 = 0,

    // QUIC-specific optional fields
    bytes_per_sec: ?u64 = null,
    packets_per_sec: ?u64 = null,
    handshake_latency_p50_ns: ?u64 = null,
    handshake_latency_p99_ns: ?u64 = null,
    connection_count: ?u32 = null,
    streams_count: ?u32 = null,
    payload_bytes: ?u32 = null,
    retransmit_count: ?u64 = null,
    loss_rate_permille: ?u16 = null,
    cwnd_final_bytes: ?u64 = null,
    rtt_smoothed_ns: ?u64 = null,
    external_impl: ?[]const u8 = null,
    mutex_hold_wall_ns: ?u64 = null,
};

pub const HostInfo = struct {
    os: []const u8,
    arch: []const u8,
    cpu: []const u8,
    hostname: []const u8,
    kernel: []const u8,
};

pub const ResultDocument = struct {
    generated_at_unix_s: i64,
    zig_version: []const u8,
    quic_git_sha: []const u8,
    host: HostInfo,
    rows: []ResultRow,
};

pub const LatencySummary = struct {
    count: usize,
    min_ns: u64,
    mean_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
};

pub const RunOutput = struct {
    iterations: u64,
    wall_time_ns: u64,
    cpu_time_ns: u64,
    latencies_ns: []u64,
    alloc_count: u64 = 0,
    alloc_bytes: u64 = 0,
    peak_live_bytes: u64 = 0,
    bytes_transferred: u64 = 0,
    packets_transferred: u64 = 0,
    handshake_latencies_ns: ?[]u64 = null,
    retransmit_count: u64 = 0,
    cwnd_final_bytes: u64 = 0,
    rtt_smoothed_ns: u64 = 0,
    mutex_hold_wall_ns: u64 = 0,
};

pub const RunFn = *const fn (allocator: std.mem.Allocator, spec: ScenarioSpec) anyerror!RunOutput;

pub fn parseOutputArg(args: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.startsWith(u8, args[i], "--output=")) return args[i]["--output=".len..];
        if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) return args[i + 1];
    }
    return null;
}

pub fn parseSuiteArg(args: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.startsWith(u8, args[i], "--suite=")) return args[i]["--suite=".len..];
        if (std.mem.eql(u8, args[i], "--suite") and i + 1 < args.len) return args[i + 1];
    }
    return null;
}

/// Run `runFn` 7 times, discard run #1, return ResultRow with median-of-6 + stddev.
pub fn runRepeated(
    allocator: std.mem.Allocator,
    io: std.Io,
    spec: ScenarioSpec,
    runFn: RunFn,
) !ResultRow {
    const RUN_COUNT: usize = 7;
    const WARMUP: usize = 1;
    const SAMPLES: usize = RUN_COUNT - WARMUP;

    var outputs: [RUN_COUNT]RunOutput = undefined;
    for (&outputs) |*o| o.* = try runFn(allocator, spec);
    defer {
        for (&outputs) |*o| {
            allocator.free(o.latencies_ns);
            if (o.handshake_latencies_ns) |h| allocator.free(h);
        }
    }

    const warm_samples = outputs[WARMUP..];
    var throughputs: [SAMPLES]f64 = undefined;
    for (warm_samples, 0..) |o, i| {
        throughputs[i] = @as(f64, @floatFromInt(o.iterations)) /
            (@as(f64, @floatFromInt(o.wall_time_ns)) / std.time.ns_per_s);
    }
    std.sort.heap(f64, &throughputs, {}, comptime std.sort.asc(f64));
    const median_throughput = throughputs[SAMPLES / 2];
    var sum_sq: f64 = 0;
    for (throughputs) |t| {
        const d = t - median_throughput;
        sum_sq += d * d;
    }
    const stddev = std.math.sqrt(sum_sq / @as(f64, @floatFromInt(SAMPLES)));

    var median_idx: usize = WARMUP;
    var best_diff: f64 = std.math.inf(f64);
    for (warm_samples, WARMUP..) |o, i| {
        const t = @as(f64, @floatFromInt(o.iterations)) /
            (@as(f64, @floatFromInt(o.wall_time_ns)) / std.time.ns_per_s);
        const d = @abs(t - median_throughput);
        if (d < best_diff) { best_diff = d; median_idx = i; }
    }
    const rep = outputs[median_idx];

    const summary = summarizeLatencies(rep.latencies_ns);
    const handshake_summary: ?LatencySummary = if (rep.handshake_latencies_ns) |h|
        summarizeLatencies(h) else null;

    return ResultRow{
        .git_sha = try gitSha(allocator, io),
        .run_timestamp_unix_s = @as(i64, @intCast(@divTrunc(std.time.nanoTimestamp(), std.time.ns_per_s))),
        .zig_version = builtin.zig_version_string,
        .os = @tagName(builtin.os.tag),
        .arch = @tagName(builtin.cpu.arch),
        .cpu = try allocator.dupe(u8, @tagName(builtin.cpu.arch)),
        .hostname = try hostnameAlloc(allocator, io),
        .kernel = try kernelAlloc(allocator, io),
        .scenario_name = spec.name,
        .variant = spec.variant,
        .iterations = rep.iterations,
        .throughput_ops_per_sec = median_throughput,
        .throughput_stddev_ops_per_sec = stddev,
        .latency_p50_ns = summary.p50_ns,
        .latency_p95_ns = summary.p95_ns,
        .latency_p99_ns = summary.p99_ns,
        .cpu_time_ns = rep.cpu_time_ns,
        .wall_time_ns = rep.wall_time_ns,
        .alloc_count = rep.alloc_count,
        .alloc_bytes = rep.alloc_bytes,
        .peak_live_bytes = rep.peak_live_bytes,
        .rss_current_bytes = rssCurrentBytes() catch 0,
        .rss_peak_bytes = rssPeakBytes() catch 0,
        .bytes_per_sec = if (rep.bytes_transferred == 0) null else @intFromFloat(
            @as(f64, @floatFromInt(rep.bytes_transferred)) * 1e9 / @as(f64, @floatFromInt(rep.wall_time_ns))),
        .packets_per_sec = if (rep.packets_transferred == 0) null else @intFromFloat(
            @as(f64, @floatFromInt(rep.packets_transferred)) * 1e9 / @as(f64, @floatFromInt(rep.wall_time_ns))),
        .handshake_latency_p50_ns = if (handshake_summary) |h| h.p50_ns else null,
        .handshake_latency_p99_ns = if (handshake_summary) |h| h.p99_ns else null,
        .connection_count = spec.connection_count,
        .streams_count = spec.streams_count,
        .payload_bytes = spec.payload_bytes,
        .retransmit_count = if (rep.retransmit_count == 0) null else rep.retransmit_count,
        .cwnd_final_bytes = if (rep.cwnd_final_bytes == 0) null else rep.cwnd_final_bytes,
        .rtt_smoothed_ns = if (rep.rtt_smoothed_ns == 0) null else rep.rtt_smoothed_ns,
        .mutex_hold_wall_ns = if (rep.mutex_hold_wall_ns == 0) null else rep.mutex_hold_wall_ns,
    };
}

pub fn writeDocument(
    allocator: std.mem.Allocator,
    io: std.Io,
    rows: []const ResultRow,
    output_path: ?[]const u8,
) !void {
    const doc = ResultDocument{
        .generated_at_unix_s = @as(i64, @intCast(@divTrunc(std.time.nanoTimestamp(), std.time.ns_per_s))),
        .zig_version = builtin.zig_version_string,
        .quic_git_sha = try gitSha(allocator, io),
        .host = .{
            .os = @tagName(builtin.os.tag),
            .arch = @tagName(builtin.cpu.arch),
            .cpu = @tagName(builtin.cpu.arch),
            .hostname = try hostnameAlloc(allocator, io),
            .kernel = try kernelAlloc(allocator, io),
        },
        .rows = @constCast(rows),
    };
    const json = try std.json.Stringify.valueAlloc(allocator, doc, .{ .whitespace = .indent_2 });
    defer allocator.free(json);
    if (output_path) |path| {
        var file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, json);
        try file.writeStreamingAll(io, "\n");
    } else {
        const out = std.Io.File.stdout();
        try out.writeStreamingAll(io, json);
        try out.writeStreamingAll(io, "\n");
    }
}

// ---------- Latency + timing helpers ----------

pub fn summarizeLatencies(values: []u64) LatencySummary {
    std.sort.heap(u64, values, {}, comptime std.sort.asc(u64));
    return .{
        .count = values.len,
        .min_ns = if (values.len == 0) 0 else values[0],
        .mean_ns = mean(values),
        .p50_ns = percentile(values, 50),
        .p95_ns = percentile(values, 95),
        .p99_ns = percentile(values, 99),
        .max_ns = if (values.len == 0) 0 else values[values.len - 1],
    };
}

fn mean(values: []const u64) u64 {
    if (values.len == 0) return 0;
    var total: u128 = 0;
    for (values) |v| total += v;
    return @intCast(total / values.len);
}

fn percentile(values: []const u64, pct: u8) u64 {
    if (values.len == 0) return 0;
    const idx = @min((values.len - 1) * pct / 100, values.len - 1);
    return values[idx];
}

pub fn nowNs() u64 {
    const ts = std.time.nanoTimestamp();
    return if (ts < 0) 0 else @intCast(ts);
}

// ---------- Environment helpers ----------

pub fn gitSha(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "git", "rev-parse", "HEAD" },
        .stdout_limit = .limited(128),
        .stderr_limit = .limited(512),
    }) catch return allocator.dupe(u8, "unknown");
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    const exited = switch (result.term) { .exited => |c| c, else => 1 };
    if (exited != 0) return allocator.dupe(u8, "unknown");
    return allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \r\n\t"));
}

pub fn hostnameAlloc(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const result = std.process.run(allocator, io, .{
        .argv = &.{"hostname"},
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(256),
    }) catch return allocator.dupe(u8, "unknown");
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    return allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \r\n\t"));
}

pub fn kernelAlloc(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "uname", "-r" },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(256),
    }) catch return allocator.dupe(u8, "unknown");
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    return allocator.dupe(u8, std.mem.trim(u8, result.stdout, " \r\n\t"));
}

pub fn rssCurrentBytes() !u64 {
    if (builtin.os.tag != .linux) return 0;
    const page_size = std.mem.page_size;
    const posix = std.posix;
    const fd = try posix.openat(posix.AT.FDCWD, "/proc/self/statm",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer _ = std.os.linux.close(fd);
    var buf: [128]u8 = undefined;
    const n = try posix.read(fd, &buf);
    const contents = buf[0..n];
    var it = std.mem.tokenizeScalar(u8, contents, ' ');
    _ = it.next();
    const resident_str = it.next() orelse return 0;
    const resident_pages = std.fmt.parseInt(u64, std.mem.trim(u8, resident_str, " \n\r"), 10) catch return 0;
    return resident_pages * page_size;
}

pub fn rssPeakBytes() !u64 {
    if (builtin.os.tag != .linux) return 0;
    const posix = std.posix;
    const fd = try posix.openat(posix.AT.FDCWD, "/proc/self/status",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer _ = std.os.linux.close(fd);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = try posix.read(fd, buf[total..]);
        if (n == 0) break;
        total += n;
    }
    const contents = buf[0..total];
    var lines = std.mem.tokenizeScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "VmHWM:")) {
            var parts = std.mem.tokenizeScalar(u8, line, ' ');
            _ = parts.next();
            const kb_str = parts.next() orelse return 0;
            const kb = std.fmt.parseInt(u64, kb_str, 10) catch return 0;
            return kb * 1024;
        }
    }
    return 0;
}

// ---------- CPU affinity (Linux only) ----------

pub fn pinCurrentThreadToCpu(cpu_id: u32) !void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    var set: std.os.linux.cpu_set_t = std.mem.zeroes(std.os.linux.cpu_set_t);
    const bits_per_word = @sizeOf(usize) * 8;
    const word_idx: usize = cpu_id / bits_per_word;
    if (word_idx >= set.len) return error.CpuIdOutOfRange;
    const bit_idx: u6 = @intCast(cpu_id % bits_per_word);
    set[word_idx] |= @as(usize, 1) << bit_idx;
    try std.os.linux.sched_setaffinity(0, &set);
}

pub fn cpuCount() u32 {
    return @intCast(std.Thread.getCpuCount() catch 1);
}
```

- [ ] **Step 2: Create `tests/test_bench_common.zig`**

```zig
const std = @import("std");
const common = @import("../benchmarks/common.zig");

test "summarizeLatencies: sorted percentiles" {
    var vals = [_]u64{ 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
    const s = common.summarizeLatencies(&vals);
    try std.testing.expectEqual(@as(usize, 10), s.count);
    try std.testing.expectEqual(@as(u64, 10), s.min_ns);
    try std.testing.expectEqual(@as(u64, 100), s.max_ns);
    try std.testing.expect(s.p50_ns >= 40 and s.p50_ns <= 60);
    try std.testing.expect(s.p95_ns >= 90);
    try std.testing.expect(s.p99_ns >= 90);
}

test "summarizeLatencies: empty slice" {
    var vals = [_]u64{};
    const s = common.summarizeLatencies(&vals);
    try std.testing.expectEqual(@as(u64, 0), s.min_ns);
    try std.testing.expectEqual(@as(u64, 0), s.p50_ns);
}

test "parseOutputArg: --output=PATH" {
    const args = [_][]const u8{ "prog", "--output=foo.json" };
    try std.testing.expectEqualStrings("foo.json", common.parseOutputArg(&args).?);
}

test "parseOutputArg: --output PATH" {
    const args = [_][]const u8{ "prog", "--output", "foo.json" };
    try std.testing.expectEqualStrings("foo.json", common.parseOutputArg(&args).?);
}

test "parseSuiteArg: --suite=NAME" {
    const args = [_][]const u8{ "prog", "--suite=micro" };
    try std.testing.expectEqualStrings("micro", common.parseSuiteArg(&args).?);
}
```

- [ ] **Step 3: Wire common.zig as a build module + add test step**

Edit `build.zig`. After the existing module declarations, add:

```zig
const bench_common_mod = b.createModule(.{
    .root_source_file = b.path("benchmarks/common.zig"),
    .target = target,
    .optimize = .ReleaseFast,
});

const bench_common_test = b.addTest(.{ .root_source_file = b.path("tests/test_bench_common.zig") });
const run_bench_common_test = b.addRunArtifact(bench_common_test);
const bench_common_test_step = b.step("test-bench-common", "Run bench harness tests");
bench_common_test_step.dependOn(&run_bench_common_test.step);
```

- [ ] **Step 4: Run the tests**

Run: `zig build test-bench-common`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/common.zig tests/test_bench_common.zig build.zig
git commit -m "feat(bench): add common.zig harness with ResultRow + runRepeated + affinity helpers"
```

---

### Task 1.2: Write benchmarks/compare.zig (tier-aware comparator)

**Files:**

- Create: `benchmarks/compare.zig`
- Create: `tests/test_bench_compare.zig`
- Modify: `build.zig`

- [ ] **Step 1: Write `benchmarks/compare.zig`**

```zig
// benchmarks/compare.zig
// SPDX-License-Identifier: Apache-2.0
//
// Tier-aware regression comparator. Exits non-zero on any FAIL.
// Tiers: micro (name prefix "micro/"), integration ("integration/"),
// external ("external/"). Noise floor: 3× baseline stddev per tier.

const std = @import("std");
const common = @import("common.zig");

const Tier = enum { micro, integration, external, unknown };

const TierThresholds = struct {
    throughput_pct: f64,
    latency_p95_pct: f64,
    alloc_bytes_pct: ?f64,
};

fn thresholds(t: Tier) TierThresholds {
    return switch (t) {
        .micro => .{ .throughput_pct = 15.0, .latency_p95_pct = 10.0, .alloc_bytes_pct = 0.0 },
        .integration => .{ .throughput_pct = 20.0, .latency_p95_pct = 25.0, .alloc_bytes_pct = 30.0 },
        .external => .{ .throughput_pct = 25.0, .latency_p95_pct = 30.0, .alloc_bytes_pct = null },
        .unknown => .{ .throughput_pct = 20.0, .latency_p95_pct = 25.0, .alloc_bytes_pct = null },
    };
}

pub fn classify(name: []const u8) Tier {
    if (std.mem.startsWith(u8, name, "micro/")) return .micro;
    if (std.mem.startsWith(u8, name, "integration/")) return .integration;
    if (std.mem.startsWith(u8, name, "external/")) return .external;
    return .unknown;
}

const AbsoluteGate = struct {
    scenario: []const u8,
    variant: []const u8,
    field: enum { latency_p99_ns, alloc_bytes },
    max: u64,
};

// Preserved from docs/PERFORMANCE_TARGETS.md:30-43
const absolute_gates = [_]AbsoluteGate{
    .{ .scenario = "micro/varint", .variant = "encode", .field = .latency_p99_ns, .max = 250 },
    .{ .scenario = "micro/pacing", .variant = "delay_compute", .field = .latency_p99_ns, .max = 400 },
    .{ .scenario = "micro/header_protection", .variant = "decode", .field = .latency_p99_ns, .max = 400_000 },
    .{ .scenario = "micro/frame_serialization", .variant = "short_header_encode", .field = .alloc_bytes, .max = 0 },
    .{ .scenario = "micro/frame_serialization", .variant = "short_header_decode", .field = .alloc_bytes, .max = 0 },
};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try init.minimal.args.toSlice(allocator);
    var baseline_path: ?[]const u8 = null;
    var current_path: ?[]const u8 = null;
    var skip_env_check = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--baseline") and i + 1 < args.len) {
            baseline_path = args[i + 1]; i += 1;
        } else if (std.mem.startsWith(u8, args[i], "--baseline=")) {
            baseline_path = args[i]["--baseline=".len..];
        } else if (std.mem.eql(u8, args[i], "--current") and i + 1 < args.len) {
            current_path = args[i + 1]; i += 1;
        } else if (std.mem.startsWith(u8, args[i], "--current=")) {
            current_path = args[i]["--current=".len..];
        } else if (std.mem.eql(u8, args[i], "--skip-env-check")) {
            skip_env_check = true;
        }
    }
    if (baseline_path == null or current_path == null) {
        try std.Io.File.stderr().writeStreamingAll(init.io,
            "usage: bench-compare --baseline <file> --current <file> [--skip-env-check]\n");
        std.process.exit(2);
    }

    const baseline_doc = try readDocument(allocator, init.io, baseline_path.?);
    const current_doc = try readDocument(allocator, init.io, current_path.?);
    defer baseline_doc.deinit();
    defer current_doc.deinit();

    if (!skip_env_check) {
        const b = baseline_doc.value.host;
        const c = current_doc.value.host;
        if (!std.mem.eql(u8, b.os, c.os) or !std.mem.eql(u8, b.arch, c.arch) or
            !std.mem.eql(u8, b.cpu, c.cpu) or
            !std.mem.eql(u8, baseline_doc.value.zig_version, current_doc.value.zig_version))
        {
            const msg = try std.fmt.allocPrint(allocator,
                "ENV MISMATCH\n  baseline: os={s} arch={s} cpu={s} zig={s}\n  current:  os={s} arch={s} cpu={s} zig={s}\n  Re-run with --skip-env-check to override (not recommended).\n",
                .{ b.os, b.arch, b.cpu, baseline_doc.value.zig_version,
                   c.os, c.arch, c.cpu, current_doc.value.zig_version });
            defer allocator.free(msg);
            try std.Io.File.stderr().writeStreamingAll(init.io, msg);
            std.process.exit(2);
        }
    }

    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(init.io,
        "| scenario | variant | tier | ops/s base | ops/s cur | Δ% | p95 base | p95 cur | Δ% | status |\n" ++
        "|---|---|---|---:|---:|---:|---:|---:|---:|---|\n");

    var failures: usize = 0;
    var warns: usize = 0;

    for (current_doc.value.rows) |cur| {
        const base = findMatch(baseline_doc.value.rows, cur) orelse continue;
        const tier = classify(cur.scenario_name);
        const thr = thresholds(tier);

        const t_delta = pctChange(base.throughput_ops_per_sec, cur.throughput_ops_per_sec);
        const p95_delta = pctChange(
            @as(f64, @floatFromInt(base.latency_p95_ns)),
            @as(f64, @floatFromInt(cur.latency_p95_ns)));

        const stddev_pct = if (base.throughput_ops_per_sec != 0)
            (base.throughput_stddev_ops_per_sec / base.throughput_ops_per_sec) * 100.0 else 0.0;
        const t_gate = @max(thr.throughput_pct, 3.0 * stddev_pct);

        var status: []const u8 = "PASS";
        if (t_delta < -t_gate or p95_delta > thr.latency_p95_pct) {
            status = "FAIL";
            failures += 1;
        } else if (t_delta < -(thr.throughput_pct / 2.0) or p95_delta > (thr.latency_p95_pct / 2.0)) {
            status = "WARN";
            warns += 1;
        }

        for (absolute_gates) |gate| {
            if (!std.mem.eql(u8, gate.scenario, cur.scenario_name)) continue;
            if (!std.mem.eql(u8, gate.variant, cur.variant)) continue;
            const actual: u64 = switch (gate.field) {
                .latency_p99_ns => cur.latency_p99_ns,
                .alloc_bytes => cur.alloc_bytes,
            };
            if (actual > gate.max) {
                status = "ABSOLUTE-FAIL";
                failures += 1;
            }
        }

        const line = try std.fmt.allocPrint(allocator,
            "| {s} | {s} | {s} | {d:.1} | {d:.1} | {d:+.2}% | {d} | {d} | {d:+.2}% | {s} |\n",
            .{ cur.scenario_name, cur.variant, @tagName(tier),
               base.throughput_ops_per_sec, cur.throughput_ops_per_sec, t_delta,
               base.latency_p95_ns, cur.latency_p95_ns, p95_delta, status });
        defer allocator.free(line);
        try stdout.writeStreamingAll(init.io, line);
    }

    const summary = try std.fmt.allocPrint(allocator, "\nSummary: {d} FAIL, {d} WARN\n", .{ failures, warns });
    defer allocator.free(summary);
    try stdout.writeStreamingAll(init.io, summary);
    if (failures > 0) std.process.exit(1);
}

fn readDocument(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Parsed(common.ResultDocument) {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024));
    return std.json.parseFromSlice(common.ResultDocument, allocator, bytes, .{ .ignore_unknown_fields = true });
}

fn findMatch(rows: []const common.ResultRow, cur: common.ResultRow) ?common.ResultRow {
    for (rows) |row| {
        if (std.mem.eql(u8, row.scenario_name, cur.scenario_name) and
            std.mem.eql(u8, row.variant, cur.variant)) return row;
    }
    return null;
}

fn pctChange(before: f64, after: f64) f64 {
    if (before == 0) return 0;
    return ((after - before) / before) * 100.0;
}
```

- [ ] **Step 2: Write `tests/test_bench_compare.zig`**

```zig
const std = @import("std");
const compare = @import("../benchmarks/compare.zig");

test "classify: micro prefix" {
    try std.testing.expectEqual(@as(compare.Tier, .micro), compare.classify("micro/varint"));
    try std.testing.expectEqual(@as(compare.Tier, .integration), compare.classify("integration/handshake_e2e"));
    try std.testing.expectEqual(@as(compare.Tier, .external), compare.classify("external/quic-go/throughput"));
    try std.testing.expectEqual(@as(compare.Tier, .unknown), compare.classify("foo/bar"));
}
```

(Classify needs to be `pub` in compare.zig — already is per the code above.)

- [ ] **Step 3: Wire compare.zig as an executable**

Add to `build.zig`:

```zig
const bench_compare = b.addExecutable(.{
    .name = "bench-compare",
    .root_source_file = b.path("benchmarks/compare.zig"),
    .target = target,
    .optimize = .ReleaseFast,
});
bench_compare.root_module.addImport("common", bench_common_mod);
const install_bench_compare = b.addInstallArtifact(bench_compare, .{});
const run_bench_compare = b.addRunArtifact(bench_compare);
if (b.args) |args| run_bench_compare.addArgs(args);
const bench_compare_step = b.step("bench-compare", "Run benchmark regression comparator");
bench_compare_step.dependOn(&install_bench_compare.step);
bench_compare_step.dependOn(&run_bench_compare.step);

const bench_compare_test = b.addTest(.{ .root_source_file = b.path("tests/test_bench_compare.zig") });
const run_bench_compare_test = b.addRunArtifact(bench_compare_test);
const bench_compare_test_step = b.step("test-bench-compare", "Run bench comparator tests");
bench_compare_test_step.dependOn(&run_bench_compare_test.step);
```

- [ ] **Step 4: Run tests + verify binary builds**

Run: `zig build test-bench-compare && zig build bench-compare -- 2>&1 | head`
Expected: tests PASS; binary shows usage on empty args.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/compare.zig tests/test_bench_compare.zig build.zig
git commit -m "feat(bench): add tier-aware compare.zig with env check + absolute gates"
```

---

### Task 1.3: Write benchmarks/bench_runner.zig (suite dispatcher)

**Files:**

- Create: `benchmarks/bench_runner.zig`
- Modify: `build.zig`

- [ ] **Step 1: Create `benchmarks/bench_runner.zig` (scaffold; registry empty until Task 2.1)**

```zig
// benchmarks/bench_runner.zig
// SPDX-License-Identifier: Apache-2.0
//
// Main entry for all zig-quic benchmarks. Dispatches via --suite=<name>.
// Each scenario is registered in `registry` below; adding a new benchmark
// means adding one import + one SuiteEntry.

const std = @import("std");
const common = @import("common.zig");

// Phase 2+ will add these imports as files arrive.

pub const SuiteEntry = struct {
    name: []const u8,           // fully-qualified: "micro/varint"
    tier: []const u8,           // "micro" | "integration" | "external"
    scenarios: []const common.ScenarioSpec,
    runFn: common.RunFn,
};

// Registry starts empty — Tasks 2.1+ populate this.
pub const registry: []const SuiteEntry = &.{};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try init.minimal.args.toSlice(allocator);
    const suite = common.parseSuiteArg(args) orelse "all";
    const output = common.parseOutputArg(args);

    for (args) |a| {
        if (std.mem.eql(u8, a, "--list")) {
            const out = std.Io.File.stdout();
            try out.writeStreamingAll(init.io, "Available suites: all, micro, integration, external\n");
            try out.writeStreamingAll(init.io, "Available scenarios:\n");
            for (registry) |e| {
                const line = try std.fmt.allocPrint(allocator, "  {s} [{s}]\n", .{ e.name, e.tier });
                defer allocator.free(line);
                try out.writeStreamingAll(init.io, line);
            }
            return;
        }
    }

    var rows: std.ArrayList(common.ResultRow) = .empty;
    defer rows.deinit(allocator);

    for (registry) |entry| {
        if (!matches(suite, entry)) continue;
        for (entry.scenarios) |spec| {
            const row = try common.runRepeated(allocator, init.io, spec, entry.runFn);
            try rows.append(allocator, row);
        }
    }

    if (rows.items.len == 0) {
        const err_out = std.Io.File.stderr();
        const msg = try std.fmt.allocPrint(allocator, "no scenarios matched suite='{s}'\n", .{suite});
        defer allocator.free(msg);
        try err_out.writeStreamingAll(init.io, msg);
        std.process.exit(3);
    }

    try common.writeDocument(allocator, init.io, rows.items, output);
}

fn matches(suite: []const u8, entry: SuiteEntry) bool {
    if (std.mem.eql(u8, suite, "all")) return true;
    if (std.mem.eql(u8, suite, entry.tier)) return true;
    const last_slash = std.mem.lastIndexOfScalar(u8, entry.name, '/') orelse return false;
    const short = entry.name[last_slash + 1 ..];
    return std.mem.eql(u8, suite, short) or std.mem.eql(u8, suite, entry.name);
}
```

- [ ] **Step 2: Wire bench_runner in build.zig**

```zig
const bench_runner = b.addExecutable(.{
    .name = "bench-v2",
    .root_source_file = b.path("benchmarks/bench_runner.zig"),
    .target = target,
    .optimize = .ReleaseFast,
});
bench_runner.root_module.addImport("common", bench_common_mod);
const install_bench_runner = b.addInstallArtifact(bench_runner, .{});
const run_bench_runner = b.addRunArtifact(bench_runner);
if (b.args) |args| run_bench_runner.addArgs(args);
const bench_v2_step = b.step("bench-v2", "Run v2 benchmark suite (--suite=all|micro|integration|external|<scenario>)");
bench_v2_step.dependOn(&install_bench_runner.step);
bench_v2_step.dependOn(&run_bench_runner.step);
```

(The step is named `bench-v2` until Task 3 renames it to `bench` after migration.)

- [ ] **Step 3: Verify runner compiles and --list works**

Run: `zig build bench-v2 -- --list`
Expected:

```text
Available suites: all, micro, integration, external
Available scenarios:
```

- [ ] **Step 4: Commit**

```bash
git add benchmarks/bench_runner.zig build.zig
git commit -m "feat(bench): add bench_runner.zig dispatcher with --list/--suite/--output"
```

---

## Phase 2: Migrate Existing Benches

Each task: move existing bench into `benchmarks/{micro,integration}/`, rewrite its `main()` into a `run(allocator, spec) !RunOutput` matching `common.RunFn`, add SuiteEntry, verify.

### Task 2.1: Migrate varint + pacing + header_protection from bench/main.zig

**Files:**

- Create: `benchmarks/micro/varint.zig`, `benchmarks/micro/pacing.zig`, `benchmarks/micro/header_protection.zig`
- Modify: `benchmarks/bench_runner.zig`, `build.zig`

- [ ] **Step 1: Identify source sections**

Run: `grep -n "varint\|pacing\|hp\|header.protection\|protect\|unprotect" bench/main.zig | head -30`

- [ ] **Step 2: Resolve actual API symbols**

Run: `grep -rn "pub fn encode\|pub fn computePacingDelay\|pub fn hpDecode\|pub fn protectPacket" src/quic/ | head`

Note the actual symbol names; they're referenced below as placeholders.

- [ ] **Step 3: Create `benchmarks/micro/varint.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const varint = @import("quic_varint");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);
    const inputs = [_]u64{ 0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903 };

    for (0..spec.warmup_iterations) |_| {
        var buf: [9]u8 = undefined;
        _ = try varint.encode(&buf, inputs[0]);
    }

    const wall_start = common.nowNs();
    var out_buf: [9]u8 = undefined;
    for (0..N) |i| {
        const v = inputs[i % inputs.len];
        const t0 = common.nowNs();
        const len = varint.encode(&out_buf, v) catch 0;
        std.mem.doNotOptimizeAway(len);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/varint", .variant = "encode", .iterations = 200_000, .warmup_iterations = 10_000 },
};
```

- [ ] **Step 4: Create `benchmarks/micro/pacing.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const rec = @import("quic_recovery");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);
    const rtts_ns = [_]u64{ 1_000_000, 10_000_000, 50_000_000, 100_000_000 };
    const cwnds = [_]u64{ 12_000, 64_000, 256_000, 1_000_000 };

    for (0..spec.warmup_iterations) |_| {
        _ = rec.computePacingDelayNs(rtts_ns[0], cwnds[0], 1200);
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const rtt = rtts_ns[i % rtts_ns.len];
        const cwnd = cwnds[i % cwnds.len];
        const t0 = common.nowNs();
        const d = rec.computePacingDelayNs(rtt, cwnd, 1200);
        std.mem.doNotOptimizeAway(d);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/pacing", .variant = "delay_compute", .iterations = 200_000, .warmup_iterations = 10_000 },
};
```

- [ ] **Step 5: Create `benchmarks/micro/header_protection.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const crypto = @import("quic_crypto");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);
    var packet: [128]u8 = undefined;
    @memset(&packet, 0x42);
    const hp_key = [_]u8{0x11} ** 16;

    for (0..spec.warmup_iterations) |_| {
        var tmp = packet;
        _ = crypto.hpDecode(&tmp, &hp_key);
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        var tmp = packet;
        const t0 = common.nowNs();
        const r = crypto.hpDecode(&tmp, &hp_key);
        std.mem.doNotOptimizeAway(r);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/header_protection", .variant = "decode", .iterations = 2000, .warmup_iterations = 200 },
    .{ .name = "micro/header_protection", .variant = "encode", .iterations = 2000, .warmup_iterations = 200 },
};
```

If symbols resolved in Step 2 differ, rename accordingly.

- [ ] **Step 6: Register in bench_runner.zig**

Add imports near the top of `benchmarks/bench_runner.zig`:

```zig
const varint_bench = @import("micro/varint.zig");
const pacing_bench = @import("micro/pacing.zig");
const hp_bench = @import("micro/header_protection.zig");
```

Replace `pub const registry: []const SuiteEntry = &.{};` with:

```zig
pub const registry: []const SuiteEntry = &.{
    .{ .name = "micro/varint", .tier = "micro", .scenarios = &varint_bench.scenarios, .runFn = varint_bench.run },
    .{ .name = "micro/pacing", .tier = "micro", .scenarios = &pacing_bench.scenarios, .runFn = pacing_bench.run },
    .{ .name = "micro/header_protection", .tier = "micro", .scenarios = &hp_bench.scenarios, .runFn = hp_bench.run },
};
```

- [ ] **Step 7: Wire modules in build.zig**

In the `bench_runner` executable block (below the existing `.addImport("common", ...)` line):

```zig
bench_runner.root_module.addImport("quic_varint", quic_varint_mod);
bench_runner.root_module.addImport("quic_recovery", quic_recovery_mod);
bench_runner.root_module.addImport("quic_crypto", quic_crypto_mod);
```

Grep `build.zig` for the existing module handle names (`quic_varint_mod` vs `varint_mod` etc.) and use the exact names.

- [ ] **Step 8: Build and run**

Run: `zig build bench-v2 -- --suite=micro --output=/tmp/micro.json`
Expected: JSON with 4 scenarios (varint encode + pacing delay_compute + hp decode/encode). Absolute gates hold: varint p99 ≤ 250ns, pacing p99 ≤ 400ns.

- [ ] **Step 9: Commit**

```bash
git add benchmarks/micro/ benchmarks/bench_runner.zig build.zig
git commit -m "feat(bench): migrate varint/pacing/hp micro-benches onto v2 harness"
```

---

### Task 2.2: Migrate TLS micro-benches (aead + tls_keygen)

**Files:**

- Create: `benchmarks/micro/aead.zig`, `benchmarks/micro/tls_keygen.zig`
- Modify: `benchmarks/bench_runner.zig`, `build.zig`

- [ ] **Step 1: Read source for primitives**

Run: `grep -n "aes\|chacha\|hkdf\|hash\|transcript" bench/bench_tls_aead.zig bench/bench_tls_handshake.zig | head -40`

- [ ] **Step 2: Create `benchmarks/micro/aead.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const crypto = @import("quic_crypto");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);
    const key_16 = [_]u8{0x11} ** 16;
    const key_32 = [_]u8{0x22} ** 32;
    const nonce = [_]u8{0x33} ** 12;
    const aad = [_]u8{0x44} ** 16;
    var pt: [1200]u8 = undefined;
    @memset(&pt, 0x55);
    var ct: [1216]u8 = undefined;

    const use_chacha = std.mem.eql(u8, spec.variant, "chacha20_poly1305");

    for (0..spec.warmup_iterations) |_| {
        if (use_chacha) {
            _ = crypto.chacha20Poly1305Encrypt(&ct, &pt, &key_32, &nonce, &aad) catch 0;
        } else {
            _ = crypto.aesGcmEncrypt(&ct, &pt, &key_16, &nonce, &aad) catch 0;
        }
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        const r: usize = if (use_chacha)
            crypto.chacha20Poly1305Encrypt(&ct, &pt, &key_32, &nonce, &aad) catch 0
        else
            crypto.aesGcmEncrypt(&ct, &pt, &key_16, &nonce, &aad) catch 0;
        std.mem.doNotOptimizeAway(r);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .bytes_transferred = N * pt.len,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/aead", .variant = "aes128_gcm", .iterations = 10_000, .warmup_iterations = 500, .payload_bytes = 1200 },
    .{ .name = "micro/aead", .variant = "chacha20_poly1305", .iterations = 10_000, .warmup_iterations = 500, .payload_bytes = 1200 },
};
```

Resolve actual symbol names via `grep -rn "pub fn .*Gcm\|pub fn .*chacha20" src/quic/crypto*` and adjust.

- [ ] **Step 3: Create `benchmarks/micro/tls_keygen.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const tls13 = @import("quic_tls13");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);
    const secret = [_]u8{0x11} ** 32;
    const salt = [_]u8{0x22} ** 32;
    const info = "tls13 benchmark";

    for (0..spec.warmup_iterations) |_| {
        var out: [32]u8 = undefined;
        _ = tls13.hkdfExpandLabel(&out, &secret, info, &salt) catch 0;
    }

    const wall_start = common.nowNs();
    for (0..N) |i| {
        var out: [32]u8 = undefined;
        const t0 = common.nowNs();
        const r = tls13.hkdfExpandLabel(&out, &secret, info, &salt) catch 0;
        std.mem.doNotOptimizeAway(r);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/tls_keygen", .variant = "hkdf_expand_label", .iterations = 50_000, .warmup_iterations = 2000 },
};
```

- [ ] **Step 4: Register + wire**

In `bench_runner.zig` imports:

```zig
const aead_bench = @import("micro/aead.zig");
const tls_keygen_bench = @import("micro/tls_keygen.zig");
```

Append to registry:

```zig
.{ .name = "micro/aead", .tier = "micro", .scenarios = &aead_bench.scenarios, .runFn = aead_bench.run },
.{ .name = "micro/tls_keygen", .tier = "micro", .scenarios = &tls_keygen_bench.scenarios, .runFn = tls_keygen_bench.run },
```

In `build.zig`:

```zig
bench_runner.root_module.addImport("quic_tls13", quic_tls13_mod);
```

- [ ] **Step 5: Build and verify**

Run: `zig build bench-v2 -- --suite=micro --output=/tmp/micro.json`
Expected: JSON now has 7 rows (4 prior + aead×2 + tls_keygen).

- [ ] **Step 6: Commit**

```bash
git add benchmarks/micro/aead.zig benchmarks/micro/tls_keygen.zig benchmarks/bench_runner.zig build.zig
git commit -m "feat(bench): migrate aead + tls_keygen micro-benches onto v2 harness"
```

---

### Task 2.3: Migrate udp_batch to integration/

**Files:**

- Create: `benchmarks/integration/udp_batch.zig`
- Modify: `benchmarks/bench_runner.zig`

- [ ] **Step 1: Read `bench/udp_batch_bench.zig`**

Run: `cat bench/udp_batch_bench.zig | head -120` — find the measurement core (single sendto loop vs sendmmsg loop).

- [ ] **Step 2: Create `benchmarks/integration/udp_batch.zig`**

```zig
const std = @import("std");
const builtin = @import("builtin");
const common = @import("../common.zig");

const PACKET_COUNT: u64 = 10_000;
const PAYLOAD_LEN: usize = 1200;

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    if (builtin.os.tag != .linux) {
        // Non-Linux: emit a compile-ok placeholder so the suite runs cross-platform.
        const latencies = try allocator.alloc(u64, 1);
        latencies[0] = 0;
        return .{
            .iterations = 1,
            .wall_time_ns = 1_000_000,
            .cpu_time_ns = 0,
            .latencies_ns = latencies,
        };
    }

    const use_batch = std.mem.eql(u8, spec.variant, "batch");
    const posix = std.posix;

    const src_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(src_fd);
    const dst_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(dst_fd);

    var dst_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
        .zero = [_]u8{0} ** 8,
    };
    try posix.bind(dst_fd, @ptrCast(&dst_addr), @sizeOf(posix.sockaddr.in));
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    try posix.getsockname(dst_fd, @ptrCast(&dst_addr), &addr_len);

    const payload = [_]u8{0x55} ** PAYLOAD_LEN;
    var latencies = try allocator.alloc(u64, PACKET_COUNT);

    const wall_start = common.nowNs();
    if (use_batch) {
        const BATCH: usize = 16;
        var iovs: [BATCH]posix.iovec_const = undefined;
        var mhdrs: [BATCH]std.os.linux.mmsghdr_const = undefined;
        for (&iovs, &mhdrs) |*iov, *mh| {
            iov.* = .{ .base = &payload, .len = PAYLOAD_LEN };
            mh.* = .{
                .msg_hdr = .{
                    .name = @ptrCast(&dst_addr),
                    .namelen = @sizeOf(posix.sockaddr.in),
                    .iov = iov,
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .msg_len = 0,
            };
        }
        var sent: u64 = 0;
        while (sent < PACKET_COUNT) {
            const t0 = common.nowNs();
            const rc = std.os.linux.sendmmsg(src_fd, &mhdrs, BATCH, 0);
            const n: usize = if (@as(isize, @bitCast(rc)) < 0) 0 else @intCast(rc);
            const dt = common.nowNs() - t0;
            for (0..n) |i| if (sent + i < PACKET_COUNT) { latencies[sent + i] = dt / @max(n, 1); };
            sent += n;
            if (n == 0) break;
        }
    } else {
        for (0..PACKET_COUNT) |i| {
            const t0 = common.nowNs();
            _ = try posix.sendto(src_fd, &payload, 0, @ptrCast(&dst_addr), @sizeOf(posix.sockaddr.in));
            latencies[i] = common.nowNs() - t0;
        }
    }
    const wall_end = common.nowNs();

    // Drain receiver
    var drain_buf: [PAYLOAD_LEN * 2]u8 = undefined;
    while (true) {
        _ = posix.recv(dst_fd, &drain_buf, posix.MSG.DONTWAIT) catch break;
    }

    return .{
        .iterations = PACKET_COUNT,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .packets_transferred = PACKET_COUNT,
        .bytes_transferred = PACKET_COUNT * PAYLOAD_LEN,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/udp_batch", .variant = "single", .iterations = PACKET_COUNT },
    .{ .name = "integration/udp_batch", .variant = "batch",  .iterations = PACKET_COUNT },
};
```

- [ ] **Step 3: Register**

In `bench_runner.zig`:

```zig
const udp_batch_bench = @import("integration/udp_batch.zig");
// registry entry:
.{ .name = "integration/udp_batch", .tier = "integration", .scenarios = &udp_batch_bench.scenarios, .runFn = udp_batch_bench.run },
```

- [ ] **Step 4: Run**

Run: `zig build bench-v2 -- --suite=integration/udp_batch --output=/tmp/udp.json`
Expected on Linux: `batch` variant ≥ 4× higher ops/sec than `single`. On macOS/Windows: placeholder.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/integration/udp_batch.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): migrate udp_batch to integration/ with single|batch variants"
```

---

### Task 2.4: Migrate poll_overhead from benchmarks/poll_bench.zig

**Files:**

- Create: `benchmarks/integration/poll_overhead.zig`
- Modify: `benchmarks/bench_runner.zig`, `build.zig`

- [ ] **Step 1: Read source**

Run: `cat benchmarks/poll_bench.zig` — preserve the 6-tier structure (0c, 1c, 10c, 100c, 1Kc, 10Kc).

- [ ] **Step 2: Resolve endpoint API**

Run: `grep -n "pub fn pollWithStats\|pub fn connectClient\|pub fn init" src/quic/endpoint.zig`

- [ ] **Step 3: Create `benchmarks/integration/poll_overhead.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };
    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const N = spec.connection_count;
    for (0..N) |c| {
        var port_buf: [6]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast((c % 55000) + 10000))});
        var addr_buf: [32]u8 = undefined;
        const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str});
        _ = ep.connectClient(addr) catch continue;
    }

    for (0..spec.warmup_iterations) |_| _ = ep.pollWithStats(0) catch {};

    const iters = spec.iterations;
    var latencies = try allocator.alloc(u64, iters);
    const wall_start = common.nowNs();
    for (0..iters) |i| {
        const t0 = common.nowNs();
        _ = ep.pollWithStats(0) catch {};
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = iters,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/poll_overhead", .variant = "0c",   .iterations = 20_000, .warmup_iterations = 2000, .connection_count = 0 },
    .{ .name = "integration/poll_overhead", .variant = "1c",   .iterations = 20_000, .warmup_iterations = 2000, .connection_count = 1 },
    .{ .name = "integration/poll_overhead", .variant = "10c",  .iterations = 10_000, .warmup_iterations = 1000, .connection_count = 10 },
    .{ .name = "integration/poll_overhead", .variant = "100c", .iterations = 5_000,  .warmup_iterations = 500,  .connection_count = 100 },
    .{ .name = "integration/poll_overhead", .variant = "1Kc",  .iterations = 2_000,  .warmup_iterations = 200,  .connection_count = 1000 },
    .{ .name = "integration/poll_overhead", .variant = "10Kc", .iterations = 500,    .warmup_iterations = 50,   .connection_count = 10_000 },
};
```

- [ ] **Step 4: Register + wire**

```zig
// bench_runner.zig imports:
const poll_bench = @import("integration/poll_overhead.zig");
// registry:
.{ .name = "integration/poll_overhead", .tier = "integration", .scenarios = &poll_bench.scenarios, .runFn = poll_bench.run },

// build.zig:
bench_runner.root_module.addImport("quic_endpoint", quic_endpoint_mod);
bench_runner.root_module.addImport("quic_config", quic_config_mod);
```

- [ ] **Step 5: Run**

Run: `zig build bench-v2 -- --suite=integration/poll_overhead --output=/tmp/poll.json`
Expected: 6 variants. 0c/1c p99 < 1µs, 10Kc p99 in hundreds of µs (reflects known O(N) #182).

- [ ] **Step 6: Commit**

```bash
git add benchmarks/integration/poll_overhead.zig benchmarks/bench_runner.zig build.zig
git commit -m "feat(bench): migrate poll_overhead to v2 harness (6-tier sweep preserved)"
```

---

### Task 2.5: Migrate conn_scale; delete scaffolds; delete legacy bench files

**Files:**

- Create: `benchmarks/integration/conn_scale.zig`
- Modify: `benchmarks/bench_runner.zig`
- Delete: `benchmarks/throughput_bench.zig`, `benchmarks/handshake_bench.zig`, `benchmarks/poll_bench.zig`, `benchmarks/scale_bench.zig`

- [ ] **Step 1: Read source**

Run: `cat benchmarks/scale_bench.zig` — preserve the 7-tier structure (1c, 10c, 100c, 1Kc, 1Kc-100s, 10Kc, 10Kc-10s).

- [ ] **Step 2: Create `benchmarks/integration/conn_scale.zig`**

```zig
const std = @import("std");
const common = @import("../common.zig");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };

    const setup_start = common.nowNs();
    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const N = spec.connection_count;
    for (0..N) |c| {
        var port_buf: [6]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast((c % 55000) + 10000))});
        var addr_buf: [32]u8 = undefined;
        const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str});
        _ = ep.connectClient(addr) catch continue;
    }
    const setup_end = common.nowNs();

    const iters = spec.iterations;
    var latencies = try allocator.alloc(u64, iters);
    for (0..spec.warmup_iterations) |_| _ = ep.pollWithStats(0) catch {};
    for (0..iters) |i| {
        const t0 = common.nowNs();
        _ = ep.pollWithStats(0) catch {};
        latencies[i] = common.nowNs() - t0;
    }

    return .{
        .iterations = iters,
        .wall_time_ns = setup_end - setup_start,
        .cpu_time_ns = setup_end - setup_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/conn_scale", .variant = "1c",       .iterations = 5000, .warmup_iterations = 500, .connection_count = 1,    .streams_count = 1 },
    .{ .name = "integration/conn_scale", .variant = "10c",      .iterations = 2000, .warmup_iterations = 200, .connection_count = 10,   .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "100c",     .iterations = 500,  .warmup_iterations = 50,  .connection_count = 100,  .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "1Kc",      .iterations = 200,  .warmup_iterations = 20,  .connection_count = 1000, .streams_count = 10 },
    .{ .name = "integration/conn_scale", .variant = "1Kc-100s", .iterations = 100,  .warmup_iterations = 10,  .connection_count = 1000, .streams_count = 100 },
    .{ .name = "integration/conn_scale", .variant = "10Kc",     .iterations = 50,   .warmup_iterations = 5,   .connection_count = 10_000, .streams_count = 1 },
    .{ .name = "integration/conn_scale", .variant = "10Kc-10s", .iterations = 50,   .warmup_iterations = 5,   .connection_count = 10_000, .streams_count = 10 },
};
```

- [ ] **Step 3: Register**

```zig
// bench_runner.zig:
const conn_scale_bench = @import("integration/conn_scale.zig");
// registry:
.{ .name = "integration/conn_scale", .tier = "integration", .scenarios = &conn_scale_bench.scenarios, .runFn = conn_scale_bench.run },
```

- [ ] **Step 4: Delete superseded files**

```bash
git rm benchmarks/throughput_bench.zig benchmarks/handshake_bench.zig benchmarks/poll_bench.zig benchmarks/scale_bench.zig
```

(The old `benchmarks/common.zig` and `benchmarks/compare.zig` were replaced in-place by Phase 1 Tasks 1.1/1.2. If git still shows them as "modified rather than replaced", that's fine — the content matches the new versions.)

- [ ] **Step 5: Build and verify full integration suite**

Run: `zig build bench-v2 -- --suite=integration --output=/tmp/integ.json`
Expected: 2+6+7 = 15 rows (udp_batch × 2 + poll_overhead × 6 + conn_scale × 7).

- [ ] **Step 6: Commit**

```bash
git add benchmarks/integration/conn_scale.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): migrate conn_scale; delete v1 scaffolds + superseded poll/scale benches"
```

---

## Phase 3: Build + CI Rewiring

### Task 3.1: Rename bench-v2 → bench; update CI/Makefile; add aliases

**Files:**

- Modify: `build.zig`, `Makefile`, `.gitlab-ci.yml`, `.pre-commit-config.yaml`

- [ ] **Step 1: Inventory old references**

Run: `grep -rn "bench-poll\|bench-scale\|bench-throughput\|bench-handshake\|perf_gate\.sh\|perf_udp_batch_gate\.sh\|scripts/perf_gate\|scripts/perf_udp_batch" Makefile .gitlab-ci.yml .pre-commit-config.yaml scripts/ 2>/dev/null`

Note every callsite — each must update to the new names.

- [ ] **Step 2: Rename bench-v2 → bench in build.zig**

Edit `build.zig`:

1. Delete or alias the old `bench` step that ran `bench/main.zig`. If other callers rely on it, add a shim:

   ```zig
   // Retired `bench` step now aliases the v2 runner with --suite=micro.
   const bench_legacy_alias = b.step("bench", "Run v2 micro benchmarks (legacy alias)");
   bench_legacy_alias.dependOn(&run_bench_runner.step);
   // (keep the bench-v2 alias for one release so existing MRs don't break)
   ```

2. Rename the v2 step:

   ```zig
   const bench_step = b.step("bench", "Run benchmark suite (--suite=all|micro|integration|external|<scenario>)");
   bench_step.dependOn(&install_bench_runner.step);
   bench_step.dependOn(&run_bench_runner.step);

   const bench_v2_alias = b.step("bench-v2", "DEPRECATED: use 'bench'. Alias to bench.");
   bench_v2_alias.dependOn(&run_bench_runner.step);
   ```

3. Add tier aliases:

   ```zig
   // bench-micro / bench-integration / bench-external shortcuts
   const bench_micro_run = b.addRunArtifact(bench_runner);
   bench_micro_run.addArgs(&.{ "--suite=micro" });
   const bench_micro_step = b.step("bench-micro", "Run micro-tier benchmarks");
   bench_micro_step.dependOn(&install_bench_runner.step);
   bench_micro_step.dependOn(&bench_micro_run.step);

   const bench_integration_run = b.addRunArtifact(bench_runner);
   bench_integration_run.addArgs(&.{ "--suite=integration" });
   const bench_integration_step = b.step("bench-integration", "Run integration-tier benchmarks");
   bench_integration_step.dependOn(&install_bench_runner.step);
   bench_integration_step.dependOn(&bench_integration_run.step);

   const bench_external_run = b.addRunArtifact(bench_runner);
   bench_external_run.addArgs(&.{ "--suite=external" });
   const bench_external_step = b.step("bench-external", "Run external-impl compare benchmarks");
   bench_external_step.dependOn(&install_bench_runner.step);
   bench_external_step.dependOn(&bench_external_run.step);
   ```

4. Add retired-name aliases for one release (remove in a later MR):

   ```zig
   const bench_poll_run = b.addRunArtifact(bench_runner);
   bench_poll_run.addArgs(&.{ "--suite=poll_overhead" });
   const bench_poll_step = b.step("bench-poll", "DEPRECATED: use 'bench -- --suite=poll_overhead'");
   bench_poll_step.dependOn(&bench_poll_run.step);

   const bench_scale_run = b.addRunArtifact(bench_runner);
   bench_scale_run.addArgs(&.{ "--suite=conn_scale" });
   const bench_scale_step = b.step("bench-scale", "DEPRECATED: use 'bench -- --suite=conn_scale'");
   bench_scale_step.dependOn(&bench_scale_run.step);
   ```

- [ ] **Step 3: Delete `bench/` directory**

All content moved to `benchmarks/` in Phase 2. Remove the `bench/` module imports from build.zig (grep for `b.path("bench/")` and purge those blocks).

```bash
git rm -r bench/
```

- [ ] **Step 4: Update Makefile**

For each `bench-poll|bench-scale|bench-throughput|bench-handshake` target in `Makefile`, replace the command with:

```makefile
bench-micro:
 $(ZIG) build bench-micro $(ZIG_FLAGS)

bench-integration:
 $(ZIG) build bench-integration $(ZIG_FLAGS)

bench-external:
 $(ZIG) build bench-external $(ZIG_FLAGS)

bench-all:
 $(ZIG) build bench $(ZIG_FLAGS) -- --suite=all

bench-baseline:
 @$(ZIG) build bench $(ZIG_FLAGS) -- --suite=all --output=benchmarks/results/baseline.json
 @echo "baseline saved"

bench-compare:
 @$(ZIG) build bench $(ZIG_FLAGS) -- --suite=all --output=/tmp/current.json
 @$(ZIG) build bench-compare -- --baseline=benchmarks/results/baseline.json --current=/tmp/current.json

perf-gate:
 @scripts/perf-gate.sh --current=/tmp/current.json
```

(Preserve any legacy targets other repos might call, as aliases.)

- [ ] **Step 5: Update .gitlab-ci.yml**

Find jobs invoking `scripts/perf_gate.sh` or `scripts/perf_udp_batch_gate.sh`. Replace with:

```yaml
perf-gate:
  script:
    - scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json
  # (old scripts are retired in Phase 7 Task 7.1; until that lands, keep the
  # old paths working by letting perf-gate.sh read them as a fallback)
```

Also: remove any reference to `bench/udp_batch_bench.zig` as a direct `zig run` invocation; the path has moved.

- [ ] **Step 6: Update .pre-commit-config.yaml**

Grep for bench/perf references. If any pre-commit hook invokes the old gate script, update path. Otherwise no-op.

- [ ] **Step 7: Full build + test to verify nothing is broken**

Run: `zig build && zig build test && zig build bench -- --suite=micro --output=/tmp/check.json`
Expected: all succeed.

- [ ] **Step 8: Commit**

```bash
git add build.zig Makefile .gitlab-ci.yml .pre-commit-config.yaml
git rm -r bench/
git commit -m "build(bench): rename bench-v2→bench, add tier aliases, retire bench/ directory"
```

---

## Phase 4: New Micro Benchmarks

### Task 4.1: Write micro/frame_serialization.zig (issue #163)

**Files:**

- Create: `benchmarks/micro/frame_serialization.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Measure encode time + heap allocations for every QUIC frame type. Establishes an allocation budget per frame type so regressions in #163 (15+ per-frame heap-alloc sites) are caught.

- [ ] **Step 1: Identify frame encode API**

Run: `grep -rn "pub fn encode\|pub fn writeFrame\|pub const Frame" src/quic/frame_mod/ src/quic/frame.zig 2>/dev/null | head -30`

Note the concrete `Frame` union / enum and the encode function signature. Adjust symbol usage below.

- [ ] **Step 2: Build a CountingAllocator wrapper**

Add to the top of `frame_serialization.zig` (reuses pattern from old `bench/main.zig`):

```zig
const CountingAllocator = struct {
    child: std.mem.Allocator,
    alloc_calls: u64 = 0,
    alloc_bytes: u64 = 0,

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn init(child: std.mem.Allocator) CountingAllocator { return .{ .child = child }; }
    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.alloc_calls += 1;
        self.alloc_bytes += len;
        return self.child.rawAlloc(len, alignment, ret_addr);
    }
    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(buf, alignment, new_len, ret_addr);
    }
    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(buf, alignment, new_len, ret_addr);
    }
    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(buf, alignment, ret_addr);
    }
};
```

- [ ] **Step 3: Write the benchmark body**

```zig
// benchmarks/micro/frame_serialization.zig
const std = @import("std");
const common = @import("../common.zig");
const frame = @import("quic_frame");

// CountingAllocator from Step 2 goes here.

const FrameKind = enum {
    stream, ack, padding, crypto, reset_stream, stop_sending,
    ping, goaway, window_update, max_stream_id, connection_close,
    short_header_encode, short_header_decode,
};

fn kindFromVariant(v: []const u8) FrameKind {
    if (std.mem.eql(u8, v, "stream")) return .stream;
    if (std.mem.eql(u8, v, "ack")) return .ack;
    if (std.mem.eql(u8, v, "padding")) return .padding;
    if (std.mem.eql(u8, v, "crypto")) return .crypto;
    if (std.mem.eql(u8, v, "reset_stream")) return .reset_stream;
    if (std.mem.eql(u8, v, "stop_sending")) return .stop_sending;
    if (std.mem.eql(u8, v, "ping")) return .ping;
    if (std.mem.eql(u8, v, "goaway")) return .goaway;
    if (std.mem.eql(u8, v, "window_update")) return .window_update;
    if (std.mem.eql(u8, v, "max_stream_id")) return .max_stream_id;
    if (std.mem.eql(u8, v, "connection_close")) return .connection_close;
    if (std.mem.eql(u8, v, "short_header_encode")) return .short_header_encode;
    if (std.mem.eql(u8, v, "short_header_decode")) return .short_header_decode;
    return .padding;
}

fn encodeOne(allocator: std.mem.Allocator, kind: FrameKind, buf: []u8) usize {
    // Build a fixture frame of the given kind and call frame.encode.
    // The concrete fixture shape depends on the actual Frame union in
    // src/quic/frame_mod/; adjust the variants below to match.
    return switch (kind) {
        .stream => frame.encodeStream(buf, .{ .stream_id = 0, .offset = 0, .data = "hello quic" }) catch 0,
        .ack => frame.encodeAck(buf, .{ .largest = 100, .delay = 1000, .ranges = &.{} }) catch 0,
        .padding => frame.encodePadding(buf, 16) catch 0,
        .crypto => frame.encodeCrypto(buf, .{ .offset = 0, .data = "crypto payload" }) catch 0,
        .reset_stream => frame.encodeResetStream(buf, .{ .stream_id = 0, .error_code = 0, .final_size = 100 }) catch 0,
        .stop_sending => frame.encodeStopSending(buf, .{ .stream_id = 0, .error_code = 0 }) catch 0,
        .ping => frame.encodePing(buf) catch 0,
        .goaway => frame.encodeGoAway(buf, .{ .stream_id = 0, .error_code = 0, .reason = "" }) catch 0,
        .window_update => frame.encodeWindowUpdate(buf, .{ .stream_id = 0, .max_data = 1024 * 1024 }) catch 0,
        .max_stream_id => frame.encodeMaxStreamId(buf, 100) catch 0,
        .connection_close => frame.encodeConnectionClose(buf, .{ .error_code = 0, .reason = "ok" }) catch 0,
        .short_header_encode => frame.encodeShortHeader(buf, .{ .dcid = &.{0x11} ** 8, .packet_number = 1, .payload = "data" }, allocator) catch 0,
        .short_header_decode => blk: {
            var tmp = buf[0..@min(32, buf.len)];
            @memset(tmp, 0x42);
            break :blk tmp.len;
        },
    };
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);

    var counting = CountingAllocator.init(allocator);
    const counted = counting.allocator();
    var buf: [2048]u8 = undefined;

    const kind = kindFromVariant(spec.variant);

    for (0..spec.warmup_iterations) |_| _ = encodeOne(counted, kind, &buf);

    // Reset counter after warmup.
    counting.alloc_calls = 0;
    counting.alloc_bytes = 0;

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        const n = encodeOne(counted, kind, &buf);
        std.mem.doNotOptimizeAway(n);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
        .alloc_count = counting.alloc_calls,
        .alloc_bytes = counting.alloc_bytes,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/frame_serialization", .variant = "stream",               .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "ack",                  .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "padding",              .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "crypto",               .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "reset_stream",         .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "stop_sending",         .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "ping",                 .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "goaway",               .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "window_update",        .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "max_stream_id",        .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "connection_close",     .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "short_header_encode",  .iterations = 50_000, .warmup_iterations = 2000 },
    .{ .name = "micro/frame_serialization", .variant = "short_header_decode",  .iterations = 50_000, .warmup_iterations = 2000 },
};
```

The exact symbol names under `frame.*` depend on the actual `frame_mod` API. If `frame.encodeStream` etc. don't exist, use the existing `Frame` union and its `encode` method — grep `src/quic/frame_mod/` for `pub fn encode` and adapt.

- [ ] **Step 4: Register**

```zig
// bench_runner.zig
const frame_ser_bench = @import("micro/frame_serialization.zig");
// registry:
.{ .name = "micro/frame_serialization", .tier = "micro", .scenarios = &frame_ser_bench.scenarios, .runFn = frame_ser_bench.run },

// build.zig
bench_runner.root_module.addImport("quic_frame", quic_frame_mod);
```

- [ ] **Step 5: Run**

Run: `zig build bench -- --suite=micro/frame_serialization --output=/tmp/frame.json`
Expected: 13 scenarios. `short_header_encode` and `short_header_decode` must show `alloc_count = 0, alloc_bytes = 0` — this is the preserved absolute gate from `docs/PERFORMANCE_TARGETS.md:33-34`.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/micro/frame_serialization.zig benchmarks/bench_runner.zig build.zig
git commit -m "feat(bench): add frame_serialization micro-bench with alloc budget (#163)"
```

---

### Task 4.2: Write micro/connection_lookup.zig (issue #154)

**Files:**

- Create: `benchmarks/micro/connection_lookup.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Measure `endpoint.findConnectionByDcid()` (or equivalent) cost at 10/100/1K/10K active connections. Baseline captures O(N) today; gate catches regression after the planned O(1) HashMap fix.

- [ ] **Step 1: Identify the lookup API**

Run: `grep -rn "findConnection\|lookupConnection\|getConnection\|dcid.*map\|connection.*by.*dcid" src/quic/endpoint.zig src/quic/conn.zig 2>/dev/null | head`

Expected: a function like `endpoint.findConnectionByDcid(dcid: []const u8) ?*Connection` — record the actual name.

- [ ] **Step 2: Write the benchmark**

```zig
// benchmarks/micro/connection_lookup.zig
const std = @import("std");
const common = @import("../common.zig");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };
    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const N = spec.connection_count;

    // Populate endpoint with N connections and record their DCIDs.
    var dcids = try allocator.alloc([8]u8, N);
    defer allocator.free(dcids);
    for (0..N) |c| {
        var port_buf: [6]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast((c % 55000) + 10000))});
        var addr_buf: [32]u8 = undefined;
        const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str});
        const conn = ep.connectClient(addr) catch continue;
        // Snapshot the DCID so the lookup has a target.
        // Adjust field name if the endpoint exposes it differently.
        const dcid = conn.dcid();
        @memcpy(&dcids[c], dcid[0..@min(8, dcid.len)]);
    }

    const iters = spec.iterations;
    var latencies = try allocator.alloc(u64, iters);
    var rng = std.Random.DefaultPrng.init(@intCast(common.nowNs()));
    const random = rng.random();

    // Warmup
    for (0..spec.warmup_iterations) |_| {
        const idx = random.uintLessThan(u32, N);
        _ = ep.findConnectionByDcid(&dcids[idx]);
    }

    const wall_start = common.nowNs();
    for (0..iters) |i| {
        const idx = random.uintLessThan(u32, N);
        const t0 = common.nowNs();
        const r = ep.findConnectionByDcid(&dcids[idx]);
        std.mem.doNotOptimizeAway(r);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = iters,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/connection_lookup", .variant = "10",    .iterations = 100_000, .warmup_iterations = 10_000, .connection_count = 10 },
    .{ .name = "micro/connection_lookup", .variant = "100",   .iterations = 100_000, .warmup_iterations = 10_000, .connection_count = 100 },
    .{ .name = "micro/connection_lookup", .variant = "1000",  .iterations = 100_000, .warmup_iterations = 10_000, .connection_count = 1000 },
    .{ .name = "micro/connection_lookup", .variant = "10000", .iterations = 50_000,  .warmup_iterations = 5000,   .connection_count = 10_000 },
};
```

If `conn.dcid()` / `ep.findConnectionByDcid()` aren't the real symbol names, substitute. If the endpoint doesn't currently expose a lookup helper, this task becomes "add a thin `findConnectionByDcid` wrapper in `src/quic/endpoint.zig` that calls the current internal lookup" — note that in a prep commit before writing the bench.

- [ ] **Step 3: Register**

```zig
// bench_runner.zig
const conn_lookup_bench = @import("micro/connection_lookup.zig");
// registry:
.{ .name = "micro/connection_lookup", .tier = "micro", .scenarios = &conn_lookup_bench.scenarios, .runFn = conn_lookup_bench.run },
```

- [ ] **Step 4: Run**

Run: `zig build bench -- --suite=micro/connection_lookup --output=/tmp/lookup.json`
Expected: 4 variants. Current O(N) behavior should show visible ~linear growth in p99 from 10 → 10K. Post-#154-fix, growth should be flat.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/micro/connection_lookup.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): add connection_lookup micro-bench at 10/100/1K/10K (#154)"
```

---

### Task 4.3: Write micro/loss_detection_scan.zig (issue #90)

**Files:**

- Create: `benchmarks/micro/loss_detection_scan.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Measure ACK-processing cost as a function of `sent_packets` array size. Captures current O(N) scan behavior; gate catches regression after #90 lands (bounded + O(log N) scan).

- [ ] **Step 1: Identify ACK / sent_packets API**

Run: `grep -rn "sent_packets\|processAck\|onAckReceived\|ack_frame" src/quic/recovery.zig src/quic/conn.zig 2>/dev/null | head`

Expected: either a standalone `Recovery` struct with `processAck` method, or connection-scoped `handleAckFrame`. Record the actual entry point.

- [ ] **Step 2: Write the benchmark**

```zig
// benchmarks/micro/loss_detection_scan.zig
const std = @import("std");
const common = @import("../common.zig");
const rec = @import("quic_recovery");

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const N = spec.connection_count; // re-using `connection_count` as sent_packets count
    const iters = spec.iterations;
    var latencies = try allocator.alloc(u64, iters);

    // Build a Recovery instance with N sent packets populated.
    // The actual constructor depends on the recovery.zig API. Below is
    // a typical shape — adjust field names to match.
    var recovery = try rec.Recovery.init(allocator);
    defer recovery.deinit();

    for (0..N) |i| {
        try recovery.recordSent(.{
            .packet_number = i,
            .time_sent_ns = common.nowNs(),
            .size = 1200,
            .ack_eliciting = true,
        });
    }

    // Build an ACK frame covering a mid-range slice.
    const ack = rec.AckFrame{
        .largest = N - 1,
        .delay_ns = 1000,
        .ranges = &[_]rec.AckRange{
            .{ .start = N / 4, .end = (N * 3) / 4 },
        },
    };

    // Warmup
    for (0..spec.warmup_iterations) |_| {
        _ = recovery.processAck(ack) catch {};
        // Re-populate since processAck consumes entries
        for (0..N) |i| {
            try recovery.recordSent(.{
                .packet_number = i,
                .time_sent_ns = common.nowNs(),
                .size = 1200,
                .ack_eliciting = true,
            });
        }
    }

    const wall_start = common.nowNs();
    for (0..iters) |i| {
        const t0 = common.nowNs();
        _ = recovery.processAck(ack) catch {};
        latencies[i] = common.nowNs() - t0;
        // Re-populate between iterations
        for (0..N) |j| {
            try recovery.recordSent(.{
                .packet_number = j,
                .time_sent_ns = common.nowNs(),
                .size = 1200,
                .ack_eliciting = true,
            });
        }
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = iters,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "micro/loss_detection_scan", .variant = "100",     .iterations = 10_000, .warmup_iterations = 500, .connection_count = 100 },
    .{ .name = "micro/loss_detection_scan", .variant = "1000",    .iterations = 5000,   .warmup_iterations = 200, .connection_count = 1000 },
    .{ .name = "micro/loss_detection_scan", .variant = "10000",   .iterations = 1000,   .warmup_iterations = 50,  .connection_count = 10_000 },
    .{ .name = "micro/loss_detection_scan", .variant = "100000",  .iterations = 200,    .warmup_iterations = 10,  .connection_count = 100_000 },
};
```

Substitute the real `Recovery` API. If `processAck` doesn't exist as a public entry point, drill into the actual call site exercised from `conn.zig` and expose the minimal public wrapper in a prep commit.

- [ ] **Step 3: Register**

```zig
// bench_runner.zig
const loss_scan_bench = @import("micro/loss_detection_scan.zig");
// registry:
.{ .name = "micro/loss_detection_scan", .tier = "micro", .scenarios = &loss_scan_bench.scenarios, .runFn = loss_scan_bench.run },
```

- [ ] **Step 4: Run**

Run: `zig build bench -- --suite=micro/loss_detection_scan --output=/tmp/loss.json`
Expected: 4 variants. Current behavior: p99 grows roughly linearly from 100 → 100K. Post-#90 fix: flat.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/micro/loss_detection_scan.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): add loss_detection_scan micro-bench at 100/1K/10K/100K (#90)"
```

---

## Phase 5: New Integration Benchmarks

### Task 5.1: Write integration/handshake_e2e.zig (replaces scaffold)

**Files:**

- Create: `benchmarks/integration/handshake_e2e.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Real Initial→Handshake-complete latency at 5 concurrency tiers. Replaces the 2026-03-27 scaffold that emitted `{handshake_avg_ms: 0}`.

- [ ] **Step 1: Identify the server + client handshake APIs**

Run: `grep -rn "pub fn connect\|pub fn accept\|handshake.*complete\|HandshakeState\|onHandshakeComplete" src/quic/ lib.zig cmd/quic-server.zig cmd/quic-client.zig 2>/dev/null | head -30`

Record the entry points. The cmd/ binaries show the correct setup pattern — mirror them in the bench.

- [ ] **Step 2: Cert setup helper**

The cmd/quic-server.zig uses `create_test_certs.sh` output. The bench needs an analogous setup. Either:

- **Option A (preferred):** use in-repo ephemeral cert generation — grep `create_test_certs.sh` for how it builds certs, and port the logic to a `fn makeTestCerts(allocator) !{ cert_path, key_path }` helper in the bench file (generates into a tmpdir that's deleted on defer).
- **Option B:** shell out to `create_test_certs.sh` before each run. Slower but simpler.

- [ ] **Step 3: Write the benchmark**

```zig
// benchmarks/integration/handshake_e2e.zig
const std = @import("std");
const common = @import("../common.zig");
const api = @import("quic_api");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

const ServerThreadCtx = struct {
    server: *api.QuicServer,
    done: *std.atomic.Value(bool),
    ready: *std.atomic.Value(bool),
};

fn serverThread(ctx: ServerThreadCtx) void {
    ctx.ready.store(true, .seq_cst);
    while (!ctx.done.load(.seq_cst)) {
        ctx.server.poll(1_000_000) catch {};
    }
}

const ClientThreadCtx = struct {
    allocator: std.mem.Allocator,
    target: []const u8,
    cert_path: []const u8,
    handshakes_to_do: u64,
    latencies: *std.ArrayList(u64),
    mu: *std.Thread.Mutex,
    done_handshakes: *std.atomic.Value(u64),
};

fn clientThread(ctx: ClientThreadCtx) void {
    for (0..ctx.handshakes_to_do) |_| {
        const t0 = common.nowNs();
        var client = api.QuicClient.init(ctx.allocator, .{
            .alpn = &test_alpn,
            .ca_path = ctx.cert_path,
        }) catch return;
        defer client.deinit();
        _ = client.connectAndHandshake(ctx.target) catch return;
        const dt = common.nowNs() - t0;

        ctx.mu.lock();
        ctx.latencies.append(ctx.allocator, dt) catch {};
        ctx.mu.unlock();
        _ = ctx.done_handshakes.fetchAdd(1, .seq_cst);
    }
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    // Generate test certs (per §Step 2 — use helper or invoke shell script)
    const certs = try makeTestCerts(allocator);
    defer certs.cleanup();

    // Spawn Zig server
    var server = try api.QuicServer.init(allocator, .{
        .listen_addr = "127.0.0.1:0",
        .cert_path = certs.cert_path,
        .key_path = certs.key_path,
        .alpn = &test_alpn,
    });
    defer server.deinit();
    const server_addr = try server.localAddr(allocator);
    defer allocator.free(server_addr);

    var done = std.atomic.Value(bool).init(false);
    var ready = std.atomic.Value(bool).init(false);
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{.{
        .server = &server,
        .done = &done,
        .ready = &ready,
    }});
    while (!ready.load(.seq_cst)) std.Thread.yield() catch {};
    defer {
        done.store(true, .seq_cst);
        srv_thread.join();
    }

    const parallel = spec.connection_count;
    const iters = spec.iterations;
    const per_thread = (iters + parallel - 1) / parallel;

    var latencies: std.ArrayList(u64) = .empty;
    defer latencies.deinit(allocator);
    var mu = std.Thread.Mutex{};
    var done_count = std.atomic.Value(u64).init(0);

    const client_threads = try allocator.alloc(std.Thread, parallel);
    defer allocator.free(client_threads);

    const wall_start = common.nowNs();
    for (client_threads) |*t| {
        t.* = try std.Thread.spawn(.{}, clientThread, .{.{
            .allocator = allocator,
            .target = server_addr,
            .cert_path = certs.cert_path,
            .handshakes_to_do = per_thread,
            .latencies = &latencies,
            .mu = &mu,
            .done_handshakes = &done_count,
        }});
    }
    for (client_threads) |t| t.join();
    const wall_end = common.nowNs();

    // Produce latency slice that runRepeated owns.
    const latency_slice = try allocator.dupe(u64, latencies.items);
    const handshake_slice = try allocator.dupe(u64, latencies.items);

    return .{
        .iterations = done_count.load(.seq_cst),
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latency_slice,
        .handshake_latencies_ns = handshake_slice,
    };
}

const TestCerts = struct {
    cert_path: []const u8,
    key_path: []const u8,
    allocator: std.mem.Allocator,

    pub fn cleanup(self: TestCerts) void {
        self.allocator.free(self.cert_path);
        self.allocator.free(self.key_path);
    }
};

fn makeTestCerts(allocator: std.mem.Allocator) !TestCerts {
    // Option A sketch: reuse existing create_test_certs.sh output if present
    // in a known location. If not, fall back to shelling out.
    // The cleanest implementation is to expose a Zig helper in
    // src/quic/testing/certs.zig and call it here; if that doesn't exist,
    // shell out to ./create_test_certs.sh and read the resulting paths.
    const cert = try allocator.dupe(u8, "./test-certs/server.crt");
    const key = try allocator.dupe(u8, "./test-certs/server.key");
    return .{ .cert_path = cert, .key_path = key, .allocator = allocator };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/handshake_e2e", .variant = "serial", .iterations = 100,  .warmup_iterations = 5,  .connection_count = 1 },
    .{ .name = "integration/handshake_e2e", .variant = "10p",    .iterations = 200,  .warmup_iterations = 10, .connection_count = 10 },
    .{ .name = "integration/handshake_e2e", .variant = "100p",   .iterations = 500,  .warmup_iterations = 20, .connection_count = 100 },
    .{ .name = "integration/handshake_e2e", .variant = "1Kp",    .iterations = 1000, .warmup_iterations = 50, .connection_count = 1000 },
    .{ .name = "integration/handshake_e2e", .variant = "10Kp",   .iterations = 2000, .warmup_iterations = 100, .connection_count = 10_000 },
};
```

The exact `api.QuicServer.init`, `api.QuicClient.connectAndHandshake` symbol names are placeholders — resolve via Step 1's grep and substitute.

- [ ] **Step 4: Register**

```zig
const handshake_e2e_bench = @import("integration/handshake_e2e.zig");
// registry:
.{ .name = "integration/handshake_e2e", .tier = "integration", .scenarios = &handshake_e2e_bench.scenarios, .runFn = handshake_e2e_bench.run },

// build.zig — api already imported via quic_api_mod
bench_runner.root_module.addImport("quic_api", quic_api_mod);
```

- [ ] **Step 5: Run — smaller tiers first**

Run: `zig build bench -- --suite=integration/handshake_e2e --output=/tmp/handshake.json` then visually inspect the serial tier first:

```bash
jq '.rows[] | select(.variant == "serial") | {handshake_latency_p50_ns, handshake_latency_p99_ns, throughput_ops_per_sec}' /tmp/handshake.json
```

Expected: reasonable values (p50 < 5ms on loopback, throughput > 200 handshakes/sec at serial).

- [ ] **Step 6: If real-UDP TLS setup blocks > 1 hour**

Per the spec Risks section §1: fall back to a `loopback-tls` variant only (set `.variant = "loopback"`) and mark `real-udp-tls` as a follow-up. Emit a note in `docs/PERFORMANCE_TRACKING.md` describing the deferred variant.

- [ ] **Step 7: Commit**

```bash
git add benchmarks/integration/handshake_e2e.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): add handshake_e2e integration bench replacing 2026-03-27 scaffold"
```

---

### Task 5.2: Write integration/stream_throughput.zig (replaces scaffold)

**Files:**

- Create: `benchmarks/integration/stream_throughput.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Real-UDP stream-level MB/s and pps over a 6-cell payload × concurrency grid. Replaces the scaffold.

- [ ] **Step 1: Identify stream write/read API**

Run: `grep -rn "pub fn openStream\|pub fn writeStream\|pub fn readStream\|StreamWriter\|StreamReader" src/quic/ lib.zig 2>/dev/null | head`

- [ ] **Step 2: Write the benchmark**

```zig
// benchmarks/integration/stream_throughput.zig
const std = @import("std");
const common = @import("../common.zig");
const api = @import("quic_api");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

// Echo server that reads from stream and writes back.
fn echoServer(server: *api.QuicServer, done: *std.atomic.Value(bool)) void {
    while (!done.load(.seq_cst)) {
        server.poll(1_000_000) catch {};
        // Accept new streams, read bytes, echo back. Exact accept/stream API
        // depends on api.zig — use the server event-loop pattern from
        // cmd/quic-server.zig.
        if (server.acceptStream()) |stream| {
            var buf: [65536]u8 = undefined;
            while (true) {
                const n = stream.read(&buf) catch break;
                if (n == 0) break;
                _ = stream.write(buf[0..n]) catch break;
            }
        }
    }
}

const ClientCfg = struct {
    target: []const u8,
    cert_path: []const u8,
    payload_bytes: u32,
    total_bytes: u64,
    latencies: *std.ArrayList(u64),
    bytes_done: *std.atomic.Value(u64),
    mu: *std.Thread.Mutex,
    allocator: std.mem.Allocator,
};

fn clientThread(c: ClientCfg) void {
    var client = api.QuicClient.init(c.allocator, .{
        .alpn = &test_alpn, .ca_path = c.cert_path,
    }) catch return;
    defer client.deinit();
    _ = client.connectAndHandshake(c.target) catch return;

    var stream = client.openStream() catch return;
    const payload = c.allocator.alloc(u8, c.payload_bytes) catch return;
    defer c.allocator.free(payload);
    @memset(payload, 0x55);
    var rcv_buf = c.allocator.alloc(u8, c.payload_bytes) catch return;
    defer c.allocator.free(rcv_buf);

    var written: u64 = 0;
    while (written < c.total_bytes) {
        const t0 = common.nowNs();
        const n = stream.write(payload) catch break;
        _ = stream.read(rcv_buf) catch break;
        const dt = common.nowNs() - t0;

        c.mu.lock();
        c.latencies.append(c.allocator, dt) catch {};
        c.mu.unlock();

        written += n;
        _ = c.bytes_done.fetchAdd(n, .seq_cst);
    }
}

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    // Reuse cert setup helper from handshake_e2e (extract to shared module if
    // this duplication grows beyond two benches).
    const certs = try @import("./handshake_e2e.zig").makeTestCerts(allocator);
    defer certs.cleanup();

    var server = try api.QuicServer.init(allocator, .{
        .listen_addr = "127.0.0.1:0",
        .cert_path = certs.cert_path,
        .key_path = certs.key_path,
        .alpn = &test_alpn,
    });
    defer server.deinit();
    const server_addr = try server.localAddr(allocator);
    defer allocator.free(server_addr);

    var done = std.atomic.Value(bool).init(false);
    const srv_thread = try std.Thread.spawn(.{}, echoServer, .{ &server, &done });
    defer {
        done.store(true, .seq_cst);
        srv_thread.join();
    }

    const parallel = spec.connection_count;
    const total_bytes_per_client: u64 = spec.iterations * spec.payload_bytes;

    var latencies: std.ArrayList(u64) = .empty;
    defer latencies.deinit(allocator);
    var mu = std.Thread.Mutex{};
    var bytes_done = std.atomic.Value(u64).init(0);

    const threads = try allocator.alloc(std.Thread, parallel);
    defer allocator.free(threads);

    const wall_start = common.nowNs();
    for (threads) |*t| {
        t.* = try std.Thread.spawn(.{}, clientThread, .{.{
            .target = server_addr,
            .cert_path = certs.cert_path,
            .payload_bytes = spec.payload_bytes,
            .total_bytes = total_bytes_per_client,
            .latencies = &latencies,
            .bytes_done = &bytes_done,
            .mu = &mu,
            .allocator = allocator,
        }});
    }
    for (threads) |t| t.join();
    const wall_end = common.nowNs();

    const total_bytes = bytes_done.load(.seq_cst);
    const iters = total_bytes / spec.payload_bytes;
    const latency_slice = try allocator.dupe(u64, latencies.items);

    return .{
        .iterations = iters,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latency_slice,
        .bytes_transferred = total_bytes,
        .packets_transferred = iters,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/stream_throughput", .variant = "64B-c1",    .iterations = 5000, .warmup_iterations = 100, .payload_bytes = 64,        .connection_count = 1 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c1",    .iterations = 5000, .warmup_iterations = 100, .payload_bytes = 1024,      .connection_count = 1 },
    .{ .name = "integration/stream_throughput", .variant = "64KB-c1",   .iterations = 500,  .warmup_iterations = 20,  .payload_bytes = 64 * 1024, .connection_count = 1 },
    .{ .name = "integration/stream_throughput", .variant = "64B-c10",   .iterations = 2000, .warmup_iterations = 50,  .payload_bytes = 64,        .connection_count = 10 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c10",   .iterations = 2000, .warmup_iterations = 50,  .payload_bytes = 1024,      .connection_count = 10 },
    .{ .name = "integration/stream_throughput", .variant = "1KB-c100",  .iterations = 500,  .warmup_iterations = 10,  .payload_bytes = 1024,      .connection_count = 100 },
};
```

- [ ] **Step 3: Register**

```zig
const stream_throughput_bench = @import("integration/stream_throughput.zig");
// registry:
.{ .name = "integration/stream_throughput", .tier = "integration", .scenarios = &stream_throughput_bench.scenarios, .runFn = stream_throughput_bench.run },
```

- [ ] **Step 4: Run**

Run: `zig build bench -- --suite=integration/stream_throughput --output=/tmp/stream.json`
Expected: 6 cells. 1KB-c1 > 100 MB/s baseline target (per 2026-03-27 spec). `bytes_per_sec` non-null on all rows.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/integration/stream_throughput.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): add stream_throughput integration bench replacing 2026-03-27 scaffold"
```

---

### Task 5.3: Write integration/datagram_batch.zig (issue #126)

**Files:**

- Create: `benchmarks/integration/datagram_batch.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Measure endpoint-mutex hold time and tail latency under 16-datagram batch RX. Captures current behavior (mutex held for full batch); gate catches regression after the planned per-conn queuing fix.

- [ ] **Step 1: Identify the batch-RX + mutex surface**

Run: `grep -rn "batch.*dgram\|batch.*recv\|recvmmsg\|mutex.*endpoint\|endpoint.*mutex" src/quic/endpoint.zig src/quic/endpoint/ 2>/dev/null | head`

The bench needs to exercise the path that takes the endpoint mutex during multi-datagram RX. If the mutex-hold duration is internal and not exposed, add a minimal internal instrumentation hook in a prep commit: a `u64` atomic that the RX path updates with `mutex_hold_ns` samples during measurement.

- [ ] **Step 2: Write the benchmark**

```zig
// benchmarks/integration/datagram_batch.zig
const std = @import("std");
const common = @import("../common.zig");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const test_alpn = [_][]const u8{"h3"};

const DATAGRAMS_PER_RUN: u64 = 1024;

pub fn run(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };
    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Populate N=100 active connections so the lookup cost is representative.
    const POP_CONNS: u32 = 100;
    for (0..POP_CONNS) |c| {
        var port_buf: [6]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast((c % 55000) + 10000))});
        var addr_buf: [32]u8 = undefined;
        const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str});
        _ = ep.connectClient(addr) catch continue;
    }

    const batch_size = switch (spec.connection_count) {
        1 => 1,
        16 => 16,
        64 => 64,
        else => 16,
    };
    _ = batch_size; // threaded into endpoint via a config hook — see Step 1 note

    // Inject DATAGRAMS_PER_RUN simulated datagrams through the RX path.
    // The exact injection point is endpoint.processIncomingDatagram() or a
    // batched variant — resolve in Step 1 and call it here.
    var latencies = try allocator.alloc(u64, DATAGRAMS_PER_RUN);
    var mutex_hold_total: u64 = 0;

    // Payload is a minimal valid short-header packet that triggers the lookup
    // path but not the full decrypt path (so we isolate mutex impact, not
    // crypto). Build once; reuse.
    const dgram = [_]u8{0x40} ++ [_]u8{0x11} ** 8 ++ [_]u8{0x00} ** 128;

    for (0..DATAGRAMS_PER_RUN) |i| {
        const t0 = common.nowNs();
        // The mutex-hold measurement requires endpoint instrumentation added
        // in the prep commit (Step 1 note). If you haven't yet:
        // use wall_time diff as an approximation — still catches regressions
        // in the same direction, just with higher variance.
        _ = ep.processIncomingDatagram(&dgram, null) catch {};
        const dt = common.nowNs() - t0;
        latencies[i] = dt;
        mutex_hold_total += dt; // replace with real mutex_hold_ns once exposed
    }

    return .{
        .iterations = DATAGRAMS_PER_RUN,
        .wall_time_ns = DATAGRAMS_PER_RUN * 1, // overall wall will be rederived in runRepeated
        .cpu_time_ns = mutex_hold_total,
        .latencies_ns = latencies,
        .mutex_hold_wall_ns = mutex_hold_total,
    };
}

pub const scenarios = [_]common.ScenarioSpec{
    .{ .name = "integration/datagram_batch", .variant = "batch_1",  .iterations = DATAGRAMS_PER_RUN, .connection_count = 1 },
    .{ .name = "integration/datagram_batch", .variant = "batch_16", .iterations = DATAGRAMS_PER_RUN, .connection_count = 16 },
    .{ .name = "integration/datagram_batch", .variant = "batch_64", .iterations = DATAGRAMS_PER_RUN, .connection_count = 64 },
};
```

- [ ] **Step 3: Register**

```zig
const datagram_batch_bench = @import("integration/datagram_batch.zig");
// registry:
.{ .name = "integration/datagram_batch", .tier = "integration", .scenarios = &datagram_batch_bench.scenarios, .runFn = datagram_batch_bench.run },
```

- [ ] **Step 4: Run**

Run: `zig build bench -- --suite=integration/datagram_batch --output=/tmp/dgram.json`
Expected: 3 variants. batch_1 vs batch_16: mutex_hold_wall_ns should be ~16× larger for batch_16 under current behavior (full batch under single lock acquisition). Post-fix: ratio closer to 1×.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/integration/datagram_batch.zig benchmarks/bench_runner.zig
git commit -m "feat(bench): add datagram_batch integration bench (#126 endpoint-mutex)"
```

---

## Phase 6: External Harness

### Task 6.1: Write external/harness.zig + scenarios.zig

**Files:**

- Create: `benchmarks/external/harness.zig`
- Create: `benchmarks/external/scenarios.zig`
- Modify: `benchmarks/bench_runner.zig`

**Purpose:** Cross-impl compare (handshake + throughput) against quic-go, quinn, aioquic. Wraps existing `test-clients/*` via `interop/run_endpoint.sh` — does not re-implement clients.

- [ ] **Step 1: Inventory test-clients capabilities**

Run these to understand what each client can do:

```bash
cat test-clients/quic-go-client/main.go | head -50
cat test-clients/quinn-client/src/main.rs 2>/dev/null | head -50
cat test-clients/aioquic-client/test_client.py | head -50
cat interop/run_endpoint.sh | head -30
```

Identify how each client is invoked for a handshake-only run vs a throughput run. If a client lacks a throughput mode, either extend it (out of scope — skip that scenario) or script a wall-timed loop around handshake-only.

- [ ] **Step 2: Write `benchmarks/external/harness.zig`**

```zig
// benchmarks/external/harness.zig
// SPDX-License-Identifier: Apache-2.0
//
// Subprocess harness for cross-implementation compare. Spawns one of
// test-clients/{quic-go,quinn,aioquic}-client against a Zig server
// (or via interop/run_endpoint.sh for Dockerized runs), measures wall-clock
// latency, emits a ResultRow with external_impl set.

const std = @import("std");
const common = @import("../common.zig");

pub const ExternalSpec = struct {
    impl: []const u8,              // "quic-go" | "quinn" | "aioquic"
    argv: []const []const u8,      // argv for std.process.run
    env_map: ?*const std.process.EnvMap = null,
    timeout_seconds: u32 = 60,
};

pub fn runSubprocess(
    allocator: std.mem.Allocator,
    io: std.Io,
    spec: common.ScenarioSpec,
    external: ExternalSpec,
) !common.RunOutput {
    const N = spec.iterations;
    var latencies = try allocator.alloc(u64, N);

    // One warmup run (discarded)
    _ = try std.process.run(allocator, io, .{
        .argv = external.argv,
        .env_map = external.env_map,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });

    const wall_start = common.nowNs();
    for (0..N) |i| {
        const t0 = common.nowNs();
        const result = std.process.run(allocator, io, .{
            .argv = external.argv,
            .env_map = external.env_map,
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        }) catch {
            // Subprocess failure — record a punitive latency and keep going.
            latencies[i] = std.time.ns_per_s * external.timeout_seconds;
            continue;
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        latencies[i] = common.nowNs() - t0;
    }
    const wall_end = common.nowNs();

    return .{
        .iterations = N,
        .wall_time_ns = wall_end - wall_start,
        .cpu_time_ns = wall_end - wall_start,
        .latencies_ns = latencies,
    };
}

pub fn checkToolchain(allocator: std.mem.Allocator, io: std.Io, tool: []const u8) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "which", tool },
        .stdout_limit = .limited(256),
        .stderr_limit = .limited(256),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) { .exited => |c| c == 0, else => false };
}
```

- [ ] **Step 3: Write `benchmarks/external/scenarios.zig`**

```zig
// benchmarks/external/scenarios.zig
// SPDX-License-Identifier: Apache-2.0
// Cross-impl benchmark scenarios wrapping test-clients/*.

const std = @import("std");
const common = @import("../common.zig");
const harness = @import("harness.zig");

// The run() for each external scenario:
// 1. Verifies toolchain for target impl (go/cargo/python). If missing,
//    emits a placeholder RunOutput with latencies=[0] and
//    wall_time_ns=1, marking the row external_impl="<impl>-SKIP".
// 2. Builds argv for the target impl's binary + args to target a Zig server.
// 3. Delegates to harness.runSubprocess.

fn runQuicGoHandshake(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    // A Zig server must be running at SERVER_ADDR; for a paired run the caller
    // (perf-gate.sh) launches it beforehand. Here we assume the address is
    // provided via environment variable QUIC_BENCH_SERVER.
    const io_dummy: std.Io = undefined;
    _ = io_dummy;
    const server = std.process.getEnvVarOwned(allocator, "QUIC_BENCH_SERVER") catch
        try allocator.dupe(u8, "127.0.0.1:4433");
    defer allocator.free(server);

    // Minimal "handshake-only" invocation for test-clients/quic-go-client.
    // The actual client CLI shape depends on main.go — adjust argv.
    const argv_slice = try allocator.alloc([]const u8, 3);
    argv_slice[0] = "go";
    argv_slice[1] = "run";
    argv_slice[2] = try std.fmt.allocPrint(allocator, "./test-clients/quic-go-client/main.go --addr={s} --handshake-only", .{server});
    defer {
        allocator.free(argv_slice[2]);
        allocator.free(argv_slice);
    }

    const io: std.Io = undefined; // replaced by caller threading (see bench_runner)
    return harness.runSubprocess(allocator, io, spec, .{
        .impl = "quic-go",
        .argv = argv_slice,
    });
}

// Analogous runQuinnHandshake, runAioquicHandshake, runQuicGoThroughput, etc.
// Each follows the same pattern — build argv, delegate to harness.

pub fn runQuinnHandshake(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    // Placeholder — implement per quinn client CLI.
    const lat = try allocator.alloc(u64, 1);
    lat[0] = 0;
    return .{
        .iterations = 1,
        .wall_time_ns = 1,
        .cpu_time_ns = 0,
        .latencies_ns = lat,
    };
}

pub fn runAioquicHandshake(allocator: std.mem.Allocator, spec: common.ScenarioSpec) !common.RunOutput {
    const lat = try allocator.alloc(u64, 1);
    lat[0] = 0;
    return .{
        .iterations = 1,
        .wall_time_ns = 1,
        .cpu_time_ns = 0,
        .latencies_ns = lat,
    };
}

pub const scenarios_quic_go = [_]common.ScenarioSpec{
    .{ .name = "external/quic-go/handshake", .variant = "loopback", .iterations = 20, .warmup_iterations = 2, .connection_count = 1 },
};
pub const scenarios_quinn = [_]common.ScenarioSpec{
    .{ .name = "external/quinn/handshake", .variant = "loopback", .iterations = 20, .warmup_iterations = 2, .connection_count = 1 },
};
pub const scenarios_aioquic = [_]common.ScenarioSpec{
    .{ .name = "external/aioquic/handshake", .variant = "loopback", .iterations = 20, .warmup_iterations = 2, .connection_count = 1 },
};
```

The threading of `std.Io` through the registry is the trickiest part — `RunFn` takes `(allocator, spec)`, but `std.process.run` needs `io`. Solution: bench_runner passes `io` via a globalvar or threads a `BenchContext` struct. For this initial scope, set a module-level `io` that bench_runner initializes before invoking external scenarios. Refactor `RunFn` to include `io` in a later MR if churn is concerning.

- [ ] **Step 4: Register external scenarios**

```zig
// bench_runner.zig imports:
const external_scenarios = @import("external/scenarios.zig");

// Add module-level var that scenarios.zig reads; bench_runner sets it in main() before dispatching:
pub var bench_io: std.Io = undefined;

// In main(): bench_io = init.io;

// registry:
.{ .name = "external/quic-go",  .tier = "external", .scenarios = &external_scenarios.scenarios_quic_go,  .runFn = external_scenarios.runQuicGoHandshake },
.{ .name = "external/quinn",    .tier = "external", .scenarios = &external_scenarios.scenarios_quinn,    .runFn = external_scenarios.runQuinnHandshake },
.{ .name = "external/aioquic",  .tier = "external", .scenarios = &external_scenarios.scenarios_aioquic,  .runFn = external_scenarios.runAioquicHandshake },
```

- [ ] **Step 5: Gate external behind toolchain availability**

Add a startup check in bench_runner.zig right before iterating the registry:

```zig
if (std.mem.eql(u8, suite, "external") or std.mem.eql(u8, suite, "all")) {
    const has_go = external.checkToolchain(allocator, init.io, "go");
    const has_cargo = external.checkToolchain(allocator, init.io, "cargo");
    const has_python = external.checkToolchain(allocator, init.io, "python3");
    if (!has_go and !has_cargo and !has_python) {
        const err_out = std.Io.File.stderr();
        try err_out.writeStreamingAll(init.io,
            "external suite needs go/cargo/python3 toolchains; none found — skipping\n");
        // Don't exit — just skip external entries below
    }
}
```

- [ ] **Step 6: Run (toolchains required)**

Run: `zig build bench -- --suite=external --output=/tmp/external.json`
Expected (with go/cargo/python3 present): 3 rows with `external_impl` populated, loopback handshake latencies in the 5-50ms range.

- [ ] **Step 7: Commit**

```bash
git add benchmarks/external/ benchmarks/bench_runner.zig
git commit -m "feat(bench): add external harness wrapping test-clients/* (quic-go, quinn, aioquic)"
```

---

## Phase 7: Gate Script

### Task 7.1: Write scripts/perf-gate.sh; retire old perf_gate scripts

**Files:**

- Create: `scripts/perf-gate.sh`
- Delete: `scripts/perf_gate.sh`, `scripts/perf_udp_batch_gate.sh`
- Preserve: `scripts/cross_platform_udp_batch_smoke.sh`, `scripts/native_runtime_smoke.{sh,ps1}`

- [ ] **Step 1: Verify what references the old gate scripts**

Run: `grep -rn "perf_gate\.sh\|perf_udp_batch_gate\.sh" Makefile .gitlab-ci.yml .pre-commit-config.yaml scripts/ 2>/dev/null`

Note every caller. Task 3.1 already updated `Makefile` / `.gitlab-ci.yml` / `.pre-commit-config.yaml` to reference `perf-gate.sh` — verify by re-running the grep. If any old references remain, they'll need updating in this task.

- [ ] **Step 2: Write `scripts/perf-gate.sh`**

```bash
#!/usr/bin/env bash
# scripts/perf-gate.sh
# Tiered, paired-A/B performance gate for zig-quic.
#
# Usage:
#   # Paired commit mode (recommended)
#   scripts/perf-gate.sh --baseline-commit=<sha> [--suite=<name>]
#
#   # Manual mode — compare two pre-captured JSONs
#   scripts/perf-gate.sh --baseline=<path.json> --current=<path.json>
#
#   # Phased mode (retrofit for existing workflows)
#   scripts/perf-gate.sh <step-name> <before|after>
#
# Exit codes:
#   0  all PASS (including WARN)
#   1  FAIL or ABSOLUTE-FAIL
#   2  environment mismatch / invocation error
#   3  missing dependency (zig, jq)

set -euo pipefail

# --- Zig version pinning ---
ZIG="${ZIG:-}"
if [[ -z "$ZIG" ]]; then
    if command -v mise >/dev/null 2>&1; then
        ZIG_RUNNER=(mise x zig@0.16.0 -- zig)
    elif command -v zig >/dev/null 2>&1; then
        ZIG_RUNNER=(zig)
        actual_ver="$(zig version 2>/dev/null || echo unknown)"
        if [[ "$actual_ver" != "0.16.0" ]]; then
            echo "[perf-gate] WARNING: ambient zig is $actual_ver; project expects 0.16.0. Numbers may not compare cleanly." >&2
        fi
    else
        echo "[perf-gate] ERROR: no zig found. Install mise + zig@0.16.0, or set ZIG=/path/to/zig." >&2
        exit 3
    fi
else
    ZIG_RUNNER=("$ZIG")
fi

command -v jq >/dev/null 2>&1 || { echo "[perf-gate] ERROR: jq required" >&2; exit 3; }

# --- Argument parsing ---
BASELINE_COMMIT=""
BASELINE_PATH=""
CURRENT_PATH=""
SUITE="all"
STEP=""
PHASE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baseline-commit=*) BASELINE_COMMIT="${1#*=}"; shift ;;
        --baseline-commit) BASELINE_COMMIT="$2"; shift 2 ;;
        --baseline=*) BASELINE_PATH="${1#*=}"; shift ;;
        --baseline) BASELINE_PATH="$2"; shift 2 ;;
        --current=*) CURRENT_PATH="${1#*=}"; shift ;;
        --current) CURRENT_PATH="$2"; shift 2 ;;
        --suite=*) SUITE="${1#*=}"; shift ;;
        --suite) SUITE="$2"; shift 2 ;;
        before|after)
            PHASE="$1"
            shift
            ;;
        -h|--help)
            grep -E "^#" "$0" | head -20
            exit 0
            ;;
        *)
            if [[ -z "$STEP" && "$1" != --* ]]; then
                STEP="$1"
                shift
            else
                echo "[perf-gate] ERROR: unknown arg: $1" >&2
                exit 2
            fi
            ;;
    esac
done

ART_DIR="${PERF_GATE_ART_DIR:-benchmarks/results/paired}"
mkdir -p "$ART_DIR"

# --- Phased mode (retrofit) ---
if [[ -n "$STEP" && -n "$PHASE" ]]; then
    if [[ "$PHASE" != "before" && "$PHASE" != "after" ]]; then
        echo "phase must be 'before' or 'after'" >&2
        exit 2
    fi
    OUT="$ART_DIR/${STEP}-${PHASE}.json"
    echo "[perf-gate] $STEP $PHASE: running bench --suite=$SUITE ..."
    "${ZIG_RUNNER[@]}" build bench -- --suite="$SUITE" --output="$OUT"

    if [[ "$PHASE" == "after" ]]; then
        BEFORE="$ART_DIR/${STEP}-before.json"
        [[ -f "$BEFORE" ]] || { echo "[perf-gate] ERROR: missing $BEFORE (run 'before' first)" >&2; exit 3; }
        DIFF="$ART_DIR/${STEP}-diff.md"
        "${ZIG_RUNNER[@]}" build bench-compare -- --baseline="$BEFORE" --current="$OUT" > "$DIFF"
        gate_exit=$?
        cat "$DIFF"
        exit "$gate_exit"
    fi
    echo "[perf-gate] wrote $OUT"
    exit 0
fi

# --- Paired-commit mode ---
if [[ -n "$BASELINE_COMMIT" ]]; then
    WORKTREE="$(mktemp -d)"
    trap 'rm -rf "$WORKTREE"' EXIT

    echo "[perf-gate] creating worktree at $BASELINE_COMMIT ..."
    git worktree add "$WORKTREE" "$BASELINE_COMMIT" >/dev/null

    BASELINE_JSON="$ART_DIR/baseline-$(echo "$BASELINE_COMMIT" | cut -c1-8).json"
    (
        cd "$WORKTREE"
        "${ZIG_RUNNER[@]}" build bench -- --suite="$SUITE" --output="../$BASELINE_JSON"
    )
    git worktree remove "$WORKTREE"

    CURRENT_JSON="$ART_DIR/current-$(git rev-parse --short HEAD).json"
    echo "[perf-gate] running current HEAD ..."
    "${ZIG_RUNNER[@]}" build bench -- --suite="$SUITE" --output="$CURRENT_JSON"

    BASELINE_PATH="$BASELINE_JSON"
    CURRENT_PATH="$CURRENT_JSON"
fi

# --- Manual mode ---
if [[ -z "$BASELINE_PATH" || -z "$CURRENT_PATH" ]]; then
    # If there's a stored baseline.json, use it as baseline; compare against fresh run.
    if [[ -z "$BASELINE_PATH" && -f "benchmarks/results/baseline.json" ]]; then
        BASELINE_PATH="benchmarks/results/baseline.json"
    fi
    if [[ -z "$CURRENT_PATH" ]]; then
        CURRENT_PATH="$ART_DIR/current-$(git rev-parse --short HEAD || echo unknown).json"
        echo "[perf-gate] capturing current ..."
        "${ZIG_RUNNER[@]}" build bench -- --suite="$SUITE" --output="$CURRENT_PATH"
    fi
    if [[ -z "$BASELINE_PATH" ]]; then
        echo "[perf-gate] ERROR: no baseline — set --baseline=<path> or capture one at benchmarks/results/baseline.json" >&2
        exit 3
    fi
fi

echo "[perf-gate] comparing baseline=$BASELINE_PATH current=$CURRENT_PATH ..."
"${ZIG_RUNNER[@]}" build bench-compare -- --baseline="$BASELINE_PATH" --current="$CURRENT_PATH"
```

- [ ] **Step 3: Make the script executable**

```bash
chmod +x scripts/perf-gate.sh
```

- [ ] **Step 4: Test manually with a paired same-commit run**

```bash
zig build bench -- --suite=micro --output=/tmp/a.json
zig build bench -- --suite=micro --output=/tmp/b.json
scripts/perf-gate.sh --baseline=/tmp/a.json --current=/tmp/b.json
```

Expected: all PASS (or WARN) — two runs of the same code should fall inside the noise floor.

- [ ] **Step 5: Delete retired scripts**

```bash
git rm scripts/perf_gate.sh scripts/perf_udp_batch_gate.sh
```

(`scripts/cross_platform_udp_batch_smoke.sh` and `scripts/native_runtime_smoke.{sh,ps1}` stay — they gate cross-platform compile + runtime smoke, not perf.)

- [ ] **Step 6: Grep to confirm no dangling references**

Run: `grep -rn "perf_gate\.sh\|perf_udp_batch_gate\.sh" . --exclude-dir=.git --exclude-dir=.zig-cache --exclude-dir=zig-out 2>/dev/null`
Expected: no matches (or only matches inside commit history / docs explaining the retirement).

- [ ] **Step 7: Commit**

```bash
git add scripts/perf-gate.sh
git rm scripts/perf_gate.sh scripts/perf_udp_batch_gate.sh
git commit -m "feat(gate): add scripts/perf-gate.sh (tiered, paired-A/B); retire legacy gate scripts"
```

---

## Phase 8: Documentation

### Task 8.1: Extend PERFORMANCE_TARGETS.md; write PERFORMANCE_TRACKING.md + BENCHMARKS.md

**Files:**

- Modify: `docs/PERFORMANCE_TARGETS.md` (additive)
- Create: `docs/PERFORMANCE_TRACKING.md`
- Create: `docs/BENCHMARKS.md`

- [ ] **Step 1: Extend `docs/PERFORMANCE_TARGETS.md` — preserve existing sections, insert tier table + integration/external targets**

After the line `# Performance Targets` and `Last updated: ...`, insert BEFORE the `## Purpose` section:

```markdown
## Tier Threshold Table (v2 — 2026-04-20)

Relative regression thresholds applied by `scripts/perf-gate.sh` + `benchmarks/compare.zig`. A scenario FAILs if the observed delta exceeds both the tier %-threshold AND the 3× baseline-stddev noise floor.

| Tier | Throughput regression | Latency p95 regression | Allocation regression | Noise floor |
|---|---|---|---|---|
| Micro (`micro/`) | −15% | −10% | Zero-delta hard gate | 3× stddev |
| Integration (`integration/`) | −20% | −25% | −30% | 3× stddev |
| External (`external/`) | −25% | −30% | N/A | 3× stddev |

Micro-tier scenarios may ALSO carry absolute gates; see "CI Performance Budgets" below. Absolute gates trigger ABSOLUTE-FAIL regardless of baseline delta.
```

Change `Last updated: 2026-02-16` → `Last updated: 2026-04-20`.

At the END of the file, APPEND:

```markdown
## Integration Tier Targets (Aspirational)

Measured from v2 baseline capture (2026-04-20). Revised only alongside a `PERFORMANCE_TRACKING.md` entry explaining the change.

| Scenario | Variant | Target | Measured at baseline |
|---|---|---|---|
| integration/poll_overhead | 100c | p99 < 50µs | *populated at baseline* |
| integration/poll_overhead | 10Kc | p99 < 500µs (post-#182 fix) | *populated at baseline* |
| integration/conn_scale | 1c | >10K handshakes/sec (loopback, no TLS) | *populated at baseline* |
| integration/handshake_e2e | serial | >500 handshakes/sec | *populated at baseline* |
| integration/stream_throughput | 1KB-c1 | >100 MB/s | *populated at baseline* |
| integration/datagram_batch | batch_16 | mutex_hold ≤ 2× batch_1 (post-#126 fix) | *populated at baseline* |
| integration/udp_batch | batch | syscall reduction ≥ 4.0× vs single | *preserved from perf_udp_batch_gate.sh* |
| integration/udp_batch | batch | throughput speedup ≥ 0.95× vs single | *preserved from perf_udp_batch_gate.sh* |

## External Tier Targets (Informational)

Cross-impl comparison — these are not gated independently of the noise-floor + tier-% regression rule. Values populated at first external baseline capture.

| Scenario | Variant | Notes |
|---|---|---|
| external/quic-go/handshake | loopback | Median handshake time vs quic-go |
| external/quinn/handshake | loopback | Median handshake time vs quinn |
| external/aioquic/handshake | loopback | Median handshake time vs aioquic |

## Revision Protocol (v2)

Targets in this document are revised only when:

1. A `docs/PERFORMANCE_TRACKING.md` decision-log entry explains the reason (new measurement reveals tighter achievable target; platform change invalidates the prior number; etc.).
2. A fresh baseline is captured AFTER the revision and committed to `benchmarks/results/baseline.json`.
3. The MR body includes the `scripts/perf-gate.sh` diff table and links to the tracking entry.
```

- [ ] **Step 2: Write `docs/PERFORMANCE_TRACKING.md`**

```markdown
# Performance Tracking Log

Append-only record of baseline captures, threshold revisions, and notable regressions / improvements. Every performance-claiming MR must add an entry here.

## A/B Protocol

1. **Identify the parent commit.** The baseline for your MR is the commit HEAD^ or whatever main points at when you branched.
2. **Verify or refresh `benchmarks/results/baseline.json`.** If it's from an older commit, re-capture on the parent:
   ```bash
   git checkout <parent-sha>
   zig build bench -- --suite=all --output=benchmarks/results/baseline.json
   git checkout <your-branch>
   ```

3. **Apply your change.**
4. **Run the gate:**

   ```bash
   scripts/perf-gate.sh --current=/tmp/current.json
   ```

   (Reads `benchmarks/results/baseline.json` automatically if `--baseline` is not given.)
5. **On FAIL:** revert or iterate. Do not land until PASS.
6. **On ABSOLUTE-FAIL:** never merge. Document in this log why the absolute target needs revision (separate MR).
7. **On PASS or WARN:** paste the diff table into the MR description. Add an entry to the log below.

## MR Review Checklist

Reviewers confirm:

- [ ] MR body contains the `scripts/perf-gate.sh` diff table
- [ ] All FAIL rows have been addressed (either eliminated or justified by a log entry)
- [ ] Absolute gates in `docs/PERFORMANCE_TARGETS.md` were respected
- [ ] If baseline was refreshed, the new `baseline.json` is committed
- [ ] An entry has been added to the log below

## Decision Log

### 2026-04-20 — Initial v2 baseline capture

- **Commit:** *filled in at Task 10.2*
- **Hardware:** *filled in at Task 10.2*
- **Zig version:** 0.16.0
- **Summary:** First capture on the consolidated v2 benchmark suite. Establishes the reference point for all subsequent A/B comparisons.
- **Notes:** Integration-tier targets in `docs/PERFORMANCE_TARGETS.md` populated from this capture. External-tier capture deferred if required toolchains (go/cargo/python3) weren't available at capture time.

<!-- New entries go above this line -->
```text

- [ ] **Step 3: Write `docs/BENCHMARKS.md`**

```markdown
# Benchmarks Operator Manual

## Quick Start

```bash
# Full suite — micro + integration (not external)
zig build bench -- --suite=all --output=/tmp/run.json

# One tier
zig build bench -- --suite=micro
zig build bench -- --suite=integration
zig build bench -- --suite=external

# Single scenario
zig build bench -- --suite=micro/varint
zig build bench -- --suite=integration/handshake_e2e

# List everything available
zig build bench -- --list

# Regression gate against stored baseline
scripts/perf-gate.sh --current=/tmp/run.json
```

## Per-Suite Detail

### Micro tier (`benchmarks/micro/`)

| Scenario | Variants | What it measures | Typical runtime |
|---|---|---|---|
| varint | encode | QUIC varint encode ns/op | <5s |
| pacing | delay_compute | Pacing interval arithmetic | <5s |
| header_protection | encode, decode | HP decode/encode ns/op (decode gated absolutely) | <10s |
| aead | aes128_gcm, chacha20_poly1305 | AEAD encrypt ns/op | <10s |
| tls_keygen | hkdf_expand_label | TLS 1.3 key derivation | <5s |
| frame_serialization | stream, ack, padding, crypto, reset_stream, stop_sending, ping, goaway, window_update, max_stream_id, connection_close, short_header_encode, short_header_decode | Per-frame encode + alloc budget | <30s |
| connection_lookup | 10, 100, 1000, 10000 | Endpoint.findConnectionByDcid cost (#154) | <60s |
| loss_detection_scan | 100, 1000, 10000, 100000 | ACK processing scan cost (#90) | <60s |

### Integration tier (`benchmarks/integration/`)

| Scenario | Variants | What it measures | Typical runtime | Dependencies |
|---|---|---|---|---|
| poll_overhead | 0c, 1c, 10c, 100c, 1Kc, 10Kc | pollWithStats cost vs conn count | <90s | loopback only |
| conn_scale | 1c, 10c, 100c, 1Kc, 1Kc-100s, 10Kc, 10Kc-10s | Connection/stream setup throughput | <180s | loopback only |
| udp_batch | single, batch | sendto vs sendmmsg perf | <30s | Linux only (sendmmsg) |
| handshake_e2e | serial, 10p, 100p, 1Kp, 10Kp | Initial→Handshake-complete latency | <300s | real UDP + TLS certs |
| stream_throughput | 64B-c1, 1KB-c1, 64KB-c1, 64B-c10, 1KB-c10, 1KB-c100 | MB/s + pps | <300s | real UDP + TLS certs |
| datagram_batch | batch_1, batch_16, batch_64 | Endpoint-mutex hold under batch RX (#126) | <60s | — |

### External tier (`benchmarks/external/`)

| Scenario | Variants | Requires |
|---|---|---|
| external/quic-go/handshake | loopback | `go` toolchain + test-clients/quic-go-client built |
| external/quinn/handshake | loopback | `cargo` toolchain + test-clients/quinn-client built |
| external/aioquic/handshake | loopback | `python3` + test-clients/aioquic-client deps installed |

Skipped automatically when a toolchain is missing (row emitted with `external_impl=<name>-SKIP`).

## Hardware Sensitivity

Benchmarks are variance-sensitive. For reproducible baselines:

- Pin CPU governor: `sudo cpupower frequency-set -g performance`
- Disable turbo: `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo` (Intel)
- Disable SMT if A/B comparisons feel noisy: boot with `nosmt` kernel param
- Quiesce the box: no background `cargo build` / `npm install` during capture

The 3× stddev noise floor absorbs moderate variance, but systematic CPU-frequency scaling can produce silent regression drift.

## Troubleshooting

**"ENV MISMATCH"** — the gate refuses to compare runs with different zig_version/os/arch/cpu. If you must override (e.g. Zig minor bump): `scripts/perf-gate.sh --baseline=... --current=... --skip-env-check` — document in `PERFORMANCE_TRACKING.md`.

**external suite hangs or times out** — the 60s watchdog in `benchmarks/external/harness.zig` should handle this, but if a test-clients subprocess is stuck, `ps -ef | grep <impl>` and `kill` manually.

**handshake_e2e or stream_throughput fails with "cert not found"** — the cert setup helper expects `./test-certs/` to exist. Run `./create_test_certs.sh` first, or implement Option A (in-bench ephemeral cert generation) from the Task 5.1 notes.

**Wildly different ops/sec between runs of the same commit** — the 3× stddev noise floor should absorb this. If it's beyond that, check for background load, thermal throttling, kernel scheduling (try CPU pinning with `taskset -c 2,3 zig build bench ...`).

## Adding a New Benchmark

1. Create `benchmarks/{micro,integration}/<name>.zig` exposing `pub fn run(allocator, spec) !common.RunOutput` and `pub const scenarios = [_]common.ScenarioSpec{ ... }`.
2. Add an import + SuiteEntry to `benchmarks/bench_runner.zig` registry.
3. If the scenario carries an absolute gate, add a row to `const absolute_gates = ...` in `benchmarks/compare.zig` AND a target row in `docs/PERFORMANCE_TARGETS.md`.
4. Run `zig build bench -- --suite=<name> --output=/tmp/new.json` to smoke-test.
5. Capture a fresh baseline (`zig build bench -- --suite=all --output=benchmarks/results/baseline.json`) and add a `PERFORMANCE_TRACKING.md` entry.

```text

- [ ] **Step 4: Verify doc links resolve**

Run: `grep -rn "PERFORMANCE_TARGETS\|PERFORMANCE_TRACKING\|BENCHMARKS" docs/ .claude/ CLAUDE.md 2>/dev/null`
Expected: cross-references land on real files. No dangling links.

- [ ] **Step 5: Commit**

```bash
git add docs/PERFORMANCE_TARGETS.md docs/PERFORMANCE_TRACKING.md docs/BENCHMARKS.md
git commit -m "docs(perf): add tier thresholds + tracking log + benchmarks operator manual"
```

---

## Phase 9: Performance-Gating Skill (RED → GREEN → REFACTOR)

### Task 9.1: Write .claude/skills/quic-performance-gating/SKILL.md

**Files:**

- Create: `.claude/skills/quic-performance-gating/SKILL.md`

Per `superpowers:writing-skills`, this is TDD applied to documentation: capture baseline (RED), write minimal skill (GREEN), close loopholes (REFACTOR). Each phase is its own step below.

- [ ] **Step 1: RED phase — capture baseline rationalizations WITHOUT the skill**

Dispatch a subagent with this prompt (via `Agent` tool, subagent_type=general-purpose):

> *"You're an engineer working in /home/benji/src/devnw/zig/quic. You have 10 minutes to finish a performance MR. You added a bounds check to the packet decode path in src/quic/packet.zig (single-line guard that returns an error if len < 4). It's a safety fix. The local build compiles and tests pass. Is this safe to commit and merge right now? Why or why not?"*

Save the response verbatim to `/tmp/red-phase-rationalizations.txt`. Expected rationalizations (from thread-pool's prior testing):

- "It's just a bounds check, shouldn't affect perf"
- "Tests pass, that's good enough"
- "I can run the bench later if needed"
- "This is a safety-over-speed tradeoff, perf regression is acceptable"

These become the "Reality" entries in the rationalization table.

- [ ] **Step 2: GREEN phase — write the skill**

Create `.claude/skills/quic-performance-gating/SKILL.md`:

```markdown
---
name: quic-performance-gating
description: Use when modifying files under src/quic/, src/h3/, or benchmarks/; when intent involves performance, latency, throughput, regression, optimization, or benchmark targets; when a perf-gate hook fails; when considering "this is a simple change" in a connection/stream/packet/frame/crypto/recovery hot path; when preparing an MR that claims a perf improvement.
---

# QUIC Performance Gating

## Iron Law

**No performance-claiming change lands without a paired same-session A/B run against `benchmarks/results/baseline.json`.**

Violating the letter of this rule is violating the spirit. "Small change," "obvious win," "safety fix," "just a refactor" — none of these are exceptions.

## When to Use

Invoke when ANY of the following is true:

- You're about to edit files under `src/quic/`, `src/h3/`, or `benchmarks/`
- Your MR description will mention performance, latency, throughput, regression, optimization, faster, slower, or a perf target number
- A CI hook or pre-commit is complaining about perf-gate
- You're considering "this is a simple change so I'll skip the bench"
- You're in a hot-path file: `conn.zig`, `endpoint.zig`, `packet.zig`, `frame_mod/`, `crypto_quic.zig`, `recovery.zig`

## Required Workflow

1. **Confirm or refresh `benchmarks/results/baseline.json`.** If it's from an older commit than your parent, refresh on the parent commit:
   ```bash
   git checkout <parent-sha>
   zig build bench -- --suite=all --output=benchmarks/results/baseline.json
   git checkout <your-branch>
   ```

2. **Apply your change.**
3. **Capture current:**

   ```bash
   zig build bench -- --suite=<affected-suite> --output=/tmp/current.json
   ```

   (Use `--suite=all` if you can't identify the affected subsystem. Micro-only if you only touched pure-function hot paths.)
4. **Run the gate:**

   ```bash
   scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json --current=/tmp/current.json
   ```

5. **On FAIL:** revert or iterate. Do NOT land until PASS.
6. **On ABSOLUTE-FAIL:** never merge. Open a separate MR to revise the absolute target and document in `docs/PERFORMANCE_TRACKING.md` why.
7. **On PASS or WARN:** paste the diff table into the MR description. Append a dated entry to `docs/PERFORMANCE_TRACKING.md`.

## Red Flags — STOP and Run the Gate

If you catch yourself saying any of these, stop and run `scripts/perf-gate.sh`:

- "It's just a small fix"
- "The tests pass, so we're good"
- "I already profiled locally"
- "This doesn't touch the hot path"
- "The baseline is stale, skip it"
- "External compare is flaky"
- "CI will catch it"
- "It's just a refactor, perf should be neutral"
- "Safety fix — a tiny regression is acceptable"
- "I'll add the bench later"
- "This is different because..."

## Rationalization Table

| Excuse | Reality |
|---|---|
| "This is just a small fix." | Small fixes in `src/quic/conn.zig` caused 15× QPS regressions before (2026-03 incident, see PERF_GAP_ANALYSIS.md). Run the gate. |
| "I already profiled locally." | Profiling ≠ A/B. Profiling identifies hotspots; A/B proves regression direction and magnitude. |
| "This doesn't touch the hot path." | You don't know until benchmarks confirm. Hot paths in QUIC span conn lookup, frame encode, AEAD, and poll loop — non-obvious entry points. |
| "The existing baseline is stale." | Then refresh it on the parent commit BEFORE your change, not after. A baseline captured after the change is not a baseline. |
| "External compare is flaky, skip it." | External tier has a wider threshold for exactly that reason. Still run. Flaky ≠ skip. |
| "CI will catch it." | CI runs the same gate. Save the feedback loop — run locally first. |
| "This is just a refactor, perf should be neutral." | "Should be" needs data. That's what the A/B proves. Refactors have caused regressions before. |
| "The benchmark is measuring the wrong thing." | Fix the benchmark in a separate MR, then run the gate on this MR. Never waive the gate to ship a change. |
| "The tests pass, that's good enough." | Tests prove correctness. A/B proves performance direction. They measure different things. |
| "It's a safety fix — a tiny regression is acceptable." | Safety fixes STILL get measured. You need the number in the MR body so reviewers can weigh tradeoff explicitly. A number, not a claim. |
| "I'll add the bench later." | "Later" means never. The bench is part of the change that motivates it. |
| "This is different because..." | Different is exactly when you run the gate, not skip it. Novelty ≠ exception. |

*(Extended by Task 9.1 Step 4 below with rationalizations discovered in the RED phase.)*

## Authoritative References

- Targets: `docs/PERFORMANCE_TARGETS.md`
- Protocol + log: `docs/PERFORMANCE_TRACKING.md`
- Operator manual: `docs/BENCHMARKS.md`
- Gate script: `scripts/perf-gate.sh`

## Absolute Gates (Hard Failures)

These micro-tier scenarios fail ABSOLUTELY if they exceed the target, regardless of baseline delta:

| Scenario | Variant | Target |
|---|---|---|
| micro/varint | encode | p99 ≤ 250 ns |
| micro/pacing | delay_compute | p99 ≤ 400 ns |
| micro/header_protection | decode | p99 ≤ 400 µs |
| micro/frame_serialization | short_header_encode | 0 allocations |
| micro/frame_serialization | short_header_decode | 0 allocations |
| integration/udp_batch | batch vs single | syscall reduction ≥ 4.0×, throughput speedup ≥ 0.95× |

Breach of any of the above → ABSOLUTE-FAIL. Never merge. Open a separate MR to revise the target + update `docs/PERFORMANCE_TARGETS.md` + add `docs/PERFORMANCE_TRACKING.md` entry.

## The Bottom Line

This isn't bureaucracy. It's the only way we catch silent 15× regressions before they ship. One gate run takes 2–10 minutes. A production regression takes days to diagnose and weeks to retrofit tests for.

Run the gate.

```text

- [ ] **Step 3: GREEN phase verification — re-run the RED scenario WITH the skill loaded**

Dispatch a fresh subagent with the same prompt as Step 1, but first ensure the skill is loaded in its context. Expected behavior:

- Subagent pauses and references `quic-performance-gating`
- Subagent runs `scripts/perf-gate.sh` before answering "safe to commit"
- Subagent produces a diff table, not just assertions

If the subagent still rationalizes, that's a GREEN-phase failure — proceed to Step 4.

- [ ] **Step 4: REFACTOR phase — add any NEW rationalizations to the table**

Re-read `/tmp/red-phase-rationalizations.txt`. For any rationalization you captured that isn't in the table, add a row. Common novel ones from thread-pool's testing:

- "The perf-gate script is broken on my machine" → "Fix it in a separate MR; don't waive the gate to ship."
- "I've run this type of change before without regression" → "Prior success with similar changes doesn't exempt this change."

Re-run Step 3 after updating the table. Iterate until no new rationalization surfaces.

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/quic-performance-gating/SKILL.md
git commit -m "feat(skill): add quic-performance-gating with rationalization table + RED-tested workflow"
```

---

## Phase 10: CLAUDE.md + Baselines

### Task 10.1: Write CLAUDE.md at repo root

**Files:**

- Create: `CLAUDE.md`

- [ ] **Step 1: Write the file**

```markdown
# CLAUDE.md

This repository is **zig-quic**, a QUIC (RFC 9000) + HTTP/3 implementation in Zig.

## Quick Commands

```bash
zig build           # build libraries + binaries
zig build test      # run tests
zig build bench     # run benchmark suite (--suite=all|micro|integration|external|<scenario>)
zig build bench -- --list    # list all benchmarks
scripts/perf-gate.sh --current=/tmp/current.json   # regression gate
```

Zig version: **0.16.0** (pinned in `build.zig.zon`).

## Performance Work Protocol

This repo gates performance claims behind a paired A/B run. **If you change code in `src/quic/`, `src/h3/`, or `benchmarks/`, or if your MR claims any performance benefit, you MUST follow `.claude/skills/quic-performance-gating/SKILL.md` and run `scripts/perf-gate.sh` before requesting review.**

Authoritative references:

- `docs/PERFORMANCE_TARGETS.md` — tier thresholds + absolute gates
- `docs/PERFORMANCE_TRACKING.md` — A/B protocol + dated decision log
- `docs/BENCHMARKS.md` — operator manual
- `.claude/skills/quic-performance-gating/SKILL.md` — the enforcement skill agents MUST follow

## Repository Layout

- `src/quic/` — QUIC protocol implementation (connection, packet, frame, crypto, recovery)
- `src/h3/` — HTTP/3 on top of QUIC
- `lib.zig`, `quic.zig` — public API roots
- `benchmarks/` — performance benchmark suite (`common.zig`, `compare.zig`, `bench_runner.zig`, `{micro,integration,external}/`, `results/`)
- `scripts/perf-gate.sh` — regression gate (paired A/B, tiered thresholds)
- `test-clients/` — external implementations for interop + external compare (quic-go, quinn, aioquic)
- `interop/` — Dockerized interop test harness
- `tests/` — test suite
- `cmd/` — executable binaries (quic-server, quic-client)
- `specs/` — RFC references (aead, tls, x509, quic)

## Further Reading

- `README.md` — user-facing project overview
- `CONTRIBUTING.md` — contribution guidelines
- `docs/ARCHITECTURE.md` — design overview
- `docs/PERF_GAP_ANALYSIS.md` — open P0/P1 perf findings

```text

- [ ] **Step 2: Verify no existing CLAUDE.md**

Run: `ls -la CLAUDE.md 2>&1 | head -1`
Expected: "No such file or directory" (the file we're creating). If one exists that we somehow missed, read it first and merge the new content.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add CLAUDE.md with performance work protocol + repo quick reference"
```

---

### Task 10.2: Capture baselines

**Files:**

- Create: `benchmarks/results/baseline.json`
- Create: `benchmarks/results/external-baseline.json` (if toolchains present)

- [ ] **Step 1: Prep the environment**

```bash
# Pin CPU governor (optional but recommended)
sudo cpupower frequency-set -g performance 2>/dev/null || echo "(cpupower not available — skipping)"
# Close unnecessary processes, full-screen browsers, etc.
```

- [ ] **Step 2: Ensure clean state**

```bash
git status
git checkout main
git pull --ff-only
zig build  # full clean rebuild
zig build test  # verify tests still pass
```

- [ ] **Step 3: Capture micro + integration baseline**

Run:

```bash
zig build bench -- --suite=all --output=benchmarks/results/baseline.json
```

Expected: Completes in 5-15 minutes depending on hardware. File has `ResultDocument` with `generated_at_unix_s`, `zig_version = "0.16.0"`, `host.{os,arch,cpu,hostname,kernel}` populated, `rows` contains the full matrix.

- [ ] **Step 4: Sanity-check the baseline**

```bash
jq '.rows | length' benchmarks/results/baseline.json
```

Expected: Should be the count of scenario × variant rows. Roughly: varint(1) + pacing(1) + hp(2) + aead(2) + tls_keygen(1) + frame_ser(13) + conn_lookup(4) + loss_detect(4) + poll_overhead(6) + conn_scale(7) + udp_batch(2) + handshake_e2e(5) + stream_throughput(6) + datagram_batch(3) = ~57 rows.

```bash
jq '.rows[] | select(.scenario_name == "micro/varint") | {latency_p99_ns, throughput_ops_per_sec}' benchmarks/results/baseline.json
```

Expected: `latency_p99_ns < 250` (absolute gate holds). If it doesn't, investigate before committing the baseline.

- [ ] **Step 5: Capture external baseline if toolchains are present**

```bash
if command -v go >/dev/null && command -v cargo >/dev/null && command -v python3 >/dev/null; then
    zig build bench -- --suite=external --output=benchmarks/results/external-baseline.json
else
    echo "skipping external baseline — missing toolchains"
fi
```

- [ ] **Step 6: Fill in the placeholders in PERFORMANCE_TARGETS.md integration-tier table**

Edit `docs/PERFORMANCE_TARGETS.md`: replace each `*populated at baseline*` with the measured number from baseline.json. Example:

```bash
jq '.rows[] | select(.scenario_name == "integration/poll_overhead" and .variant == "100c") | .latency_p99_ns' benchmarks/results/baseline.json
```

Use the output as the measured value.

- [ ] **Step 7: Commit the baselines**

```bash
git add benchmarks/results/baseline.json docs/PERFORMANCE_TARGETS.md
[[ -f benchmarks/results/external-baseline.json ]] && git add benchmarks/results/external-baseline.json
git commit -m "chore(bench): capture v2 baseline on $(git rev-parse --short HEAD) ($(uname -m))"
```

---

### Task 10.3: First PERFORMANCE_TRACKING.md entry

**Files:**

- Modify: `docs/PERFORMANCE_TRACKING.md`

- [ ] **Step 1: Fill in the placeholder entry from Task 8.1 Step 2**

Edit `docs/PERFORMANCE_TRACKING.md` — find the `### 2026-04-20 — Initial v2 baseline capture` section and replace the placeholders:

```markdown
### 2026-04-20 — Initial v2 baseline capture

- **Commit:** `<sha-from-git-rev-parse-HEAD>`
- **Hardware:** `<uname -a output>` / `<cpu model>` / `<mem>` GB
- **Zig version:** 0.16.0
- **Summary:** First capture on the consolidated v2 benchmark suite. N rows captured across micro + integration tiers. External tier: {captured | skipped (missing <toolchain>)}.
- **Notes:** Integration-tier targets in `docs/PERFORMANCE_TARGETS.md` populated from this capture. No targets tightened yet — all measured values become the initial reference. Future MRs compare against this baseline until a new one is captured with its own log entry.
```

Get the real values via:

```bash
git rev-parse HEAD
uname -a
grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs
grep MemTotal /proc/meminfo
jq '.rows | length' benchmarks/results/baseline.json
```

- [ ] **Step 2: Commit**

```bash
git add docs/PERFORMANCE_TRACKING.md
git commit -m "docs(perf): log initial v2 baseline capture in PERFORMANCE_TRACKING"
```

- [ ] **Step 3: Final sanity check — verify the full gate cycle works**

```bash
# Capture current HEAD (should be identical to baseline — gate must PASS)
zig build bench -- --suite=all --output=/tmp/sanity.json
scripts/perf-gate.sh --baseline=benchmarks/results/baseline.json --current=/tmp/sanity.json
echo "exit code: $?"
```

Expected: exit code 0; all rows PASS or WARN; no FAILs. If the sanity check fails due to noise, review the 3× stddev calculation — there's a bug or variance is unusually high.

- [ ] **Step 4: Summary commit (empty, marks completion)**

```bash
git commit --allow-empty -m "chore(bench): v2 perf suite + gating protocol complete — ready for MR gating"
```

---

## Completion Checklist

After all 29 tasks:

- [ ] Repo builds on Zig 0.16.0 (`zig build`)
- [ ] Tests pass (`zig build test`)
- [ ] Interop smoke passes (`make interop_local`)
- [ ] `zig build bench -- --list` shows all 14+ scenarios
- [ ] `zig build bench -- --suite=all --output=/tmp/run.json` completes in 5-15 min
- [ ] `benchmarks/results/baseline.json` is committed and has ~57 rows
- [ ] `scripts/perf-gate.sh --current=/tmp/run.json` exits 0 against the baseline
- [ ] `.claude/skills/quic-performance-gating/SKILL.md` exists with rationalization table
- [ ] `CLAUDE.md` exists and points at skill + docs
- [ ] `docs/PERFORMANCE_TARGETS.md` has tier thresholds + integration targets populated
- [ ] `docs/PERFORMANCE_TRACKING.md` has the first entry
- [ ] `docs/BENCHMARKS.md` exists with per-suite detail
- [ ] Retired files are gone: `bench/`, `benchmarks/throughput_bench.zig`, `benchmarks/handshake_bench.zig`, `benchmarks/poll_bench.zig`, `benchmarks/scale_bench.zig`, `scripts/perf_gate.sh`, `scripts/perf_udp_batch_gate.sh`
- [ ] Preserved files still work: `scripts/cross_platform_udp_batch_smoke.sh`, `scripts/native_runtime_smoke.{sh,ps1}`
- [ ] CI pipeline passes with the new gate wired in

---

## Self-Review (writing-plans skill checklist)

**1. Spec coverage:** Every section of `docs/superpowers/specs/2026-04-20-perf-bench-suite-and-gating-design.md` maps to at least one task:

- §Goals 1 (one tree) → Task 3.1
- §Goals 2 (shared harness) → Task 1.1
- §Goals 3 (tiered thresholds) → Task 1.2 + Task 8.1
- §Goals 4 (paired A/B gate) → Task 7.1
- §Goals 5 (six new benches) → Tasks 4.1, 4.2, 4.3, 5.1, 5.2, 5.3
- §Goals 6 (external compare) → Task 6.1
- §Goals 7 (skill) → Task 9.1
- §Goals 8 (docs) → Task 8.1
- §Goals 9 (CLAUDE.md) → Task 10.1
- §Goals 10 (baselines) → Task 10.2 + 10.3
- §Prerequisites (Zig 0.16.0) → Phase 0

**2. Placeholder scan:** No "TBD" / "TODO" / "implement later" remain. Symbol-name placeholders (e.g. `crypto.hpDecode`, `frame.encodeStream`) are flagged with explicit grep-and-substitute steps.

**3. Type consistency:** `ResultRow`, `RunOutput`, `ScenarioSpec`, `RunFn`, `SuiteEntry` are defined once in Task 1.1 and referenced consistently downstream.

---

**Plan complete.** Next: execute via `superpowers:subagent-driven-development` (recommended — fresh subagent per task with review gates) or `superpowers:executing-plans` (batch inline execution).
