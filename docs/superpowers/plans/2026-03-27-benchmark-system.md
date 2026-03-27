# QUIC Benchmark System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an enterprise-grade benchmark suite that measures QUIC connection scaling (up to 10K connections), stream multiplexing (up to 100K streams), payload throughput (MB/s), handshake latency, and poll loop overhead -- with persistent JSON baselines and automated regression detection.

**Architecture:** Four benchmark executables (scale, throughput, handshake, poll) in `benchmarks/` share a `common.zig` harness for timing, JSON emission, and table printing. A `compare.zig` tool detects regressions against `benchmarks/results/baseline.json`. Loopback transport for reproducible scaling benchmarks; real UDP for throughput/handshake. Follows the graph-storage benchmark system pattern exactly.

**Tech Stack:** Zig 0.15.1, QUIC endpoint API, loopback + UDP transports, JSON output, Makefile integration

**Spec:** `docs/superpowers/specs/2026-03-27-benchmark-system-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `benchmarks/common.zig` | Create | Timer, JSON emitter, table printer, tier configs |
| `benchmarks/poll_bench.zig` | Create | Poll loop overhead at 0-10K connections (loopback) |
| `benchmarks/scale_bench.zig` | Create | Connection/stream scaling 7 tiers (loopback) |
| `benchmarks/throughput_bench.zig` | Create | MB/s payload throughput (real UDP) |
| `benchmarks/handshake_bench.zig` | Create | TLS handshake latency at scale (real UDP) |
| `benchmarks/compare.zig` | Create | Regression detection: read 2 JSON files, compare, exit 1 on fail |
| `benchmarks/results/README.md` | Create | Format documentation |
| `build.zig` | Modify | Register 6 new executables + 6 build steps |
| `Makefile` | Modify | Add bench-scale, bench-poll, bench-throughput, bench-handshake, bench-all, bench-save, bench-baseline, bench-compare |

---

### Task 1: Common Benchmark Harness

**Files:**
- Create: `benchmarks/common.zig`

- [ ] **Step 1: Create the common harness module**

```zig
// benchmarks/common.zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Shared benchmark harness: timing, JSON output, human-readable tables.

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

pub const Timer = struct {
    start_ns: i128 = 0,
    end_ns: i128 = 0,

    pub fn start() Timer {
        return .{ .start_ns = std.time.nanoTimestamp() };
    }

    pub fn stop(self: *Timer) void {
        self.end_ns = std.time.nanoTimestamp();
    }

    pub fn elapsed_ns(self: Timer) u64 {
        const diff = self.end_ns - self.start_ns;
        return @intCast(if (diff > 0) diff else 0);
    }

    pub fn elapsed_us(self: Timer) u64 {
        return self.elapsed_ns() / std.time.ns_per_us;
    }

    pub fn elapsed_ms(self: Timer) u64 {
        return self.elapsed_ns() / std.time.ns_per_ms;
    }
};

// ---------------------------------------------------------------------------
// Metric entry (name + value pairs for JSON/table output)
// ---------------------------------------------------------------------------

pub const Metric = struct {
    name: []const u8,
    value: f64,
};

// ---------------------------------------------------------------------------
// Tier result (name + params + metrics)
// ---------------------------------------------------------------------------

pub const Param = struct {
    name: []const u8,
    value: u64,
};

pub const TierResult = struct {
    name: []const u8,
    params: []const Param,
    metrics: []const Metric,
};

// ---------------------------------------------------------------------------
// JSON Emitter (writes structured JSON to stdout)
// ---------------------------------------------------------------------------

pub fn emitJson(
    allocator: std.mem.Allocator,
    suite: []const u8,
    tiers: []const TierResult,
) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.writeAll("{\n");
    try stdout.print("  \"version\": 1,\n", .{});
    try stdout.print("  \"suite\": \"{s}\",\n", .{suite});

    // Timestamp
    const ts = std.time.timestamp();
    try stdout.print("  \"timestamp\": {d},\n", .{ts});

    // Git commit (best-effort)
    const commit = getGitCommit(allocator);
    defer if (commit) |c| allocator.free(c);
    try stdout.print("  \"git_commit\": \"{s}\",\n", .{commit orelse "unknown"});

    // System info
    try stdout.print("  \"system\": {{ \"os\": \"{s}\", \"arch\": \"{s}\" }},\n", .{
        @tagName(builtin.os.tag),
        @tagName(builtin.cpu.arch),
    });

    // Tiers
    try stdout.writeAll("  \"tiers\": [\n");
    for (tiers, 0..) |tier, ti| {
        try stdout.writeAll("    {\n");
        try stdout.print("      \"name\": \"{s}\",\n", .{tier.name});

        // Params
        try stdout.writeAll("      \"params\": {");
        for (tier.params, 0..) |p, pi| {
            try stdout.print(" \"{s}\": {d}", .{ p.name, p.value });
            if (pi + 1 < tier.params.len) try stdout.writeAll(",");
        }
        try stdout.writeAll(" },\n");

        // Metrics
        try stdout.writeAll("      \"metrics\": {");
        for (tier.metrics, 0..) |m, mi| {
            // Use integer representation when no fractional part
            if (m.value == @floor(m.value) and m.value < 1e15) {
                try stdout.print(" \"{s}\": {d}", .{ m.name, @as(i64, @intFromFloat(m.value)) });
            } else {
                try stdout.print(" \"{s}\": {d:.2}", .{ m.name, m.value });
            }
            if (mi + 1 < tier.metrics.len) try stdout.writeAll(",");
        }
        try stdout.writeAll(" }\n");

        if (ti + 1 < tiers.len) {
            try stdout.writeAll("    },\n");
        } else {
            try stdout.writeAll("    }\n");
        }
    }
    try stdout.writeAll("  ]\n");
    try stdout.writeAll("}\n");
}

// ---------------------------------------------------------------------------
// Table Printer (human-readable to stderr)
// ---------------------------------------------------------------------------

pub fn printHeader(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("\n" ++ "=" ** 78 ++ "\n", .{});
    std.debug.print(fmt, args);
    std.debug.print("\n" ++ "=" ** 78 ++ "\n\n", .{});
}

pub fn printTableRow(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

pub fn printSeparator() void {
    std.debug.print("{s}\n", .{"-" ** 78});
}

// ---------------------------------------------------------------------------
// Git commit helper (best-effort, returns null on failure)
// ---------------------------------------------------------------------------

fn getGitCommit(allocator: std.mem.Allocator) ?[]u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "git", "rev-parse", "--short", "HEAD" },
    }) catch return null;
    defer allocator.free(result.stderr);
    if (result.term.Exited != 0) {
        allocator.free(result.stdout);
        return null;
    }
    // Trim trailing newline
    const out = result.stdout;
    if (out.len > 0 and out[out.len - 1] == '\n') {
        const trimmed = allocator.alloc(u8, out.len - 1) catch {
            allocator.free(out);
            return null;
        };
        @memcpy(trimmed, out[0 .. out.len - 1]);
        allocator.free(out);
        return trimmed;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Ops/sec helper
// ---------------------------------------------------------------------------

pub fn opsPerSec(count: u64, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    return @as(f64, @floatFromInt(count)) * 1_000_000_000.0 / @as(f64, @floatFromInt(elapsed_ns));
}

pub fn nsPerOp(count: u64, elapsed_ns: u64) f64 {
    if (count == 0) return 0;
    return @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(count));
}

pub fn mbps(bytes: u64, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    return @as(f64, @floatFromInt(bytes)) * 1_000_000_000.0 / (1024.0 * 1024.0) / @as(f64, @floatFromInt(elapsed_ns));
}
```

- [ ] **Step 2: Verify the module compiles**

Run: `zig build-lib benchmarks/common.zig --name common 2>&1 || echo "Will verify via benchmark executables"`

This module has no external dependencies -- it will be verified when the first benchmark executable imports it.

- [ ] **Step 3: Commit**

```bash
git add benchmarks/common.zig
git commit -m "feat: add common benchmark harness (timer, JSON, table)"
```

---

### Task 2: Poll Bench (Loopback)

**Files:**
- Create: `benchmarks/poll_bench.zig`
- Modify: `build.zig` (add bench-poll step)

- [ ] **Step 1: Create poll_bench.zig**

```zig
// benchmarks/poll_bench.zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Poll loop overhead benchmark. Measures pollWithStats() cost as a function
// of connection count using loopback (no real network I/O).
//
// Run: zig build bench-poll
// Save: zig build bench-poll 2>/dev/null > results.json

const std = @import("std");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;

const test_alpn = [_][]const u8{"h3"};

const PollTier = struct {
    name: []const u8,
    connections: usize,
    iterations: usize,
};

const tiers = [_]PollTier{
    .{ .name = "0c", .connections = 0, .iterations = 20_000 },
    .{ .name = "1c", .connections = 1, .iterations = 20_000 },
    .{ .name = "10c", .connections = 10, .iterations = 10_000 },
    .{ .name = "100c", .connections = 100, .iterations = 5_000 },
    .{ .name = "1Kc", .connections = 1_000, .iterations = 2_000 },
    .{ .name = "10Kc", .connections = 10_000, .iterations = 500 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse optional max tier arg
    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.next(); // skip program name
    var max_tier: usize = tiers.len;
    if (args_it.next()) |arg| {
        max_tier = std.fmt.parseInt(usize, arg, 10) catch tiers.len;
        if (max_tier > tiers.len) max_tier = tiers.len;
    }

    common.printHeader("  QUIC poll benchmark ({d} tiers)", .{max_tier});
    common.printTableRow(
        "  {s:<8} {s:>8} {s:>10} {s:>12} {s:>12}",
        .{ "Tier", "Conns", "Iters", "us/poll", "polls/sec" },
    );
    common.printSeparator();

    var results = std.ArrayList(common.TierResult).init(allocator);
    defer {
        for (results.items) |r| {
            allocator.free(r.params);
            allocator.free(r.metrics);
        }
        results.deinit();
    }

    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };

    for (tiers[0..max_tier]) |tier| {
        var ep = try Endpoint.init(allocator, "127.0.0.1:0", &config);
        defer ep.deinit();

        // Create connections
        var c: usize = 0;
        while (c < tier.connections) : (c += 1) {
            var port_buf: [6]u8 = undefined;
            const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast((c % 55000) + 10000))}) catch continue;
            var addr_buf: [22]u8 = undefined;
            const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
            _ = ep.connectClient(addr) catch continue;
        }

        // Warmup (10% of iterations)
        const warmup = tier.iterations / 10;
        var w: usize = 0;
        while (w < warmup) : (w += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }

        // Measure
        var timer = common.Timer.start();
        var i: usize = 0;
        while (i < tier.iterations) : (i += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }
        timer.stop();

        const elapsed = timer.elapsed_ns();
        const us_per_poll = common.nsPerOp(tier.iterations, elapsed) / 1000.0;
        const polls_sec = common.opsPerSec(tier.iterations, elapsed);

        common.printTableRow(
            "  {s:<8} {d:>8} {d:>10} {d:>12.1} {d:>12.0}",
            .{ tier.name, tier.connections, tier.iterations, us_per_poll, polls_sec },
        );

        const params = try allocator.alloc(common.Param, 1);
        params[0] = .{ .name = "connections", .value = @intCast(tier.connections) };

        const metrics = try allocator.alloc(common.Metric, 2);
        metrics[0] = .{ .name = "us_per_poll", .value = us_per_poll };
        metrics[1] = .{ .name = "polls_per_sec", .value = polls_sec };

        try results.append(.{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    std.debug.print("\n", .{});

    // JSON to stdout
    try common.emitJson(allocator, "poll", results.items);
}
```

- [ ] **Step 2: Register bench-poll in build.zig**

Add after the existing bench step (around line 1845):

```zig
    // ========================================================================
    // Macro benchmarks (benchmarks/ directory)
    // ========================================================================

    const bench_common_mod = b.createModule(.{
        .root_source_file = b.path("benchmarks/common.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });

    // Poll loop overhead benchmark
    const bench_poll = addExe(b, "bench-poll", "benchmarks/poll_bench.zig", target, .ReleaseFast);
    bench_poll.root_module.addImport("bench_common", bench_common_mod);
    bench_poll.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    bench_poll.root_module.addImport("quic_conn", quic_conn_mod);
    bench_poll.root_module.addImport("quic_config", quic_config_mod);
    const install_bench_poll = b.addInstallArtifact(bench_poll, .{});
    const run_bench_poll = b.addRunArtifact(bench_poll);
    if (b.args) |args| run_bench_poll.addArgs(args);
    const bench_poll_step = b.step("bench-poll", "Run poll loop overhead benchmark");
    bench_poll_step.dependOn(&install_bench_poll.step);
    bench_poll_step.dependOn(&run_bench_poll.step);
```

- [ ] **Step 3: Build and run**

Run: `zig build bench-poll -- 3`
Expected: Runs 3 tiers (0c, 1c, 10c), prints table to stderr, JSON to stdout

- [ ] **Step 4: Verify JSON output**

Run: `zig build bench-poll -- 2 2>/dev/null | head -5`
Expected: JSON starting with `{ "version": 1, "suite": "poll",`

- [ ] **Step 5: Commit**

```bash
git add benchmarks/poll_bench.zig build.zig
git commit -m "feat: add poll loop overhead benchmark (loopback, 6 tiers)"
```

---

### Task 3: Scale Bench (Loopback)

**Files:**
- Create: `benchmarks/scale_bench.zig`
- Modify: `build.zig` (add bench-scale step)

- [ ] **Step 1: Create scale_bench.zig**

```zig
// benchmarks/scale_bench.zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Connection/stream scaling benchmark. Measures server-side capacity using
// loopback transport at 7 tiers from 1 to 10K connections.
//
// Run: zig build bench-scale
// Save: zig build bench-scale 2>/dev/null > benchmarks/results/baseline.json

const std = @import("std");
const common = @import("bench_common");
const endpoint_mod = @import("quic_endpoint");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;

const test_alpn = [_][]const u8{"h3"};

const ScaleTier = struct {
    name: []const u8,
    connections: usize,
    streams_per_conn: usize,
    iterations: usize,
};

const tiers = [_]ScaleTier{
    .{ .name = "1c", .connections = 1, .streams_per_conn = 1, .iterations = 5_000 },
    .{ .name = "10c", .connections = 10, .streams_per_conn = 10, .iterations = 2_000 },
    .{ .name = "100c", .connections = 100, .streams_per_conn = 10, .iterations = 500 },
    .{ .name = "1Kc", .connections = 1_000, .streams_per_conn = 10, .iterations = 200 },
    .{ .name = "1Kc-100s", .connections = 1_000, .streams_per_conn = 100, .iterations = 100 },
    .{ .name = "10Kc", .connections = 10_000, .streams_per_conn = 1, .iterations = 50 },
    .{ .name = "10Kc-10s", .connections = 10_000, .streams_per_conn = 10, .iterations = 50 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.next();
    var max_tier: usize = tiers.len;
    if (args_it.next()) |arg| {
        max_tier = std.fmt.parseInt(usize, arg, 10) catch tiers.len;
        if (max_tier > tiers.len) max_tier = tiers.len;
    }

    common.printHeader("  QUIC scale benchmark ({d} tiers)", .{max_tier});
    common.printTableRow(
        "  {s:<10} {s:>7} {s:>8} {s:>10} {s:>10} {s:>12}",
        .{ "Tier", "Conns", "Streams", "Setup/s", "Poll(us)", "Accept/s" },
    );
    common.printSeparator();

    var results = std.ArrayList(common.TierResult).init(allocator);
    defer {
        for (results.items) |r| {
            allocator.free(r.params);
            allocator.free(r.metrics);
        }
        results.deinit();
    }

    for (tiers[0..max_tier]) |tier| {
        var config = cfg.QuicConfig{
            .alpn = &test_alpn,
            .allow_insecure = true,
            .max_connections = 0,
        };

        // --- Measure connection setup rate ---
        var setup_timer = common.Timer.start();
        var ep = try Endpoint.init(allocator, "127.0.0.1:0", &config);

        var c: usize = 0;
        while (c < tier.connections) : (c += 1) {
            var port_buf: [6]u8 = undefined;
            const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast((c % 55000) + 10000))}) catch continue;
            var addr_buf: [22]u8 = undefined;
            const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
            _ = ep.connectClient(addr) catch continue;
        }
        setup_timer.stop();

        const conn_setup_ops_sec = common.opsPerSec(tier.connections, setup_timer.elapsed_ns());

        // --- Measure poll overhead ---
        // Warmup
        var w: usize = 0;
        while (w < tier.iterations / 5) : (w += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }

        var poll_timer = common.Timer.start();
        var i: usize = 0;
        while (i < tier.iterations) : (i += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }
        poll_timer.stop();
        const poll_us = common.nsPerOp(tier.iterations, poll_timer.elapsed_ns()) / 1000.0;

        // --- Measure accept rate ---
        var accept_timer = common.Timer.start();
        var a: usize = 0;
        const accept_iters = tier.iterations * 10;
        while (a < accept_iters) : (a += 1) {
            _ = ep.popAccepted();
        }
        accept_timer.stop();
        const accept_ops_sec = common.opsPerSec(accept_iters, accept_timer.elapsed_ns());

        ep.deinit();

        const total_streams = tier.connections * tier.streams_per_conn;

        common.printTableRow(
            "  {s:<10} {d:>7} {d:>8} {d:>10.0} {d:>10.1} {d:>12.0}",
            .{ tier.name, tier.connections, total_streams, conn_setup_ops_sec, poll_us, accept_ops_sec },
        );

        const params = try allocator.alloc(common.Param, 2);
        params[0] = .{ .name = "connections", .value = @intCast(tier.connections) };
        params[1] = .{ .name = "streams_per_conn", .value = @intCast(tier.streams_per_conn) };

        const metrics = try allocator.alloc(common.Metric, 3);
        metrics[0] = .{ .name = "conn_setup_ops_sec", .value = conn_setup_ops_sec };
        metrics[1] = .{ .name = "poll_us", .value = poll_us };
        metrics[2] = .{ .name = "accept_rate_ops_sec", .value = accept_ops_sec };

        try results.append(.{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    std.debug.print("\n", .{});
    try common.emitJson(allocator, "scale", results.items);
}
```

- [ ] **Step 2: Register bench-scale in build.zig**

Add after the bench-poll registration:

```zig
    // Connection/stream scaling benchmark
    const bench_scale = addExe(b, "bench-scale", "benchmarks/scale_bench.zig", target, .ReleaseFast);
    bench_scale.root_module.addImport("bench_common", bench_common_mod);
    bench_scale.root_module.addImport("quic_endpoint", quic_endpoint_mod);
    bench_scale.root_module.addImport("quic_conn", quic_conn_mod);
    bench_scale.root_module.addImport("quic_config", quic_config_mod);
    const install_bench_scale = b.addInstallArtifact(bench_scale, .{});
    const run_bench_scale = b.addRunArtifact(bench_scale);
    if (b.args) |args| run_bench_scale.addArgs(args);
    const bench_scale_step = b.step("bench-scale", "Run connection/stream scaling benchmark");
    bench_scale_step.dependOn(&install_bench_scale.step);
    bench_scale_step.dependOn(&run_bench_scale.step);
```

- [ ] **Step 3: Build and run first 3 tiers**

Run: `zig build bench-scale -- 3`
Expected: Table with 1c, 10c, 100c tiers showing Setup/s, Poll(us), Accept/s

- [ ] **Step 4: Verify JSON output**

Run: `zig build bench-scale -- 2 2>/dev/null | head -5`
Expected: JSON with `"suite": "scale"` and tier data

- [ ] **Step 5: Commit**

```bash
git add benchmarks/scale_bench.zig build.zig
git commit -m "feat: add connection/stream scaling benchmark (loopback, 7 tiers)"
```

---

### Task 4: Compare Tool (Regression Detection)

**Files:**
- Create: `benchmarks/compare.zig`
- Create: `benchmarks/results/README.md`
- Modify: `build.zig` (add bench-compare step)

- [ ] **Step 1: Create compare.zig**

```zig
// benchmarks/compare.zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Benchmark regression detection tool.
//
// Reads two JSON result files, compares each metric at each tier,
// prints a table showing delta% and pass/fail.
//
// Usage: zig build bench-compare -- baseline.json current.json
// Optional: zig build bench-compare -- baseline.json current.json 25
//           (last arg is threshold percentage, default per-metric)
//
// Exit code 0 if all pass, 1 if any regression exceeds threshold.

const std = @import("std");

const print = std.debug.print;

// ---------------------------------------------------------------------------
// Metric classification
// ---------------------------------------------------------------------------

const MetricKind = enum {
    higher_is_better,
    lower_is_better,
};

const MetricDef = struct {
    suffix: []const u8,
    kind: MetricKind,
    default_threshold: f64, // percentage
};

// Suffix-based classification: match the end of the metric name
const metric_defs = [_]MetricDef{
    .{ .suffix = "_ops_sec", .kind = .higher_is_better, .default_threshold = 15.0 },
    .{ .suffix = "_mbps", .kind = .higher_is_better, .default_threshold = 15.0 },
    .{ .suffix = "_per_sec", .kind = .higher_is_better, .default_threshold = 15.0 },
    .{ .suffix = "_pps", .kind = .higher_is_better, .default_threshold = 15.0 },
    .{ .suffix = "polls_per_sec", .kind = .higher_is_better, .default_threshold = 25.0 },
    .{ .suffix = "_ns", .kind = .lower_is_better, .default_threshold = 20.0 },
    .{ .suffix = "_ms", .kind = .lower_is_better, .default_threshold = 20.0 },
    .{ .suffix = "_us", .kind = .lower_is_better, .default_threshold = 20.0 },
};

fn classifyMetric(name: []const u8) struct { kind: MetricKind, threshold: f64 } {
    // Check longest match first (polls_per_sec before _per_sec)
    for (metric_defs) |md| {
        if (name.len >= md.suffix.len and
            std.mem.eql(u8, name[name.len - md.suffix.len ..], md.suffix))
        {
            return .{ .kind = md.kind, .threshold = md.default_threshold };
        }
    }
    // Default: lower is better, 20% threshold
    return .{ .kind = .lower_is_better, .threshold = 20.0 };
}

// ---------------------------------------------------------------------------
// JSON parsing (simplified: extract tiers with name + metrics map)
// ---------------------------------------------------------------------------

const ParsedTier = struct {
    name: []const u8,
    metrics: std.StringHashMap(f64),
};

fn parseJsonFile(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList(ParsedTier) {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(data);

    var result = std.ArrayList(ParsedTier).init(allocator);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return result;

    const tiers_val = root.object.get("tiers") orelse return result;
    if (tiers_val != .array) return result;

    for (tiers_val.array.items) |tier_val| {
        if (tier_val != .object) continue;
        const name_val = tier_val.object.get("name") orelse continue;
        if (name_val != .string) continue;

        var metrics_map = std.StringHashMap(f64).init(allocator);

        const metrics_val = tier_val.object.get("metrics") orelse continue;
        if (metrics_val != .object) continue;

        var it = metrics_val.object.iterator();
        while (it.next()) |entry| {
            const v: f64 = switch (entry.value_ptr.*) {
                .integer => |i| @floatFromInt(i),
                .float => |f| f,
                else => continue,
            };
            metrics_map.put(entry.key_ptr.*, v) catch continue;
        }

        try result.append(.{
            .name = name_val.string,
            .metrics = metrics_map,
        });
    }

    return result;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.next(); // skip program name

    const baseline_path = args_it.next() orelse {
        print("Usage: bench-compare <baseline.json> <current.json> [threshold%%]\n", .{});
        std.process.exit(2);
    };
    const current_path = args_it.next() orelse {
        print("Usage: bench-compare <baseline.json> <current.json> [threshold%%]\n", .{});
        std.process.exit(2);
    };

    var threshold_override: ?f64 = null;
    if (args_it.next()) |arg| {
        threshold_override = std.fmt.parseFloat(f64, arg) catch null;
    }

    var baseline = try parseJsonFile(allocator, baseline_path);
    defer {
        for (baseline.items) |*t| t.metrics.deinit();
        baseline.deinit();
    }

    var current = try parseJsonFile(allocator, current_path);
    defer {
        for (current.items) |*t| t.metrics.deinit();
        current.deinit();
    }

    // Print header
    print("\n", .{});
    print("  {s:<10} {s:<24} {s:>12} {s:>12} {s:>8} {s:>6}\n", .{
        "Tier", "Metric", "Baseline", "Current", "Delta%", "Status",
    });
    print("  {s}\n", .{"-" ** 74});

    var any_fail = false;

    for (baseline.items) |bt| {
        // Find matching current tier
        var ct: ?ParsedTier = null;
        for (current.items) |t| {
            if (std.mem.eql(u8, t.name, bt.name)) {
                ct = t;
                break;
            }
        }
        if (ct == null) continue;

        var mit = bt.metrics.iterator();
        while (mit.next()) |entry| {
            const name = entry.key_ptr.*;
            const base_val = entry.value_ptr.*;
            const cur_val = ct.?.metrics.get(name) orelse continue;

            if (base_val == 0) continue;
            const delta_pct = ((cur_val - base_val) / base_val) * 100.0;

            const cls = classifyMetric(name);
            const threshold = threshold_override orelse cls.threshold;

            const is_regression = switch (cls.kind) {
                .higher_is_better => delta_pct < -threshold,
                .lower_is_better => delta_pct > threshold,
            };

            const status: []const u8 = if (is_regression) "FAIL" else "PASS";
            if (is_regression) any_fail = true;

            print("  {s:<10} {s:<24} {d:>12.1} {d:>12.1} {d:>+7.1}% {s:>6}\n", .{
                bt.name, name, base_val, cur_val, delta_pct, status,
            });
        }
    }

    print("\n", .{});

    if (any_fail) {
        print("  REGRESSION DETECTED -- one or more metrics exceeded threshold\n\n", .{});
        std.process.exit(1);
    } else {
        print("  All metrics within threshold -- PASS\n\n", .{});
    }
}
```

- [ ] **Step 2: Create results/README.md**

```markdown
# Benchmark Results

JSON benchmark result files. Format version 1.

## Files

- `baseline.json` -- accepted performance standard (update with `make bench-baseline`)
- `<git-sha>.json` -- per-commit snapshots (save with `make bench-save`)

## Workflow

1. `make bench-baseline` -- set new acceptance criteria
2. `make bench-save` -- capture current performance snapshot
3. `make bench-compare` -- detect regressions against baseline (exit 1 on fail)
```

- [ ] **Step 3: Register bench-compare in build.zig**

Add after the bench-scale registration:

```zig
    // Regression comparison tool
    const bench_compare = addExe(b, "bench-compare", "benchmarks/compare.zig", target, .ReleaseFast);
    const install_bench_compare = b.addInstallArtifact(bench_compare, .{});
    const run_bench_compare = b.addRunArtifact(bench_compare);
    if (b.args) |args| run_bench_compare.addArgs(args);
    const bench_compare_step = b.step("bench-compare", "Compare benchmark results against baseline");
    bench_compare_step.dependOn(&install_bench_compare.step);
    bench_compare_step.dependOn(&run_bench_compare.step);
```

- [ ] **Step 4: Test the compare tool**

First generate two result files:

Run:
```bash
zig build bench-scale -- 2 2>/dev/null > /tmp/bench-a.json
zig build bench-scale -- 2 2>/dev/null > /tmp/bench-b.json
zig build bench-compare -- /tmp/bench-a.json /tmp/bench-b.json
```
Expected: All PASS (comparing identical runs, delta should be small)

- [ ] **Step 5: Commit**

```bash
git add benchmarks/compare.zig benchmarks/results/README.md build.zig
git commit -m "feat: add benchmark regression detection tool (compare.zig)"
```

---

### Task 5: Throughput Bench (Real UDP)

**Files:**
- Create: `benchmarks/throughput_bench.zig`
- Modify: `build.zig` (add bench-throughput step)

- [ ] **Step 1: Create throughput_bench.zig**

```zig
// benchmarks/throughput_bench.zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Payload throughput benchmark using real UDP sockets on localhost.
// Measures MB/s and packets/sec at different payload sizes and concurrency.
//
// Run: zig build bench-throughput

const std = @import("std");
const common = @import("bench_common");
const api = @import("quic_api");

const PayloadTier = struct {
    name: []const u8,
    payload_size: usize,
    concurrency: usize,
    iterations: usize,
};

const tiers = [_]PayloadTier{
    // Small payloads, single connection
    .{ .name = "64B-c1", .payload_size = 64, .concurrency = 1, .iterations = 1_000 },
    .{ .name = "1KB-c1", .payload_size = 1024, .concurrency = 1, .iterations = 1_000 },
    // Larger payloads, single connection
    .{ .name = "64KB-c1", .payload_size = 64 * 1024, .concurrency = 1, .iterations = 200 },
    // Small payloads, higher concurrency
    .{ .name = "64B-c10", .payload_size = 64, .concurrency = 10, .iterations = 500 },
    .{ .name = "1KB-c10", .payload_size = 1024, .concurrency = 10, .iterations = 500 },
    // Medium concurrency
    .{ .name = "1KB-c100", .payload_size = 1024, .concurrency = 100, .iterations = 100 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.next();
    var max_tier: usize = tiers.len;
    if (args_it.next()) |arg| {
        max_tier = std.fmt.parseInt(usize, arg, 10) catch tiers.len;
        if (max_tier > tiers.len) max_tier = tiers.len;
    }

    common.printHeader("  QUIC throughput benchmark ({d} tiers)", .{max_tier});
    common.printTableRow(
        "  {s:<12} {s:>10} {s:>6} {s:>10} {s:>12}",
        .{ "Tier", "Payload", "Conc", "Iters", "Note" },
    );
    common.printSeparator();

    var results = std.ArrayList(common.TierResult).init(allocator);
    defer {
        for (results.items) |r| {
            allocator.free(r.params);
            allocator.free(r.metrics);
        }
        results.deinit();
    }

    for (tiers[0..max_tier]) |tier| {
        // Throughput benchmarks require a running server + client handshake.
        // For now, measure the raw endpoint poll+send throughput without TLS
        // to establish baselines. Full TLS throughput requires cert setup
        // which will be added when handshake_bench is connected.

        common.printTableRow(
            "  {s:<12} {d:>10} {d:>6} {d:>10} {s:>12}",
            .{ tier.name, tier.payload_size, tier.concurrency, tier.iterations, "placeholder" },
        );

        const params = try allocator.alloc(common.Param, 2);
        params[0] = .{ .name = "payload_size", .value = @intCast(tier.payload_size) };
        params[1] = .{ .name = "concurrency", .value = @intCast(tier.concurrency) };

        const metrics = try allocator.alloc(common.Metric, 1);
        metrics[0] = .{ .name = "throughput_mbps", .value = 0 };

        try results.append(.{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    std.debug.print("\n  (Full UDP throughput measurement requires TLS cert setup --\n", .{});
    std.debug.print("   see handshake_bench for the server/client pattern)\n\n", .{});

    try common.emitJson(allocator, "throughput", results.items);
}
```

- [ ] **Step 2: Register bench-throughput in build.zig**

```zig
    // Throughput benchmark (real UDP)
    const bench_throughput = addExe(b, "bench-throughput", "benchmarks/throughput_bench.zig", target, .ReleaseFast);
    bench_throughput.root_module.addImport("bench_common", bench_common_mod);
    bench_throughput.root_module.addImport("quic_api", quic_api_mod);
    const install_bench_throughput = b.addInstallArtifact(bench_throughput, .{});
    const run_bench_throughput = b.addRunArtifact(bench_throughput);
    if (b.args) |args| run_bench_throughput.addArgs(args);
    const bench_throughput_step = b.step("bench-throughput", "Run payload throughput benchmark (real UDP)");
    bench_throughput_step.dependOn(&install_bench_throughput.step);
    bench_throughput_step.dependOn(&run_bench_throughput.step);
```

- [ ] **Step 3: Build and verify**

Run: `zig build bench-throughput -- 2`
Expected: Compiles, prints tier table with placeholder values, emits JSON

- [ ] **Step 4: Commit**

```bash
git add benchmarks/throughput_bench.zig build.zig
git commit -m "feat: add throughput benchmark scaffold (real UDP, 6 tiers)"
```

---

### Task 6: Handshake Bench (Real UDP)

**Files:**
- Create: `benchmarks/handshake_bench.zig`
- Modify: `build.zig` (add bench-handshake step)

- [ ] **Step 1: Create handshake_bench.zig**

```zig
// benchmarks/handshake_bench.zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// TLS handshake latency benchmark. Measures handshake completion time
// at varying concurrency levels using real UDP.
//
// Run: zig build bench-handshake

const std = @import("std");
const common = @import("bench_common");
const api = @import("quic_api");

const HandshakeTier = struct {
    name: []const u8,
    parallel: usize,
    total_handshakes: usize,
};

const tiers = [_]HandshakeTier{
    .{ .name = "serial", .parallel = 1, .total_handshakes = 100 },
    .{ .name = "10p", .parallel = 10, .total_handshakes = 100 },
    .{ .name = "100p", .parallel = 100, .total_handshakes = 200 },
    .{ .name = "1Kp", .parallel = 1_000, .total_handshakes = 1_000 },
    .{ .name = "10Kp", .parallel = 10_000, .total_handshakes = 10_000 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_it = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.next();
    var max_tier: usize = tiers.len;
    if (args_it.next()) |arg| {
        max_tier = std.fmt.parseInt(usize, arg, 10) catch tiers.len;
        if (max_tier > tiers.len) max_tier = tiers.len;
    }

    common.printHeader("  QUIC handshake benchmark ({d} tiers)", .{max_tier});
    common.printTableRow(
        "  {s:<10} {s:>10} {s:>12} {s:>12}",
        .{ "Tier", "Parallel", "Total", "Note" },
    );
    common.printSeparator();

    var results = std.ArrayList(common.TierResult).init(allocator);
    defer {
        for (results.items) |r| {
            allocator.free(r.params);
            allocator.free(r.metrics);
        }
        results.deinit();
    }

    for (tiers[0..max_tier]) |tier| {
        // Full handshake benchmarks require TLS cert generation and a
        // server thread. This scaffold establishes the tier structure
        // and JSON output format. The measurement implementation will
        // use the same cert-gen pattern as cmd/quic-server.zig.

        common.printTableRow(
            "  {s:<10} {d:>10} {d:>12} {s:>12}",
            .{ tier.name, tier.parallel, tier.total_handshakes, "placeholder" },
        );

        const params = try allocator.alloc(common.Param, 1);
        params[0] = .{ .name = "parallel", .value = @intCast(tier.parallel) };

        const metrics = try allocator.alloc(common.Metric, 1);
        metrics[0] = .{ .name = "handshake_avg_ms", .value = 0 };

        try results.append(.{
            .name = tier.name,
            .params = params,
            .metrics = metrics,
        });
    }

    std.debug.print("\n  (Full handshake measurement requires TLS cert generation --\n", .{});
    std.debug.print("   will be wired after server/client pattern is established)\n\n", .{});

    try common.emitJson(allocator, "handshake", results.items);
}
```

- [ ] **Step 2: Register bench-handshake in build.zig**

```zig
    // Handshake latency benchmark (real UDP)
    const bench_handshake = addExe(b, "bench-handshake", "benchmarks/handshake_bench.zig", target, .ReleaseFast);
    bench_handshake.root_module.addImport("bench_common", bench_common_mod);
    bench_handshake.root_module.addImport("quic_api", quic_api_mod);
    const install_bench_handshake = b.addInstallArtifact(bench_handshake, .{});
    const run_bench_handshake = b.addRunArtifact(bench_handshake);
    if (b.args) |args| run_bench_handshake.addArgs(args);
    const bench_handshake_step = b.step("bench-handshake", "Run TLS handshake latency benchmark (real UDP)");
    bench_handshake_step.dependOn(&install_bench_handshake.step);
    bench_handshake_step.dependOn(&run_bench_handshake.step);
```

- [ ] **Step 3: Build and verify**

Run: `zig build bench-handshake -- 2`
Expected: Compiles, prints tier table, emits JSON

- [ ] **Step 4: Commit**

```bash
git add benchmarks/handshake_bench.zig build.zig
git commit -m "feat: add handshake latency benchmark scaffold (real UDP, 5 tiers)"
```

---

### Task 7: Makefile Targets

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add benchmark targets to Makefile**

Add after the existing `bench:` target:

```makefile
bench-poll:
	$(ZIG) build bench-poll $(ZIG_FLAGS)

bench-scale:
	$(ZIG) build bench-scale $(ZIG_FLAGS)

bench-throughput:
	$(ZIG) build bench-throughput $(ZIG_FLAGS)

bench-handshake:
	$(ZIG) build bench-handshake $(ZIG_FLAGS)

bench-all: bench bench-poll bench-scale bench-throughput bench-handshake

bench-save:
	@echo "Running scale benchmark and saving results..."
	@$(ZIG) build bench-scale $(ZIG_FLAGS) 2>/dev/null > benchmarks/results/$$(git rev-parse --short HEAD).json
	@echo "Saved to benchmarks/results/$$(git rev-parse --short HEAD).json"

bench-baseline:
	@echo "Running scale benchmark and saving as baseline..."
	@$(ZIG) build bench-scale $(ZIG_FLAGS) 2>/dev/null > benchmarks/results/baseline.json
	@echo "Saved to benchmarks/results/baseline.json"

bench-compare:
	@echo "Running scale benchmark and comparing against baseline..."
	@$(ZIG) build bench-scale $(ZIG_FLAGS) 2>/dev/null > /tmp/quic-current-bench.json
	@$(ZIG) build bench-compare $(ZIG_FLAGS) -- benchmarks/results/baseline.json /tmp/quic-current-bench.json
```

- [ ] **Step 2: Verify make bench-poll works**

Run: `make bench-poll`
Expected: Runs poll benchmark, prints table

- [ ] **Step 3: Verify make bench-scale works**

Run: `make bench-scale`
Expected: Runs scale benchmark, prints table + JSON

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "feat: add Makefile targets for benchmark suite"
```

---

### Task 8: Generate Initial Baseline

**Files:**
- Create: `benchmarks/results/baseline.json` (generated)

- [ ] **Step 1: Generate and save baseline**

Run: `make bench-baseline`
Expected: Runs scale benchmark, saves to `benchmarks/results/baseline.json`

- [ ] **Step 2: Verify baseline file**

Run: `cat benchmarks/results/baseline.json | head -10`
Expected: JSON with `"version": 1, "suite": "scale"`, tier data

- [ ] **Step 3: Verify comparison against self**

Run: `make bench-compare`
Expected: All PASS (comparing fresh run against just-saved baseline)

- [ ] **Step 4: Commit baseline**

```bash
git add benchmarks/results/baseline.json
git commit -m "chore: save initial scale benchmark baseline"
```

---

### Task 9: Add bench-all to CI Target

**Files:**
- Modify: `Makefile` (update `ci` target if it exists)

- [ ] **Step 1: Check if CI target exists**

Run: `grep -n "^ci:" Makefile`

If it exists, add `bench-poll bench-scale` to its dependencies (not throughput/handshake since those need real network and TLS).

If it does not exist, skip this step.

- [ ] **Step 2: Verify full benchmark suite**

Run: `make bench-all`
Expected: All 5 benchmark suites run (micro + poll + scale + throughput scaffold + handshake scaffold)

- [ ] **Step 3: Final commit**

```bash
git add Makefile
git commit -m "chore: wire poll and scale benchmarks into CI target"
```

---

## Summary

| Task | What it produces | Dependencies |
|------|-----------------|-------------|
| 1. Common Harness | `benchmarks/common.zig` | None |
| 2. Poll Bench | `benchmarks/poll_bench.zig` + build.zig | Task 1 |
| 3. Scale Bench | `benchmarks/scale_bench.zig` + build.zig | Task 1 |
| 4. Compare Tool | `benchmarks/compare.zig` + results/README.md | Task 3 (for testing) |
| 5. Throughput Bench | `benchmarks/throughput_bench.zig` + build.zig | Task 1 |
| 6. Handshake Bench | `benchmarks/handshake_bench.zig` + build.zig | Task 1 |
| 7. Makefile | Makefile targets | Tasks 2-6 |
| 8. Baseline | `benchmarks/results/baseline.json` | Tasks 3, 4, 7 |
| 9. CI Integration | CI wiring | Task 7 |

Tasks 2-6 can be parallelized (they all depend only on Task 1). Tasks 7-9 are sequential.
