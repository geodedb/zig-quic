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
    /// Populated only by external-tier scenarios. Suffix "-SKIP" marks a
    /// row that was skipped (toolchain missing / build failed / server
    /// failed to start); downstream compare/gate treats skip rows as
    /// non-contributing rather than regressions.
    external_impl: ?[]const u8 = null,
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
        if (d < best_diff) {
            best_diff = d;
            median_idx = i;
        }
    }
    const rep = outputs[median_idx];

    const summary = summarizeLatencies(rep.latencies_ns);
    const handshake_summary: ?LatencySummary = if (rep.handshake_latencies_ns) |h|
        summarizeLatencies(h)
    else
        null;

    return ResultRow{
        .git_sha = try gitSha(allocator, io),
        .run_timestamp_unix_s = @as(i64, @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_s))),
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
        .bytes_per_sec = if (rep.bytes_transferred == 0) null else @intFromFloat(@as(f64, @floatFromInt(rep.bytes_transferred)) * 1e9 / @as(f64, @floatFromInt(rep.wall_time_ns))),
        .packets_per_sec = if (rep.packets_transferred == 0) null else @intFromFloat(@as(f64, @floatFromInt(rep.packets_transferred)) * 1e9 / @as(f64, @floatFromInt(rep.wall_time_ns))),
        .handshake_latency_p50_ns = if (handshake_summary) |h| h.p50_ns else null,
        .handshake_latency_p99_ns = if (handshake_summary) |h| h.p99_ns else null,
        .connection_count = spec.connection_count,
        .streams_count = spec.streams_count,
        .payload_bytes = spec.payload_bytes,
        .retransmit_count = if (rep.retransmit_count == 0) null else rep.retransmit_count,
        .cwnd_final_bytes = if (rep.cwnd_final_bytes == 0) null else rep.cwnd_final_bytes,
        .rtt_smoothed_ns = if (rep.rtt_smoothed_ns == 0) null else rep.rtt_smoothed_ns,
        .mutex_hold_wall_ns = if (rep.mutex_hold_wall_ns == 0) null else rep.mutex_hold_wall_ns,
        .external_impl = rep.external_impl,
    };
}

pub fn writeDocument(
    allocator: std.mem.Allocator,
    io: std.Io,
    rows: []const ResultRow,
    output_path: ?[]const u8,
) !void {
    const doc = ResultDocument{
        .generated_at_unix_s = @as(i64, @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_s))),
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
    const ts = nanoTimestamp();
    return if (ts < 0) 0 else @intCast(ts);
}

/// Zig 0.16.0 compat: std.time.nanoTimestamp() was removed. Mirrors the shim
/// used in tests/test_transport_geode_compat.zig so timestamps can be emitted
/// without a platform-specific branch on every caller.
fn nanoTimestamp() i128 {
    if (builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    }
    // Fallback: monotonic-ish but non-epoch on unsupported hosts. Callers
    // treat timestamps as opaque comparators; absolute epoch only matters
    // inside ResultDocument.generated_at_unix_s which divides by ns_per_s.
    var timer = std.time.Timer.start() catch return 0;
    return @as(i128, @intCast(timer.read()));
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
    const exited = switch (result.term) {
        .exited => |c| c,
        else => 1,
    };
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
    const page_size = std.heap.pageSize();
    const posix = std.posix;
    const fd = try posix.openat(posix.AT.FDCWD, "/proc/self/statm", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
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
    const fd = try posix.openat(posix.AT.FDCWD, "/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
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
