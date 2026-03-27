// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 DevNW / CodePros

//! Shared benchmark harness for the QUIC benchmark suite.
//!
//! Provides timing, JSON output, table printing, and math helpers
//! used by all benchmark executables (poll, scale, throughput, handshake).

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// High-resolution timer backed by `std.time.nanoTimestamp`.
pub const Timer = struct {
    start_ns: i128,
    stop_ns: ?i128,

    /// Start a new timer, capturing the current timestamp.
    pub fn start() Timer {
        return .{
            .start_ns = std.time.nanoTimestamp(),
            .stop_ns = null,
        };
    }

    /// Stop the timer, capturing the end timestamp.
    pub fn stop(self: *Timer) void {
        self.stop_ns = std.time.nanoTimestamp();
    }

    /// Elapsed time in nanoseconds.
    /// If stop() has not been called, measures up to now.
    pub fn elapsed_ns(self: Timer) u64 {
        const end = self.stop_ns orelse std.time.nanoTimestamp();
        const diff = end - self.start_ns;
        return @intCast(@max(0, diff));
    }

    /// Elapsed time in microseconds.
    pub fn elapsed_us(self: Timer) u64 {
        return self.elapsed_ns() / std.time.ns_per_us;
    }

    /// Elapsed time in milliseconds.
    pub fn elapsed_ms(self: Timer) u64 {
        return self.elapsed_ns() / std.time.ns_per_ms;
    }
};

/// A single named metric (e.g. "ops_per_sec", 1234.5).
pub const Metric = struct {
    name: []const u8,
    value: f64,
};

/// A single named parameter (e.g. "connections", 100).
pub const Param = struct {
    name: []const u8,
    value: u64,
};

/// Result for one benchmark tier (a named configuration with params and metrics).
pub const TierResult = struct {
    name: []const u8,
    params: []const Param,
    metrics: []const Metric,
};

// ---------------------------------------------------------------------------
// JSON output (stdout)
// ---------------------------------------------------------------------------

/// Emit benchmark results as JSON to stdout.
///
/// Format:
/// ```json
/// {
///   "version": 1,
///   "suite": "<suite-name>",
///   "timestamp": <unix-seconds>,
///   "git_commit": "<short-sha or unknown>",
///   "system": { "os": "<os>", "arch": "<arch>" },
///   "tiers": [ { "name": "...", "params": {...}, "metrics": {...} } ]
/// }
/// ```
pub fn emitJson(allocator: std.mem.Allocator, suite: []const u8, tiers: []const TierResult) !void {
    const stdout = std.io.getStdOut().writer();
    var jw = std.json.writeStream(stdout, .{ .whitespace = .indent_2 });
    defer jw.deinit();

    const git_commit = getGitCommit(allocator);
    defer allocator.free(git_commit);

    const timestamp = std.time.timestamp();

    try jw.beginObject();

    try jw.objectField("version");
    try jw.write(1);

    try jw.objectField("suite");
    try jw.write(suite);

    try jw.objectField("timestamp");
    try jw.write(timestamp);

    try jw.objectField("git_commit");
    try jw.write(git_commit);

    try jw.objectField("system");
    try jw.beginObject();
    try jw.objectField("os");
    try jw.write(@tagName(builtin.os.tag));
    try jw.objectField("arch");
    try jw.write(@tagName(builtin.cpu.arch));
    try jw.endObject();

    try jw.objectField("tiers");
    try jw.beginArray();

    for (tiers) |tier| {
        try jw.beginObject();

        try jw.objectField("name");
        try jw.write(tier.name);

        try jw.objectField("params");
        try jw.beginObject();
        for (tier.params) |p| {
            try jw.objectField(p.name);
            try jw.write(p.value);
        }
        try jw.endObject();

        try jw.objectField("metrics");
        try jw.beginObject();
        for (tier.metrics) |m| {
            try jw.objectField(m.name);
            try jw.write(m.value);
        }
        try jw.endObject();

        try jw.endObject();
    }

    try jw.endArray();

    try jw.endObject();

    // Trailing newline for clean output
    try stdout.writeByte('\n');
}

/// Best-effort retrieval of the short git commit hash.
/// Returns "unknown" on any failure.
fn getGitCommit(allocator: std.mem.Allocator) []const u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "git", "rev-parse", "--short", "HEAD" },
    }) catch return allocator.dupe(u8, "unknown") catch return "unknown";
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        allocator.free(result.stdout);
        return allocator.dupe(u8, "unknown") catch return "unknown";
    }

    // Trim trailing newline
    const trimmed = std.mem.trimRight(u8, result.stdout, "\n\r ");
    if (trimmed.len == 0) {
        allocator.free(result.stdout);
        return allocator.dupe(u8, "unknown") catch return "unknown";
    }

    // result.stdout is allocator-owned; we need to return just the trimmed slice.
    // Since trimmed is a sub-slice of result.stdout, we dupe and free the original.
    const commit = allocator.dupe(u8, trimmed) catch {
        allocator.free(result.stdout);
        return "unknown";
    };
    allocator.free(result.stdout);
    return commit;
}

// ---------------------------------------------------------------------------
// Human-readable table output (stderr via std.debug.print)
// ---------------------------------------------------------------------------

/// Print a header line to stderr.
pub fn printHeader(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

/// Print a table row to stderr.
pub fn printTableRow(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

/// Print a separator line to stderr.
pub fn printSeparator() void {
    std.debug.print("{s}\n", .{"-" ** 78});
}

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/// Calculate operations per second from a count and elapsed nanoseconds.
pub fn opsPerSec(count: u64, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    const count_f: f64 = @floatFromInt(count);
    const ns_f: f64 = @floatFromInt(elapsed_ns);
    return count_f / (ns_f / 1_000_000_000.0);
}

/// Calculate nanoseconds per operation from a count and elapsed nanoseconds.
pub fn nsPerOp(count: u64, elapsed_ns: u64) f64 {
    if (count == 0) return 0;
    const ns_f: f64 = @floatFromInt(elapsed_ns);
    const count_f: f64 = @floatFromInt(count);
    return ns_f / count_f;
}

/// Calculate throughput in megabytes per second from bytes and elapsed nanoseconds.
pub fn mbps(bytes: u64, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    const bytes_f: f64 = @floatFromInt(bytes);
    const ns_f: f64 = @floatFromInt(elapsed_ns);
    const seconds = ns_f / 1_000_000_000.0;
    return (bytes_f / (1024.0 * 1024.0)) / seconds;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Timer basic usage" {
    var t = Timer.start();
    // Minimal spin to ensure elapsed > 0
    std.Thread.sleep(1_000);
    t.stop();
    const ns = t.elapsed_ns();
    try std.testing.expect(ns > 0);
    // elapsed_us and elapsed_ms should not error
    _ = t.elapsed_us();
    _ = t.elapsed_ms();
}

test "Timer without stop measures to now" {
    const t = Timer.start();
    std.Thread.sleep(1_000);
    const ns = t.elapsed_ns();
    try std.testing.expect(ns > 0);
}

test "opsPerSec" {
    // 1000 ops in 1 second = 1000 ops/sec
    const result = opsPerSec(1000, 1_000_000_000);
    try std.testing.expectApproxEqRel(result, 1000.0, 0.001);
}

test "opsPerSec zero elapsed" {
    try std.testing.expectEqual(@as(f64, 0), opsPerSec(100, 0));
}

test "nsPerOp" {
    // 1_000_000 ns for 100 ops = 10_000 ns/op
    const result = nsPerOp(100, 1_000_000);
    try std.testing.expectApproxEqRel(result, 10_000.0, 0.001);
}

test "nsPerOp zero count" {
    try std.testing.expectEqual(@as(f64, 0), nsPerOp(0, 1_000_000));
}

test "mbps" {
    // 1 MiB in 1 second = 1.0 MB/s
    const result = mbps(1024 * 1024, 1_000_000_000);
    try std.testing.expectApproxEqRel(result, 1.0, 0.001);
}

test "mbps zero elapsed" {
    try std.testing.expectEqual(@as(f64, 0), mbps(1024, 0));
}

test "Metric struct" {
    const m = Metric{ .name = "ops_per_sec", .value = 42.0 };
    try std.testing.expectEqualStrings("ops_per_sec", m.name);
    try std.testing.expectEqual(@as(f64, 42.0), m.value);
}

test "Param struct" {
    const p = Param{ .name = "connections", .value = 100 };
    try std.testing.expectEqualStrings("connections", p.name);
    try std.testing.expectEqual(@as(u64, 100), p.value);
}

test "TierResult struct" {
    const params = [_]Param{.{ .name = "n", .value = 10 }};
    const metrics = [_]Metric{.{ .name = "ops", .value = 500.0 }};
    const tier = TierResult{
        .name = "small",
        .params = &params,
        .metrics = &metrics,
    };
    try std.testing.expectEqualStrings("small", tier.name);
    try std.testing.expectEqual(@as(usize, 1), tier.params.len);
    try std.testing.expectEqual(@as(usize, 1), tier.metrics.len);
}

test "printSeparator does not crash" {
    printSeparator();
}

test "printHeader does not crash" {
    printHeader("  {s:<20} {s:>10}", .{ "Benchmark", "Value" });
}

test "printTableRow does not crash" {
    printTableRow("  {s:<20} {d:>10.2}", .{ "test_row", 42.5 });
}
