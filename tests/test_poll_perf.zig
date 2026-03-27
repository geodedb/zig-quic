// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Poll loop performance regression tests.
//
// These tests measure the overhead of pollWithStats() under different
// connection counts to detect lock contention regressions. The key metric
// is poll cycles per second — higher is better.
//
// The bottleneck being tested: ep.mu lock held during Phases 4b and 5
// of pollWithStats(). With N connections, Phase 5 (armConnectionPtoTimers)
// iterates all connections. Before optimization, each connection called
// nanoTimestamp() and computeSpacePtoTimeNs() 3x unconditionally, creating
// O(3N) syscall overhead per poll cycle. After fix, early-exit checks
// skip these syscalls when PTO timers are already armed (common case).

const std = @import("std");
const testing = std.testing;

const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;

const test_alpn = [_][]const u8{"h3"};

fn makeTestConfig() cfg.QuicConfig {
    return cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0,
    };
}

// Measure poll cycles per second with zero connections.
// Baseline: should be >100k polls/sec (pure lock overhead).
test "perf: poll cycle rate - 0 connections (baseline)" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const iterations: usize = 10_000;
    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        _ = ep.pollWithStats(0) catch continue;
    }

    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;
    const polls_per_sec = if (elapsed_ms > 0) (iterations * 1000) / @as(usize, @intCast(elapsed_ms)) else iterations * 1_000_000;

    std.debug.print("\n[PERF] 0 connections: {} polls in {}ms = {} polls/sec\n", .{ iterations, elapsed_ms, polls_per_sec });

    // Baseline: at least 10k polls/sec with 0 connections
    try testing.expect(polls_per_sec > 10_000);
}

// Measure poll cycle rate with 1 connection.
// Regression test: Phase 5 should not add significant overhead for 1 connection.
test "perf: poll cycle rate - 1 connection" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Create 1 connection
    _ = ep.connectClient("127.0.0.1:10001") catch {};

    const iterations: usize = 10_000;
    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        _ = ep.pollWithStats(0) catch continue;
    }

    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;
    const polls_per_sec = if (elapsed_ms > 0) (iterations * 1000) / @as(usize, @intCast(elapsed_ms)) else iterations * 1_000_000;

    std.debug.print("\n[PERF] 1 connection: {} polls in {}ms = {} polls/sec\n", .{ iterations, elapsed_ms, polls_per_sec });

    // 1 connection should not significantly degrade from baseline
    try testing.expect(polls_per_sec > 5_000);
}

// Measure poll cycle rate with 10 connections.
// Regression test: Phase 5 iterates all 10 connections every cycle.
test "perf: poll cycle rate - 10 connections" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(40000 + i))}) catch continue;
        var addr_buf: [22]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }

    const iterations: usize = 5_000;
    const start = std.time.nanoTimestamp();

    i = 0;
    while (i < iterations) : (i += 1) {
        _ = ep.pollWithStats(0) catch continue;
    }

    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;
    const polls_per_sec = if (elapsed_ms > 0) (iterations * 1000) / @as(usize, @intCast(elapsed_ms)) else iterations * 1_000_000;

    std.debug.print("\n[PERF] 10 connections: {} polls in {}ms = {} polls/sec\n", .{ iterations, elapsed_ms, polls_per_sec });

    // 10 connections should still allow >2k polls/sec
    try testing.expect(polls_per_sec > 2_000);
}

// Measure poll cycle rate with 100 connections.
// This is the critical test for lock contention at scale.
test "perf: poll cycle rate - 100 connections" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(50000 + i))}) catch continue;
        var addr_buf: [22]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }

    const iterations: usize = 2_000;
    const start = std.time.nanoTimestamp();

    i = 0;
    while (i < iterations) : (i += 1) {
        _ = ep.pollWithStats(0) catch continue;
    }

    const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;
    const polls_per_sec = if (elapsed_ms > 0) (iterations * 1000) / @as(usize, @intCast(elapsed_ms)) else iterations * 1_000_000;

    std.debug.print("\n[PERF] 100 connections: {} polls in {}ms = {} polls/sec\n", .{ iterations, elapsed_ms, polls_per_sec });

    // 100 connections should still allow >500 polls/sec
    try testing.expect(polls_per_sec > 500);
}

// Measure per-poll overhead as a function of connection count.
// Reports microseconds per poll call for regression tracking.
// Asserts that overhead scales sub-linearly.
test "perf: per-poll overhead scaling" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const conn_counts = [_]usize{ 0, 1, 10, 50 };
    var us_per_poll_results: [conn_counts.len]u64 = undefined;
    var conn_idx: usize = 0;

    for (conn_counts, 0..) |target_conns, ci| {
        // Add connections to reach target
        while (conn_idx < target_conns) : (conn_idx += 1) {
            var port_buf: [6]u8 = undefined;
            const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(60000 + conn_idx))}) catch continue;
            var addr_buf: [22]u8 = undefined;
            const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
            _ = ep.connectClient(addr) catch continue;
        }

        const iterations: usize = 5_000;
        const start = std.time.nanoTimestamp();

        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            _ = ep.pollWithStats(0) catch continue;
        }

        const elapsed_ns: u64 = @intCast(std.time.nanoTimestamp() - start);
        us_per_poll_results[ci] = elapsed_ns / (std.time.ns_per_us * iterations);
    }

    // Assert: 50 connections should not be more than 20x overhead vs 0 connections
    // This catches the O(3N) syscall regression per poll cycle
    const baseline = if (us_per_poll_results[0] > 0) us_per_poll_results[0] else 1;
    const at_50 = us_per_poll_results[3];
    try testing.expect(at_50 < baseline * 20);
}
