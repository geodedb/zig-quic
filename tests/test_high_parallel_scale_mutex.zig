// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Heavy localhost scale regression for endpoint PTO-dirty mutexing. This is
// intentionally filter/env gated because 20k Connection objects consume hundreds
// of MiB due the per-connection packet buffer pool.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

const DEFAULT_CONNECTIONS: usize = 20_000;
const DEFAULT_DIRTY_THREADS: usize = 8;
const DEFAULT_DIRTY_ROUNDS: usize = 8;
const DEFAULT_DURATION_MS: usize = 1_000;

fn envEnabled(name: [:0]const u8) bool {
    const raw = std.c.getenv(name) orelse return false;
    const value = std.mem.span(raw);
    return value.len != 0 and !std.mem.eql(u8, value, "0") and !std.mem.eql(u8, value, "false");
}

fn envUsize(name: [:0]const u8, default: usize) usize {
    const raw = std.c.getenv(name) orelse return default;
    return std.fmt.parseUnsigned(usize, std.mem.span(raw), 10) catch default;
}

fn threadSleep(ns: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.os.linux.nanosleep(&ts, &ts);
}

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn dirtySetCount(ep: *endpoint_mod.Endpoint) usize {
    const io = std.Io.Threaded.global_single_threaded.io();
    ep.pto_dirty_mu.lockUncancelable(io);
    defer ep.pto_dirty_mu.unlock(io);
    return ep.pto_dirty_set.count();
}

fn closedSetCount(ep: *endpoint_mod.Endpoint) usize {
    const io = std.Io.Threaded.global_single_threaded.io();
    ep.closed_conn_mu.lockUncancelable(io);
    defer ep.closed_conn_mu.unlock(io);
    return ep.closed_conn_set.count();
}

fn populateConnections(
    allocator: std.mem.Allocator,
    ep: *endpoint_mod.Endpoint,
    total: usize,
) ![]*conn_mod.Connection {
    try ep.conns.ensureTotalCapacity(@intCast(total * 2));
    try ep.pto_dirty_set.ensureTotalCapacity(@intCast(total));

    const conns = try allocator.alloc(*conn_mod.Connection, total);
    errdefer allocator.free(conns);

    var i: usize = 0;
    while (i < total) : (i += 1) {
        const port: u16 = @intCast((i % 55_000) + 10_000);
        var addr_buf: [32]u8 = undefined;
        const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port});
        conns[i] = try ep.connectClient(addr);
    }

    return conns;
}

fn assertDirtyDrained(ep: *endpoint_mod.Endpoint, conns: []*conn_mod.Connection) !void {
    try testing.expectEqual(@as(u32, 0), ep.pto_dirty_count.load(.acquire));
    try testing.expectEqual(@as(usize, 0), dirtySetCount(ep));
    for (conns) |conn| {
        try testing.expect(!conn.pto_dirty.load(.acquire));
    }
}

test "high-parallel scale: 20k dirty notifications drain under poll contention" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!envEnabled("QUIC_HEAVY_SCALE")) return error.SkipZigTest;

    const allocator = std.heap.smp_allocator;
    const connection_count = envUsize("QUIC_HEAVY_CONNECTIONS", DEFAULT_CONNECTIONS);
    const dirty_threads = envUsize("QUIC_HEAVY_DIRTY_THREADS", DEFAULT_DIRTY_THREADS);
    const dirty_rounds = envUsize("QUIC_HEAVY_DIRTY_ROUNDS", DEFAULT_DIRTY_ROUNDS);
    const duration_ms = envUsize("QUIC_HEAVY_DURATION_MS", DEFAULT_DURATION_MS);

    try testing.expect(connection_count >= 20_000);
    try testing.expect(dirty_threads > 0);
    try testing.expect(dirty_rounds > 0);
    try testing.expect(duration_ms > 0);

    var config = cfg.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .allow_insecure = true,
        .max_connections = 0,
    };
    var ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const conns = try populateConnections(allocator, &ep, connection_count);
    defer allocator.free(conns);
    try testing.expectEqual(connection_count, conns.len);

    // connectClient installs the endpoint notifier while each Connection starts
    // dirty. Drain that seeded state before the contention phase.
    _ = try ep.pollWithStats(0);
    try assertDirtyDrained(&ep, conns);
    try testing.expectEqual(@as(usize, 0), ep.timers.items.len);

    var stop_poll = std.atomic.Value(bool).init(false);
    var poll_ops = std.atomic.Value(u64).init(0);
    const poll_thread = try std.Thread.spawn(.{}, struct {
        fn run(ep_ptr: *endpoint_mod.Endpoint, stop: *std.atomic.Value(bool), ops: *std.atomic.Value(u64)) void {
            while (!stop.load(.acquire)) {
                _ = ep_ptr.pollWithStats(0) catch {};
                _ = ops.fetchAdd(1, .monotonic);
            }
        }
    }.run, .{ &ep, &stop_poll, &poll_ops });

    const deadline_ns = nowNs() + @as(u64, @intCast(duration_ms)) * std.time.ns_per_ms;
    const workers = try allocator.alloc(std.Thread, dirty_threads);
    defer allocator.free(workers);
    for (workers, 0..) |*worker, worker_id| {
        worker.* = try std.Thread.spawn(.{}, struct {
            fn run(connections: []*conn_mod.Connection, thread_id: usize, stride: usize, min_rounds: usize, deadline: u64) void {
                var round: usize = 0;
                while (round < min_rounds or nowNs() < deadline) : (round += 1) {
                    var i = thread_id;
                    while (i < connections.len) : (i += stride) {
                        connections[i].markPtoDirty();
                    }
                    threadSleep(1 * std.time.ns_per_ms);
                }
            }
        }.run, .{ conns, worker_id, dirty_threads, dirty_rounds, deadline_ns });
    }

    for (workers) |worker| worker.join();
    stop_poll.store(true, .release);
    poll_thread.join();

    var drain: usize = 0;
    while (drain < 16) : (drain += 1) {
        _ = try ep.pollWithStats(0);
        if (ep.pto_dirty_count.load(.acquire) == 0 and dirtySetCount(&ep) == 0) break;
    }

    try testing.expect(poll_ops.load(.acquire) > 0);
    try assertDirtyDrained(&ep, conns);

    for (conns) |conn| conn.markClosed();
    try testing.expectEqual(@as(u32, @intCast(connection_count)), ep.closed_conn_count.load(.acquire));
    try testing.expectEqual(connection_count, closedSetCount(&ep));

    _ = try ep.pollWithStats(0);
    try testing.expectEqual(@as(u32, 0), ep.closed_conn_count.load(.acquire));
    try testing.expectEqual(@as(usize, 0), closedSetCount(&ep));
    try testing.expectEqual(@as(usize, 0), ep.conns.count());
    try testing.expect(ep.retired.items.len >= connection_count);
}
