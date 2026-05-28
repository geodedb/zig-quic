// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// GAP-0200: Thread-safety unit tests for QUIC endpoint and connection
//
// This test file validates that the mutex-based thread-safety primitives
// added to the QUIC library work correctly under concurrent access.

const std = @import("std");
const compat = @import("compat");
const testing = std.testing;

// Build system provides these imports
const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

// Default ALPN for tests
const test_alpn = [_][]const u8{"h3"};

// Test that endpoint mutex can be acquired and released properly
test "endpoint mutex initialization" {
    var config = cfg.QuicConfig{ .alpn = &test_alpn };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Test that we can lock and unlock the endpoint mutex
    compat.mutexLock(&ep.mu);
    compat.mutexUnlock(&ep.mu);

    // Test double lock/unlock (simulating sequential access patterns)
    compat.mutexLock(&ep.mu);
    compat.mutexUnlock(&ep.mu);
}

// Test concurrent accept queue operations
test "thread-safe accept queue operations" {
    var config = cfg.QuicConfig{ .alpn = &test_alpn };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Create multiple threads that try to pop from accept queue
    var threads: [4]std.Thread = undefined;
    var pop_results: [4]?*conn_mod.Connection = undefined;

    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *endpoint_mod.Endpoint, result: *?*conn_mod.Connection) void {
                // Attempt to pop - should return null since queue is empty
                result.* = ep_ptr.popAccepted();
            }
        }.run, .{ &ep, &pop_results[i] });
    }

    // Wait for all threads to complete
    for (&threads) |*t| {
        t.join();
    }

    // All results should be null (queue was empty)
    for (pop_results) |result| {
        try testing.expectEqual(@as(?*conn_mod.Connection, null), result);
    }
}

// Test concurrent mutex access stress test
test "concurrent mutex stress test" {
    var config = cfg.QuicConfig{ .alpn = &test_alpn };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 8;
    const iterations_per_thread = 1000;
    var threads: [num_threads]std.Thread = undefined;
    var counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *endpoint_mod.Endpoint, cnt: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < iterations_per_thread) : (i += 1) {
                    compat.mutexLock(&ep_ptr.mu);
                    _ = cnt.fetchAdd(1, .monotonic);
                    compat.mutexUnlock(&ep_ptr.mu);
                }
            }
        }.run, .{ &ep, &counter });
    }

    // Wait for all threads
    for (&threads) |*t| {
        t.join();
    }

    // Verify all increments happened
    try testing.expectEqual(@as(u64, num_threads * iterations_per_thread), counter.load(.monotonic));
}

// Test popAccepted returns null when empty (thread-safe version)
test "popAccepted returns null when empty" {
    var config = cfg.QuicConfig{ .alpn = &test_alpn };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Should return null since no connections have been accepted
    const result = ep.popAccepted();
    try testing.expectEqual(@as(?*conn_mod.Connection, null), result);
}

// Test that mutex protects concurrent popAccepted calls
test "concurrent popAccepted calls are safe" {
    var config = cfg.QuicConfig{ .alpn = &test_alpn };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 16;
    var threads: [num_threads]std.Thread = undefined;
    var null_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *endpoint_mod.Endpoint, cnt: *std.atomic.Value(u32)) void {
                // Call popAccepted many times
                var i: usize = 0;
                while (i < 100) : (i += 1) {
                    const result = ep_ptr.popAccepted();
                    if (result == null) {
                        _ = cnt.fetchAdd(1, .monotonic);
                    }
                }
            }
        }.run, .{ &ep, &null_count });
    }

    // Wait for all threads
    for (&threads) |*t| {
        t.join();
    }

    // All calls should have returned null (no connections)
    try testing.expectEqual(@as(u32, num_threads * 100), null_count.load(.monotonic));
}

// Test that Connection has mutex field
test "connection mutex field exists" {
    // This test verifies Connection keeps both general state and TLS-context
    // serialization primitives.
    // A full connection test would require TLS setup which is complex
    const ConnType = conn_mod.Connection;

    // Check that the struct has a mu field using comptime
    const has_mu = comptime blk: {
        const info = @typeInfo(ConnType);
        for (info.@"struct".fields) |field| {
            if (std.mem.eql(u8, field.name, "mu")) {
                break :blk true;
            }
        }
        break :blk false;
    };
    const has_tls_context_mu = comptime blk: {
        const info = @typeInfo(ConnType);
        for (info.@"struct".fields) |field| {
            if (std.mem.eql(u8, field.name, "tls_context_mu")) {
                break :blk true;
            }
        }
        break :blk false;
    };
    try testing.expect(has_mu);
    try testing.expect(has_tls_context_mu);
}

test "pending_hs_send_retry_waits_for_rx_serial_mutex" {
    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    var conn: conn_mod.Connection = undefined;
    var alloc = testing.allocator;
    conn.init(&alloc, .Server, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.pending_hs_send = true;

    const io = std.Io.Threaded.global_single_threaded.io();
    ep.pending_hs_send_mu.lockUncancelable(io);
    try ep.pending_hs_send_set.put(&conn, {});
    ep.pending_hs_send_count.store(1, .release);
    ep.pending_hs_send_mu.unlock(io);

    conn.endpoint_rx_serial_mu.lockUncancelable(io);

    var poll_started = std.atomic.Value(bool).init(false);
    var poll_done = std.atomic.Value(bool).init(false);
    const poll_thread = try std.Thread.spawn(.{}, struct {
        fn run(endpoint: *endpoint_mod.Endpoint, started: *std.atomic.Value(bool), done: *std.atomic.Value(bool)) void {
            started.store(true, .release);
            _ = endpoint.pollWithStats(0) catch {};
            done.store(true, .release);
        }
    }.run, .{ &ep, &poll_started, &poll_done });

    while (!poll_started.load(.acquire)) {
        compat.threadSleep(std.time.ns_per_ms);
    }
    compat.threadSleep(50 * std.time.ns_per_ms);
    const retry_waited = !poll_done.load(.acquire);

    conn.endpoint_rx_serial_mu.unlock(io);
    poll_thread.join();

    try testing.expect(retry_waited);
    try testing.expect(poll_done.load(.acquire));
}

test "onPacketSent legacy sent maps tolerate concurrent PTO accounting" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    var alloc = gpa.allocator();

    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Server, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    const num_threads = 8;
    const iterations = 256;
    var threads: [num_threads]std.Thread = undefined;

    for (&threads, 0..) |*t, tid| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(c: *conn_mod.Connection, thread_id: usize) void {
                var i: usize = 0;
                while (i < iterations) : (i += 1) {
                    const pn: u64 = @intCast(thread_id * iterations + i);
                    c.onPacketSent(.Initial, pn, 1200, true);
                }
            }
        }.run, .{ &conn, tid });
    }

    for (&threads) |*t| t.join();

    const io = std.Io.Threaded.global_single_threaded.io();
    conn.sent_history_mu.lockUncancelable(io);
    defer conn.sent_history_mu.unlock(io);
    try testing.expectEqual(@as(u32, num_threads * iterations), conn.sent_time.count());
    try testing.expectEqual(@as(u32, num_threads * iterations), conn.sent_sizes.count());
}

test "pto_dirty_recompute_waits_for_connection_mutex" {
    var config = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const conn = try ep.connectClient("127.0.0.1:9");
    _ = try ep.pollWithStats(0);

    conn.markPtoDirty();
    const io = std.Io.Threaded.global_single_threaded.io();
    conn.mu.lockUncancelable(io);

    var poll_started = std.atomic.Value(bool).init(false);
    var poll_done = std.atomic.Value(bool).init(false);
    const poll_thread = try std.Thread.spawn(.{}, struct {
        fn run(endpoint: *endpoint_mod.Endpoint, started: *std.atomic.Value(bool), done: *std.atomic.Value(bool)) void {
            started.store(true, .release);
            _ = endpoint.pollWithStats(0) catch {};
            done.store(true, .release);
        }
    }.run, .{ &ep, &poll_started, &poll_done });

    while (!poll_started.load(.acquire)) {
        compat.threadSleep(std.time.ns_per_ms);
    }
    compat.threadSleep(25 * std.time.ns_per_ms);
    const recompute_waited = !poll_done.load(.acquire);

    conn.mu.unlock(io);
    poll_thread.join();
    try testing.expect(recompute_waited);
    try testing.expect(poll_done.load(.acquire));
}
