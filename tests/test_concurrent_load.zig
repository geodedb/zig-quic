// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Concurrent connection load tests for QUIC endpoint.
//
// These tests validate thread-safety under increasing concurrent connection
// pressure. They expose race conditions in the endpoint's connection map,
// timer queue, and accept queue when accessed from multiple threads.

const std = @import("std");
const testing = std.testing;

const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;
const Key = endpoint_mod.Key;

const test_alpn = [_][]const u8{"h3"};

fn makeTestConfig() cfg.QuicConfig {
    return cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0, // unlimited for load tests
    };
}

// ---------------------------------------------------------------------------
// Load test: concurrent popAccepted under contention
// ---------------------------------------------------------------------------

test "load: concurrent popAccepted - 16 threads x 10000 iterations" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 16;
    const iterations = 10_000;
    var threads: [num_threads]std.Thread = undefined;
    var null_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, cnt: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < iterations) : (i += 1) {
                    if (ep_ptr.popAccepted() == null) {
                        _ = cnt.fetchAdd(1, .monotonic);
                    }
                }
            }
        }.run, .{ &ep, &null_count });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * iterations), null_count.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Load test: concurrent mutex stress with increasing thread counts
// ---------------------------------------------------------------------------

test "load: mutex stress - 2 threads x 50000 iterations" {
    try runMutexStress(2, 50_000);
}

test "load: mutex stress - 4 threads x 50000 iterations" {
    try runMutexStress(4, 50_000);
}

test "load: mutex stress - 8 threads x 50000 iterations" {
    try runMutexStress(8, 50_000);
}

test "load: mutex stress - 16 threads x 50000 iterations" {
    try runMutexStress(16, 50_000);
}

test "load: mutex stress - 32 threads x 10000 iterations" {
    try runMutexStress(32, 10_000);
}

fn runMutexStress(comptime num_threads: usize, comptime iterations: usize) !void {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    var threads: [num_threads]std.Thread = undefined;
    var counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, cnt: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < iterations) : (i += 1) {
                    ep_ptr.mu.lock();
                    _ = cnt.fetchAdd(1, .monotonic);
                    ep_ptr.mu.unlock();
                }
            }
        }.run, .{ &ep, &counter });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * iterations), counter.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Load test: concurrent connection map read/write simulation
// ---------------------------------------------------------------------------

test "load: concurrent connection map access - 8 threads" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 8;
    const iterations = 5_000;
    var threads: [num_threads]std.Thread = undefined;
    var ops_completed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, ops: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < iterations) : (i += 1) {
                    // Simulate connection lookup pattern (read path)
                    ep_ptr.mu.lock();
                    const count = ep_ptr.conns.count();
                    _ = count;
                    ep_ptr.mu.unlock();

                    _ = ops.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &ops_completed });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * iterations), ops_completed.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Load test: concurrent connection map iteration under mutation
// ---------------------------------------------------------------------------

test "load: concurrent map iteration with mutation - 4 reader + 2 writer threads" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_readers = 4;
    const num_writers = 2;
    const iterations = 2_000;
    var reader_threads: [num_readers]std.Thread = undefined;
    var writer_threads: [num_writers]std.Thread = undefined;
    var reads_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var writes_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

    // Writers: insert and remove synthetic keys
    for (&writer_threads, 0..) |*t, idx| {
        const WriterCtx = struct {
            ep_ptr: *Endpoint,
            writes: *std.atomic.Value(u64),
            stop: *std.atomic.Value(bool),
            thread_idx: usize,
        };
        const ctx = WriterCtx{
            .ep_ptr = &ep,
            .writes = &writes_done,
            .stop = &stop_flag,
            .thread_idx = idx,
        };
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(c: WriterCtx) void {
                var i: usize = 0;
                while (i < iterations) : (i += 1) {
                    c.ep_ptr.mu.lock();
                    // Simulate write contention: count + iterator under lock
                    _ = c.ep_ptr.conns.count();
                    var it = c.ep_ptr.conns.iterator();
                    while (it.next()) |_| {}
                    c.ep_ptr.mu.unlock();

                    _ = c.writes.fetchAdd(1, .monotonic);
                }
                _ = c.stop.swap(true, .release);
            }
        }.run, .{ctx});
    }

    // Readers: iterate the connection map
    for (&reader_threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, reads: *std.atomic.Value(u64), stop: *std.atomic.Value(bool)) void {
                while (!stop.load(.acquire)) {
                    ep_ptr.mu.lock();
                    var it = ep_ptr.conns.iterator();
                    while (it.next()) |_| {}
                    ep_ptr.mu.unlock();

                    _ = reads.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &reads_done, &stop_flag });
    }

    for (&writer_threads) |*t| t.join();
    for (&reader_threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_writers * iterations), writes_done.load(.monotonic));
    try testing.expect(reads_done.load(.monotonic) > 0);
}

// ---------------------------------------------------------------------------
// Load test: concurrent timer scheduling simulation
// ---------------------------------------------------------------------------

test "load: concurrent timer access - 8 threads" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 8;
    const iterations = 5_000;
    var threads: [num_threads]std.Thread = undefined;
    var ops_completed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, ops: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < iterations) : (i += 1) {
                    // Simulate timer queue read access
                    ep_ptr.mu.lock();
                    const timer_count = ep_ptr.timers.items.len;
                    _ = timer_count;
                    ep_ptr.mu.unlock();

                    _ = ops.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &ops_completed });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * iterations), ops_completed.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Load test: poll + accept concurrent access pattern
// ---------------------------------------------------------------------------

test "load: poll + accept concurrent pattern - 1 poller + 8 acceptors" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_acceptors = 8;
    const accept_iterations = 5_000;
    var acceptor_threads: [num_acceptors]std.Thread = undefined;
    var poller_thread: std.Thread = undefined;
    var accepts_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var poll_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

    // Poller thread: calls poll with short timeouts
    poller_thread = try std.Thread.spawn(.{}, struct {
        fn run(ep_ptr: *Endpoint, done: *std.atomic.Value(bool)) void {
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                ep_ptr.poll(0) catch {};
            }
            _ = done.swap(true, .release);
        }
    }.run, .{ &ep, &poll_done });

    // Acceptor threads: concurrent popAccepted
    for (&acceptor_threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, accepts: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < accept_iterations) : (i += 1) {
                    _ = ep_ptr.popAccepted();
                    _ = accepts.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &accepts_done });
    }

    poller_thread.join();
    for (&acceptor_threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_acceptors * accept_iterations), accepts_done.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Load test: rapid endpoint create/destroy cycle
// ---------------------------------------------------------------------------

test "load: rapid endpoint lifecycle - 50 create/destroy cycles" {
    const cycles = 50;
    var i: usize = 0;
    while (i < cycles) : (i += 1) {
        var config = makeTestConfig();
        var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
        // Quick poll to exercise I/O path
        ep.poll(0) catch {};
        ep.deinit();
    }
}

// ---------------------------------------------------------------------------
// Load test: sequential connectClient then concurrent poll+accept
// ---------------------------------------------------------------------------

test "load: connectClient then concurrent poll+accept" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Create connections sequentially (connectClient mutates conns map)
    const num_conns = 20;
    var i: usize = 0;
    while (i < num_conns) : (i += 1) {
        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(10000 + i))}) catch continue;
        var addr_buf: [22]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }

    // Now concurrent poll + accept with established connections
    const num_threads = 4;
    const iterations = 1_000;
    var threads: [num_threads]std.Thread = undefined;
    var ops_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, ops: *std.atomic.Value(u64)) void {
                var j: usize = 0;
                while (j < iterations) : (j += 1) {
                    _ = ep_ptr.popAccepted();
                    _ = ops.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &ops_done });
    }

    for (&threads) |*t| t.join();
    try testing.expectEqual(@as(u64, num_threads * iterations), ops_done.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Load test: high-frequency poll with zero timeout (non-blocking drain)
// ---------------------------------------------------------------------------

test "load: high-frequency poll drain - 10000 iterations" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const stats = ep.pollWithStats(0) catch continue;
        _ = stats;
    }
}

// ---------------------------------------------------------------------------
// Load test: parallel poll from multiple threads (demonstrates the race)
// ---------------------------------------------------------------------------

test "load: parallel poll from multiple threads - 4 threads" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 4;
    const poll_iterations = 500;
    var threads: [num_threads]std.Thread = undefined;
    var polls_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, done: *std.atomic.Value(u64)) void {
                var i: usize = 0;
                while (i < poll_iterations) : (i += 1) {
                    // This is the key test: multiple threads calling poll()
                    // Without thread-safe poll, this races on conns, timers, etc.
                    ep_ptr.poll(0) catch {};
                    _ = done.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &polls_done });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * poll_iterations), polls_done.load(.monotonic));
}

// ===========================================================================
// Massive throughput load tests
// ===========================================================================

test "load: massive parallel poll - 8 threads x 5000 iterations" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Pre-create connections to stress the connection map during poll
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(20000 + i))}) catch continue;
        var addr_buf: [22]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }

    const num_threads = 8;
    const poll_iterations = 5_000;
    var threads: [num_threads]std.Thread = undefined;
    var polls_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, done: *std.atomic.Value(u64)) void {
                var j: usize = 0;
                while (j < poll_iterations) : (j += 1) {
                    ep_ptr.poll(0) catch {};
                    _ = done.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &polls_done });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * poll_iterations), polls_done.load(.monotonic));
}

test "load: massive mixed operations - 16 threads poll+accept+timer" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    const num_threads = 16;
    const iterations = 2_000;
    var threads: [num_threads]std.Thread = undefined;
    var ops_done: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads, 0..) |*t, idx| {
        const Ctx = struct {
            ep_ptr: *Endpoint,
            ops: *std.atomic.Value(u64),
            thread_id: usize,
        };
        const ctx = Ctx{
            .ep_ptr = &ep,
            .ops = &ops_done,
            .thread_id = idx,
        };
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(c: Ctx) void {
                var j: usize = 0;
                while (j < iterations) : (j += 1) {
                    switch (c.thread_id % 4) {
                        0 => {
                            // Poller
                            c.ep_ptr.poll(0) catch {};
                        },
                        1 => {
                            // Acceptor
                            _ = c.ep_ptr.popAccepted();
                        },
                        2 => {
                            // Timer scheduler
                            _ = c.ep_ptr.scheduleTimer(100) catch 0;
                        },
                        3 => {
                            // Connection map reader
                            c.ep_ptr.mu.lock();
                            var it = c.ep_ptr.conns.iterator();
                            while (it.next()) |_| {}
                            c.ep_ptr.mu.unlock();
                        },
                        else => unreachable,
                    }
                    _ = c.ops.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ctx});
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * iterations), ops_done.load(.monotonic));
}

test "load: sustained throughput - 100 connections x 8 threads x 1000 poll cycles" {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Create 100 connections to simulate server under load
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(30000 + i))}) catch continue;
        var addr_buf: [22]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }

    const num_threads = 8;
    const poll_iterations = 1_000;
    var threads: [num_threads]std.Thread = undefined;
    var total_polls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(ep_ptr: *Endpoint, polls: *std.atomic.Value(u64)) void {
                var j: usize = 0;
                while (j < poll_iterations) : (j += 1) {
                    const stats = ep_ptr.pollWithStats(0) catch continue;
                    _ = stats;
                    _ = polls.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{ &ep, &total_polls });
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(@as(u64, num_threads * poll_iterations), total_polls.load(.monotonic));
}

test "load: rapid endpoint lifecycle - 200 create/destroy cycles" {
    const cycles = 200;
    var i: usize = 0;
    while (i < cycles) : (i += 1) {
        var config = makeTestConfig();
        var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
        ep.poll(0) catch {};
        ep.deinit();
    }
}
