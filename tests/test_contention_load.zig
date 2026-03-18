// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Endpoint mutex contention load tests.
//
// These tests reproduce the contention pattern observed in Geode where poll()
// holds ep.mu for the entire Phase 4 (packet receive + process), blocking all
// concurrent operations like popAccepted(), scheduleTimer(), and connection map
// reads (simulating stream I/O that contends with poll).
//
// The tests measure handler-thread throughput at increasing concurrency levels
// (c=1..16) while a dedicated poll thread holds the lock. Throughput collapse
// at higher concurrency would confirm the contention bottleneck.

const std = @import("std");
const testing = std.testing;

const endpoint_mod = @import("quic_endpoint");
const conn_mod = @import("quic_conn");
const cfg = @import("quic_config");

const Endpoint = endpoint_mod.Endpoint;

const test_alpn = [_][]const u8{"h3"};

/// Duration each throughput test runs, in nanoseconds (100ms).
const test_duration_ns: u64 = 100 * std.time.ns_per_ms;

fn makeTestConfig() cfg.QuicConfig {
    return cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
        .max_connections = 0, // unlimited for load tests
    };
}

/// Pre-populate the endpoint with synthetic client connections so that poll()
/// and connection-map operations have realistic work to do under the lock.
fn preCreateConnections(ep: *Endpoint, count: usize, base_port: u16) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{@as(u16, @intCast(base_port +| @as(u16, @intCast(i))))}) catch continue;
        var addr_buf: [22]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "127.0.0.1:{s}", .{port_str}) catch continue;
        _ = ep.connectClient(addr) catch continue;
    }
}

// ---------------------------------------------------------------------------
// Result tracking
// ---------------------------------------------------------------------------

const ContentionResult = struct {
    concurrency: usize,
    handler_ops: u64,
    poll_ops: u64,
    elapsed_ns: u64,

    fn opsPerSec(self: ContentionResult) u64 {
        if (self.elapsed_ns == 0) return 0;
        return self.handler_ops * std.time.ns_per_s / self.elapsed_ns;
    }
};

// ---------------------------------------------------------------------------
// Core contention runner
// ---------------------------------------------------------------------------

fn runContentionTest(comptime num_handlers: usize) !ContentionResult {
    var config = makeTestConfig();
    var ep = try Endpoint.init(testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();

    // Pre-create connections to give poll() and map reads realistic work.
    preCreateConnections(&ep, 20, 40000 + @as(u16, num_handlers) * 1000);

    var handler_ops = std.atomic.Value(u64).init(0);
    var poll_ops = std.atomic.Value(u64).init(0);
    var stop = std.atomic.Value(bool).init(false);

    // --- Poll thread: holds ep.mu for Phase 4 receive+process ---
    const poll_thread = try std.Thread.spawn(.{}, struct {
        fn run(ep_ptr: *Endpoint, p_ops: *std.atomic.Value(u64), s: *std.atomic.Value(bool)) void {
            while (!s.load(.acquire)) {
                ep_ptr.poll(0) catch {};
                _ = p_ops.fetchAdd(1, .monotonic);
            }
        }
    }.run, .{ &ep, &poll_ops, &stop });

    // --- Handler threads: mixed operations that contend with poll ---
    var handler_threads: [num_handlers]std.Thread = undefined;
    for (&handler_threads, 0..) |*t, idx| {
        const Ctx = struct {
            ep_ptr: *Endpoint,
            ops: *std.atomic.Value(u64),
            stop_flag: *std.atomic.Value(bool),
            thread_id: usize,
        };
        const ctx = Ctx{
            .ep_ptr = &ep,
            .ops = &handler_ops,
            .stop_flag = &stop,
            .thread_id = idx,
        };
        t.* = try std.Thread.spawn(.{}, struct {
            fn run(c: Ctx) void {
                while (!c.stop_flag.load(.acquire)) {
                    // Rotate through the three operations Geode contends on:
                    switch (c.thread_id % 3) {
                        0 => {
                            // popAccepted path (accept queue contention)
                            _ = c.ep_ptr.popAccepted();
                        },
                        1 => {
                            // scheduleTimer path (timer queue contention)
                            _ = c.ep_ptr.scheduleTimer(100) catch 0;
                        },
                        2 => {
                            // Connection map read (stream I/O contention)
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

    // Run for the fixed test duration.
    var timer = try std.time.Timer.start();
    while (timer.read() < test_duration_ns) {
        std.atomic.spinLoopHint();
    }
    const elapsed = timer.read();

    // Signal all threads to stop.
    stop.store(true, .release);

    for (&handler_threads) |*t| t.join();
    poll_thread.join();

    return ContentionResult{
        .concurrency = num_handlers,
        .handler_ops = handler_ops.load(.monotonic),
        .poll_ops = poll_ops.load(.monotonic),
        .elapsed_ns = elapsed,
    };
}

// ---------------------------------------------------------------------------
// Individual concurrency-level tests
// ---------------------------------------------------------------------------

test "contention: c=1 handler vs 1 poll thread" {
    const r = try runContentionTest(1);
    // Baseline: just verify we got ops.
    try testing.expect(r.handler_ops > 0);
    try testing.expect(r.poll_ops > 0);
    std.debug.print("\n  [c=1]  handler_ops={d}  poll_ops={d}  ops/s={d}\n", .{ r.handler_ops, r.poll_ops, r.opsPerSec() });
}

test "contention: c=2 handlers vs 1 poll thread" {
    const r = try runContentionTest(2);
    try testing.expect(r.handler_ops > 0);
    try testing.expect(r.poll_ops > 0);
    std.debug.print("\n  [c=2]  handler_ops={d}  poll_ops={d}  ops/s={d}\n", .{ r.handler_ops, r.poll_ops, r.opsPerSec() });
}

test "contention: c=4 handlers vs 1 poll thread" {
    const r = try runContentionTest(4);
    try testing.expect(r.handler_ops > 0);
    try testing.expect(r.poll_ops > 0);
    std.debug.print("\n  [c=4]  handler_ops={d}  poll_ops={d}  ops/s={d}\n", .{ r.handler_ops, r.poll_ops, r.opsPerSec() });
}

test "contention: c=8 handlers vs 1 poll thread" {
    const r = try runContentionTest(8);
    try testing.expect(r.handler_ops > 0);
    try testing.expect(r.poll_ops > 0);
    std.debug.print("\n  [c=8]  handler_ops={d}  poll_ops={d}  ops/s={d}\n", .{ r.handler_ops, r.poll_ops, r.opsPerSec() });
}

test "contention: c=16 handlers vs 1 poll thread" {
    const r = try runContentionTest(16);
    try testing.expect(r.handler_ops > 0);
    try testing.expect(r.poll_ops > 0);
    std.debug.print("\n  [c=16] handler_ops={d}  poll_ops={d}  ops/s={d}\n", .{ r.handler_ops, r.poll_ops, r.opsPerSec() });
}

// ---------------------------------------------------------------------------
// Throughput scaling assertion
// ---------------------------------------------------------------------------

test "contention: throughput does not collapse at c=8 vs c=1" {
    const r1 = try runContentionTest(1);
    const r8 = try runContentionTest(8);

    const ops_c1 = r1.opsPerSec();
    const ops_c8 = r8.opsPerSec();

    std.debug.print("\n  scaling check: c=1 ops/s={d}  c=8 ops/s={d}  ratio={d}%\n", .{
        ops_c1,
        ops_c8,
        if (ops_c1 > 0) ops_c8 * 100 / ops_c1 else 0,
    });

    // c=8 should retain at least 20% of c=1 throughput.
    // Before lock splitting, c=8 poll was starved to 2-27 ops and handlers
    // dominated unfairly. With timer_mu split, both paths make progress.
    // The 20% threshold accounts for OS scheduling variance under CI load.
    try testing.expect(ops_c1 > 0);
    try testing.expect(ops_c8 > ops_c1 / 5);
}
