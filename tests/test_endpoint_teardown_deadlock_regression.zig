// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Regression test for the Endpoint.mu <-> poll-worker deadlock captured with
// gdb in quic v0.1.44 while the geode server ran under 0.5 CPU:
//
//   teardown thread:  holds Endpoint.mu (api.destroyBatch contract)
//                     -> Endpoint.destroyConnections
//                     -> Connection.beginEndpointDestroy waits for
//                        endpoint_rx_refs == 0            (conn.zig:1691)
//   poll worker:      holds an endpoint RX ref on the same connection
//                     (processShortHeaderDatagramConcurrent)
//                     -> maybeQueueDeferredAccepted
//                     -> waits to lock Endpoint.mu
//
// Neither side can make progress: the teardown never releases `mu` and the
// worker never drops its ref. Under CPU starvation the window between "worker
// pinned the connection" and "worker finished its post-processing" widens
// enough that geode's deferred-destroy drain lands in it routinely.
//
// The interleaving is forced with barriers, not timing:
//   1. worker pins the connection (acquireEndpointRxRef) and signals;
//   2. teardown locks Endpoint.mu, signals, then calls api.destroyBatch;
//   3. worker, after step 2, enters the real deferred-accept path, which needs
//      Endpoint.mu, and only then drops its ref.
// Pre-fix this hangs forever, so the test waits on a deadline and fails with
// error.EndpointTeardownDeadlock instead of hanging the suite. The stuck threads
// are detached and the endpoint is leaked in that case (it is still in use).
//
// Runs on Linux only, matching the other endpoint regression tests.

const std = @import("std");
const builtin = @import("builtin");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const ep_mod = @import("quic_endpoint");

const Endpoint = ep_mod.Endpoint;
const Connection = conn_mod.Connection;

const deadlock_deadline_ns: u64 = 10 * std.time.ns_per_s;

const Shared = struct {
    ep: *Endpoint,
    conn: *Connection,
    /// 1 once the worker holds its RX ref.
    worker_pinned: std.atomic.Value(u32) = .init(0),
    /// 1 once the teardown thread holds Endpoint.mu.
    teardown_locked: std.atomic.Value(u32) = .init(0),
    /// Incremented by each thread when it finishes.
    done: std.atomic.Value(u32) = .init(0),
    /// Whether the worker saw the doomed connection published to `accepted`.
    worker_saw_accepted: std.atomic.Value(bool) = .init(false),
};

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn waitFlag(flag: *std.atomic.Value(u32)) void {
    while (flag.load(.acquire) == 0) {
        io().futexWaitTimeout(u32, &flag.raw, 0, .{ .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(std.time.ns_per_ms),
            .clock = .awake,
        } }) catch {};
    }
}

fn setFlag(flag: *std.atomic.Value(u32)) void {
    flag.store(1, .release);
    io().futexWake(u32, &flag.raw, std.math.maxInt(u32));
}

fn pollWorker(s: *Shared) void {
    defer _ = s.done.fetchAdd(1, .acq_rel);
    // Step 1: pin the connection exactly like the RX paths do.
    if (!s.conn.acquireEndpointRxRef()) return;
    setFlag(&s.worker_pinned);
    // Step 3: only once teardown holds Endpoint.mu, take the real post-RX path
    // that needs Endpoint.mu while the ref is still held.
    waitFlag(&s.teardown_locked);
    ep_mod.testing_hooks.queueDeferredAccepted(s.ep, s.conn);
    // If the deferred-accept path published the doomed connection, an
    // application accept() could pop a pointer that is about to be freed.
    s.ep.mu.lockUncancelable(io());
    for (s.ep.accepted.items) |c| {
        if (c == s.conn) s.worker_saw_accepted.store(true, .release);
    }
    s.ep.mu.unlock(io());
    s.conn.releaseEndpointRxRef();
}

fn teardown(s: *Shared) void {
    defer _ = s.done.fetchAdd(1, .acq_rel);
    waitFlag(&s.worker_pinned);
    // Step 2: same locking as geode's QuicTransport.drainPendingDestroy.
    s.ep.pto_lifetime_mu.lockUncancelable(io());
    defer s.ep.pto_lifetime_mu.unlock(io());
    s.ep.mu.lockUncancelable(io());
    defer s.ep.mu.unlock(io());
    setFlag(&s.teardown_locked);
    api.destroyBatch(s.ep, &[_]*Connection{s.conn});
}

fn nowNs() i128 {
    return std.Io.Clock.awake.now(io()).nanoseconds;
}

test "destroyBatch under Endpoint.mu does not deadlock with a pinned poll worker that needs Endpoint.mu" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        // Server role + deferred accept: the configuration geode runs with, and
        // the one where the short-header RX path calls
        // maybeQueueDeferredAccepted while still holding the RX ref.
        .inline_server_cert_der = &[_]u8{0},
        .defer_accept_until_stream = true,
    };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    try std.testing.expect(ep.role == .Server);

    const conn = try gpa.create(Connection);
    conn.init(&gpa, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    try ep.conns.put(.{ .peer_hash = 7, .dcid_hash = 70 }, conn);
    try ep.conns.put(.{ .peer_hash = 7, .dcid_hash = 71 }, conn);

    var shared = Shared{ .ep = ep, .conn = conn };
    const worker = try std.Thread.spawn(.{}, pollWorker, .{&shared});
    const tear = try std.Thread.spawn(.{}, teardown, .{&shared});

    const start = nowNs();
    while (shared.done.load(.acquire) < 2) {
        if (nowNs() - start > deadlock_deadline_ns) {
            // Pre-fix: teardown is parked in beginEndpointDestroy holding
            // Endpoint.mu, the worker is parked on Endpoint.mu holding the ref.
            // Leak everything; the threads can never be joined.
            worker.detach();
            tear.detach();
            return error.EndpointTeardownDeadlock;
        }
        std.Io.sleep(io(), std.Io.Duration.fromNanoseconds(std.time.ns_per_ms), .awake) catch {};
    }
    worker.join();
    tear.join();

    // The connection is gone from every endpoint table and was never handed to
    // the accept queue while it was being torn down.
    try std.testing.expect(!shared.worker_saw_accepted.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), ep.conns.count());
    try std.testing.expectEqual(@as(usize, 0), ep.accepted.items.len);
    try std.testing.expectEqual(@as(usize, 0), ep.retired.items.len);

    api.endpointDeinit(ep);
}
