// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Regression test: use-after-free between the server's pending-handshake
// retry (pollWithStats Phase 4.5) and connection teardown.
//
// Phase 4.5 snapshots raw `*Connection` pointers out of `pending_hs_send_set`
// under `pending_hs_send_mu`, drops that lock, and then retries
// sendHandshakePackets on each connection without holding `Endpoint.mu` and,
// before the fix, without an endpoint RX pin. A concurrent
// api.destroy / api.destroyBatch (geode's deferred-destroy drain) only waits
// for RX pins, so it could free a snapshotted connection while the retry was
// still using it -- and a NoHandshakeKeys outcome re-inserted the freed
// pointer into `pending_hs_send_set` for the next poll.
//
// The interleaving is forced, not timed:
//   1. the test holds the connection's `endpoint_rx_serial_mu`, which the
//      retry takes first thing for each snapshotted connection;
//   2. a poll thread runs pollWithStats; Phase 4.5 snapshots the connection
//      (the set drains to zero) and parks on the serial mutex;
//   3. a teardown thread takes pto_lifetime_mu + Endpoint.mu (geode's
//      QuicTransport.drainPendingDestroy locking) and calls destroyBatch.
// Fixed: the retry pinned the connection, so destroyBatch waits until the
// retry finishes. Pre-fix: destroyBatch frees the connection while the poll
// thread is still parked on a mutex inside it. The test reports that as
// error.ConnectionFreedDuringPendingHandshakeRetry without touching the freed
// memory again (the parked poll thread is detached and the endpoint leaked).
//
// Runs on Linux only, matching the other endpoint regression tests.

const std = @import("std");
const builtin = @import("builtin");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const ep_mod = @import("quic_endpoint");

const Endpoint = ep_mod.Endpoint;
const Connection = conn_mod.Connection;

/// How long teardown must stay blocked behind the in-flight retry. Pre-fix the
/// destroy finishes in well under a millisecond.
const destroy_blocked_window_ns: u64 = 300 * std.time.ns_per_ms;
const deadline_ns: u64 = 10 * std.time.ns_per_s;

const Shared = struct {
    ep: *Endpoint,
    conn: *Connection,
    poll_done: std.atomic.Value(bool) = .init(false),
    destroy_done: std.atomic.Value(bool) = .init(false),
};

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowNs() i128 {
    return std.Io.Clock.awake.now(io()).nanoseconds;
}

fn sleepMs(ms: u64) void {
    std.Io.sleep(io(), std.Io.Duration.fromNanoseconds(ms * std.time.ns_per_ms), .awake) catch {};
}

fn pollThread(s: *Shared) void {
    _ = s.ep.pollWithStats(0) catch {};
    s.poll_done.store(true, .release);
}

fn teardownThread(s: *Shared) void {
    s.ep.pto_lifetime_mu.lockUncancelable(io());
    defer s.ep.pto_lifetime_mu.unlock(io());
    s.ep.mu.lockUncancelable(io());
    defer s.ep.mu.unlock(io());
    api.destroyBatch(s.ep, &[_]*Connection{s.conn});
    s.destroy_done.store(true, .release);
}

test "destroyBatch waits for an in-flight pending-handshake retry instead of freeing its connection" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // page_allocator: the pre-fix failure path leaks the endpoint and a thread
    // parked inside freed memory, which the testing allocator would report.
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{
        .alpn = &[_][]const u8{"h3"},
        .inline_server_cert_der = &[_]u8{0},
    };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    try std.testing.expect(ep.role == .Server);

    // A server connection whose first Handshake flight was deferred
    // (processInitial hit NoHandshakeKeys and called markPendingHandshakeSend).
    const conn = try gpa.create(Connection);
    conn.init(&gpa, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    try ep.conns.put(.{ .peer_hash = 9, .dcid_hash = 90 }, conn);
    ep.markPendingHandshakeSend(conn);
    try std.testing.expectEqual(@as(u32, 1), ep.pending_hs_send_count.load(.acquire));

    // Step 1: park the retry on the connection's RX serial mutex.
    conn.endpoint_rx_serial_mu.lockUncancelable(io());
    var serial_locked = true;
    defer if (serial_locked) conn.endpoint_rx_serial_mu.unlock(io());

    var shared = Shared{ .ep = ep, .conn = conn };

    // Step 2: Phase 4.5 takes the snapshot (the set drains to zero), then
    // blocks on the serial mutex we hold.
    const poller = try std.Thread.spawn(.{}, pollThread, .{&shared});
    const start = nowNs();
    while (ep.pending_hs_send_count.load(.acquire) != 0) {
        if (nowNs() - start > deadline_ns) {
            poller.detach();
            serial_locked = false;
            conn.endpoint_rx_serial_mu.unlock(io());
            return error.PendingHandshakeRetryNeverSnapshotted;
        }
        sleepMs(1);
    }
    // Let the poll thread reach the serial mutex (it is the next blocking
    // step after the snapshot; nothing else in between waits).
    sleepMs(20);
    try std.testing.expect(!shared.poll_done.load(.acquire));

    // Step 3: tear the connection down while the retry still holds it.
    const tear = try std.Thread.spawn(.{}, teardownThread, .{&shared});
    const destroy_start = nowNs();
    while (nowNs() - destroy_start < destroy_blocked_window_ns) {
        if (shared.destroy_done.load(.acquire)) {
            // Pre-fix: the connection was freed while the poll thread is
            // parked on a mutex inside it. Unlocking it, or letting the retry
            // continue, would touch freed memory; leak instead.
            tear.join();
            serial_locked = false;
            poller.detach();
            return error.ConnectionFreedDuringPendingHandshakeRetry;
        }
        sleepMs(1);
    }

    // Fixed: teardown is waiting for the retry's pin. Let the retry finish;
    // it releases the pin and the destroy completes.
    serial_locked = false;
    conn.endpoint_rx_serial_mu.unlock(io());
    const finish_start = nowNs();
    while (!shared.destroy_done.load(.acquire) or !shared.poll_done.load(.acquire)) {
        if (nowNs() - finish_start > deadline_ns) {
            tear.detach();
            poller.detach();
            return error.TeardownNeverCompleted;
        }
        sleepMs(1);
    }
    tear.join();
    poller.join();

    // The freed connection is not left behind in any endpoint table or in the
    // pending-handshake set (a NoHandshakeKeys retry may have re-marked it).
    ep.pending_hs_send_mu.lockUncancelable(io());
    const still_pending = ep.pending_hs_send_set.count();
    ep.pending_hs_send_mu.unlock(io());
    try std.testing.expectEqual(@as(u32, 0), still_pending);
    try std.testing.expectEqual(@as(u32, 0), ep.pending_hs_send_count.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), ep.conns.count());

    api.endpointDeinit(ep);
}
