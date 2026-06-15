// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Regression tests for the server-side dead-connection reaper
// (endpoint/lifecycle.zig).
//
// ROOT CAUSE (k8s Raft cluster strand, iter-3): the QUIC server endpoint never
// reaped a connection whose peer silently vanished (a churned/rescheduled pod).
// `IdleTimer` (connection/idle.zig) and `closeStaleConnectionsForPeer` both
// existed but were DEAD CODE -- never wired. A dead pod's connection lingered in
// `endpoint.conns` forever (the ~12-minute `proto_reader stall idle_ms=706702`
// symptom) and, when the replacement pod reconnected from a recycled address,
// accumulated stale state blocked/starved fresh handshakes -> repeating
// `getOrCreatePeerConnection failed error=HandshakeError`.
//
// The fix adds an OPT-IN (`dead_conn_reap_ms > 0`, default 0 = off) reap sweep:
//   * idle reap: close any connection with no RX activity within the budget
//     (`shouldReapIdleConnection`), reaping a vanished peer regardless of its IP;
//   * same-peer stale close on a fresh server handshake
//     (`closeStaleConnectionsForPeer` / `samePeerConn`), giving instant recovery
//     when a churned pod reconnects from a recycled address.
//
// These tests pin the PURE decision logic (no sockets/TLS). The end-to-end churn
// recovery is exercised by geode's k8s gate (owed) -- the in-repo QUIC stub makes
// handshakes no-ops, so it cannot reproduce a real HandshakeError.

const std = @import("std");
const testing = std.testing;

const lifecycle = @import("lifecycle");
const quic_conn = @import("quic_conn");
const Connection = quic_conn.Connection;
const SockAddr = quic_conn.SockAddr;

const ns_per_ms = std.time.ns_per_ms;

test "shouldReapIdleConnection: disabled (reap_ms == 0) never reaps" {
    // Reaping is OFF by default; no connection is ever reaped however stale it
    // looks. This guarantees endpoints that do not opt in are unaffected.
    try testing.expect(!lifecycle.shouldReapIdleConnection(0, 1_000_000_000_000, 0));
    try testing.expect(!lifecycle.shouldReapIdleConnection(1, 1_000_000_000_000, 0));
}

test "shouldReapIdleConnection: never-received (last_rx_ns == 0) is not reaped" {
    // A connection that has received nothing yet (e.g. handshake in flight) is
    // not the idle reaper's responsibility -- handshake/PTO timers own that.
    try testing.expect(!lifecycle.shouldReapIdleConnection(0, 9_999_999_999, 30_000));
}

test "shouldReapIdleConnection: reaped only strictly past the budget" {
    const reap_ms: u64 = 30_000;
    const budget_ns: i128 = @as(i128, @intCast(reap_ms)) * ns_per_ms;
    const last_rx: i128 = 1_000_000_000;
    // exactly at the budget boundary -> not yet (strictly-greater required).
    try testing.expect(!lifecycle.shouldReapIdleConnection(last_rx, last_rx + budget_ns, reap_ms));
    // one nanosecond past the budget -> reap.
    try testing.expect(lifecycle.shouldReapIdleConnection(last_rx, last_rx + budget_ns + 1, reap_ms));
}

test "shouldReapIdleConnection: fresh activity is never reaped" {
    const reap_ms: u64 = 30_000;
    const last_rx: i128 = 5_000_000_000;
    // a heartbeat 1us ago keeps a healthy raft peer alive forever.
    try testing.expect(!lifecycle.shouldReapIdleConnection(last_rx, last_rx + 1_000, reap_ms));
}

test "samePeerConn: matches same peer address, distinguishes a different peer" {
    const alloc = testing.allocator;
    // samePeerConn reads only `.peer`, so a partial construction is sufficient
    // and avoids dragging TLS/stream state into a pure-logic test.
    const a = try alloc.create(Connection);
    defer alloc.destroy(a);
    const b = try alloc.create(Connection);
    defer alloc.destroy(b);
    const c = try alloc.create(Connection);
    defer alloc.destroy(c);
    a.peer = SockAddr.ipv4(10, 0, 0, 1, 4242);
    b.peer = SockAddr.ipv4(10, 0, 0, 1, 4242); // same pod address (recycled IP)
    c.peer = SockAddr.ipv4(10, 0, 0, 2, 4242); // different pod address

    try testing.expect(lifecycle.samePeerConn(a, b));
    try testing.expect(!lifecycle.samePeerConn(a, c));
    // self-match is true here; excluding self is the caller's contract.
    try testing.expect(lifecycle.samePeerConn(a, a));
}
