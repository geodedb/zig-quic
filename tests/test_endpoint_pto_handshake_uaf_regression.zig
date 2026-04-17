// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
// Regression test for the use-after-free in Endpoint.processExpiredTimers
// when a `PtoHandshake` timer fires after its captured *Connection has been
// freed (endpoint.zig:~1489 calls `c.setPtoExpiredHandshake()`).
//
// Pre-fix behaviour: processExpiredTimers dereferences a dangling
// `*Connection` pointer and SIGSEGVs intermittently (see
// /home/benji/src/devnw/codepros/geode/geode/docs/audit/bugfix-quic-handshake-triage.md
// secondary defect — DoS exploit surface).
//
// Post-fix behaviour: processExpiredTimers must validate the pointer against
// `self.conns` (or equivalent) before firing, and skip the callback for freed
// connections.
//
// The test builds a real Endpoint, creates a Connection, schedules a
// PtoHandshake timer that captures a pointer to it, deinit()s the Connection,
// then fires the timer deterministically via `forceExpireAllTimers()`. A
// use-after-free manifests as a segfault or ReleaseSafe panic. The test must
// NOT segfault and MUST return cleanly.
//
// Runs on Linux only — pthread / linux timer fallback. Other platforms skip.

const std = @import("std");
const builtin = @import("builtin");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const ep_mod = @import("quic_endpoint");

test "processExpiredTimers does not UAF when PtoHandshake conn was freed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    // Build a client-role Connection on the heap so we can free it
    // deterministically before the timer fires.
    const conn_ptr = try gpa.create(conn_mod.Connection);
    conn_ptr.init(
        &gpa,
        .Client,
        -1,
        conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433),
    );

    // Schedule a PtoHandshake timer on the endpoint capturing conn_ptr.
    // delay_ms = 10 — we'll force-expire below, so timing is irrelevant.
    _ = try ep.scheduleConnPto(conn_ptr, .PtoHandshake, 10);

    // Free the connection BEFORE the timer fires. This reproduces the exact
    // window the triage describes: connection torn down in a prior poll cycle,
    // Timer struct still captures the (now dangling) pointer.
    conn_ptr.deinit();
    gpa.destroy(conn_ptr);

    // Force the timer to fire. Pre-fix: this dereferences conn_ptr and
    // typically SIGSEGVs (or returns bogus memory under UBSan / ReleaseSafe
    // allocator reuse). Post-fix: this either no-ops or returns without
    // invoking the callback.
    ep.forceExpireAllTimers();

    // If we got here, no UAF occurred. The timer must have been consumed.
    try std.testing.expect(ep.timers.items.len == 0);
}

test "processExpiredTimers does not UAF when PtoInitial conn was freed" {
    // Same regression, PtoInitial variant (endpoint.zig:~1481 calls
    // c.setPtoExpiredInitial()). Any fix must cover both arms.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    const conn_ptr = try gpa.create(conn_mod.Connection);
    conn_ptr.init(
        &gpa,
        .Client,
        -1,
        conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433),
    );

    _ = try ep.scheduleConnPto(conn_ptr, .PtoInitial, 10);

    conn_ptr.deinit();
    gpa.destroy(conn_ptr);

    ep.forceExpireAllTimers();
    try std.testing.expect(ep.timers.items.len == 0);
}
