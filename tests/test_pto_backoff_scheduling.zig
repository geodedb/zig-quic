// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros
const std = @import("std");
const builtin = @import("builtin");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");
const recovery = @import("quic_recovery");
const Space = recovery.PacketNumberSpace;

fn nowMs() !i64 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.REALTIME, &ts) != 0) return error.ClockUnavailable;
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

fn arm(comptime space: Space, conn: *conn_mod.Connection, ep: *api.QuicEndpoint) void {
    switch (space) {
        .Initial => conn.computeAndMaybeArmPtoInitial(ep),
        .Handshake => conn.computeAndMaybeArmPtoHandshake(ep),
        .Application => conn.computeAndMaybeArmPto(ep),
    }
}

fn timerId(comptime space: Space, conn: *conn_mod.Connection) u64 {
    return switch (space) {
        .Initial => conn.pto_initial_id,
        .Handshake => conn.pto_handshake_id,
        .Application => conn.pto_app_id,
    };
}

fn expire(comptime space: Space, conn: *conn_mod.Connection) void {
    // These are the production expiry hooks. The standalone connection has
    // no traffic keys, so this changes recovery state without sending packets.
    switch (space) {
        .Initial => conn.setPtoExpiredInitial(),
        .Handshake => conn.setPtoExpiredHandshake(),
        .Application => conn.setPtoExpiredApp(),
    }
}

fn expectScheduledDelay(comptime space: Space, conn: *conn_mod.Connection, ep: *api.QuicEndpoint, expected_ms: u32) !void {
    const before = try nowMs();
    arm(space, conn, ep);
    const after = try nowMs();
    const id = timerId(space, conn);
    try std.testing.expect(id != 0);
    defer _ = ep.cancelTimer(id);
    for (ep.timers.items) |timer| {
        if (timer.id != id) continue;
        try std.testing.expect(timer.conn == conn);
        const valid = timer.deadline_ms >= before + expected_ms and timer.deadline_ms <= after + expected_ms;
        if (!valid) std.debug.print("PTO timer deadline regression: space={s} expected_ms={d} observed_ms={d}\n", .{
            @tagName(space), expected_ms, timer.deadline_ms - before,
        });
        try std.testing.expect(valid);
        // Calling the arming path again must preserve the existing timer.
        const timer_count = ep.timers.items.len;
        arm(space, conn, ep);
        try std.testing.expectEqual(id, timerId(space, conn));
        try std.testing.expectEqual(timer_count, ep.timers.items.len);
        return;
    }
    return error.MissingPtoTimer;
}

fn backoffCase(comptime space: Space) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var allocator = std.testing.allocator;
    const config = api.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.rec.rtt = .{ .smoothed_rtt_ns = 300 * std.time.ns_per_ms, .rttvar_ns = 0 };
    conn.rec.timer_granularity_ns = std.time.ns_per_ms;
    try conn.rec.onPacketSent(space, 0, 1200, true, 0);
    // Assert actual Endpoint deadlines, without sleeping or substituting a
    // scheduler. RFC 9002 section 6.2.1 requires consecutive PTOs to back off.
    for ([_]u32{ 301, 602, 1204 }, 0..) |delay, count| {
        try std.testing.expectEqual(@as(u32, @intCast(count)), conn.rec.pto_count);
        try expectScheduledDelay(space, &conn, &ep, delay);
        expire(space, &conn);
    }
}

test "Initial PTO preserves recovery backoff in the actual Endpoint timer" {
    try backoffCase(.Initial);
}

test "Handshake PTO preserves recovery backoff in the actual Endpoint timer" {
    try backoffCase(.Handshake);
}

test "Application PTO preserves recovery backoff in the actual Endpoint timer" {
    try backoffCase(.Application);
}

test "PTO timers round up fractional milliseconds and saturate the scheduler bound" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    inline for (.{ Space.Initial, Space.Handshake, Space.Application }) |space| {
        var allocator = std.testing.allocator;
        const config = api.QuicConfig{ .alpn = &.{"h3"} };
        var ep = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &config);
        defer ep.deinit();
        var conn: conn_mod.Connection = undefined;
        conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
        defer conn.deinit();
        try conn.rec.onPacketSent(space, 0, 1200, true, 0);
        conn.rec.rtt = .{ .smoothed_rtt_ns = 2 * std.time.ns_per_ms + 1, .rttvar_ns = 0 };
        conn.rec.timer_granularity_ns = 0;
        try expectScheduledDelay(space, &conn, &ep, 3);
        expire(space, &conn);
        conn.rec.pto_count = 63;
        try expectScheduledDelay(space, &conn, &ep, std.math.maxInt(u32));
    }
}

test "PTO timers remain idle without outstanding ack-eliciting packets" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var allocator = std.testing.allocator;
    const config = api.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    inline for (.{ Space.Initial, Space.Handshake, Space.Application }) |space| {
        try conn.rec.onPacketSent(space, 0, 64, false, 0);
        arm(space, &conn, &ep);
        try std.testing.expectEqual(@as(u64, 0), timerId(space, &conn));
    }
    try std.testing.expectEqual(@as(usize, 0), ep.timers.items.len);
}
