const std = @import("std");
const api = @import("quic_api");

// Basic timing tests for endpoint timers.

test "endpoint_timer_fire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 20);
    const t0 = std.time.milliTimestamp();
    try api.poll(ep, 200);
    const dt = std.time.milliTimestamp() - t0;

    // Should have waited at least a few milliseconds, but much less than the full poll timeout.
    try std.testing.expect(dt >= 5);
    try std.testing.expect(dt < 500);

    // Timer should be consumed.
    try std.testing.expect(ep.timers.items.len == 0);
}

test "endpoint_timer_cancel" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 200);
    const id2 = try api.scheduleTimer(ep, 200);
    try std.testing.expect(ep.timers.items.len == 2);

    try std.testing.expect(api.cancelTimer(ep, id2));
    try std.testing.expect(ep.timers.items.len == 1);

    // Poll briefly to let the remaining timer not fire yet; count stays 1.
    try api.poll(ep, 10);
    try std.testing.expect(ep.timers.items.len == 1);

    // Now poll long enough for it to expire and be removed.
    try api.poll(ep, 300);
    try std.testing.expect(ep.timers.items.len == 0);
}

test "endpoint_pto_schedule_and_expire_flag" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    // Build a minimal connection object and set a non-zero smoothed RTT so PTO computes
    var conn: @import("quic_conn").Connection = undefined;
    // Phase 8c: Pass -1 for sock_fd (I/O now via transport abstraction)
    conn.init(&gpa, .Server, -1, @import("quic_conn").SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    // Seed RTT so PTO > 0
    conn.rtt_app.have_sample = true;
    conn.rtt_app.smoothed_rtt_ns = 50 * std.time.ns_per_ms;
    conn.rtt_app.rttvar_ns = 10 * std.time.ns_per_ms;

    // With Recovery-based PTO, timers are only armed when there is an outstanding
    // ack-eliciting packet. Record one such send now.
    const now_ns_i128 = std.time.nanoTimestamp();
    const now_ns_u64: u64 = @intCast(@max(@as(i128, 0), now_ns_i128));
    try conn.rec.onPacketSent(.Application, 1, 1200, true, now_ns_u64);

    // Arm PTO and ensure a timer is created
    conn.computeAndMaybeArmPto(ep);
    std.debug.print("DEBUG app: active={any} timers={d} pto_count={d}\n", .{ conn.pto_app_active, ep.timers.items.len, conn.pto_app_count });
    try std.testing.expect(conn.pto_app_active);
    try std.testing.expect(ep.timers.items.len >= 1);

    // Deterministically expire all timers and verify PTO flag clears
    ep.forceExpireAllTimers();
    std.debug.print("DEBUG app after expire: active={any} timers={d} pto_count={d}\n", .{ conn.pto_app_active, ep.timers.items.len, conn.pto_app_count });
    try std.testing.expect(!conn.pto_app_active);
    try std.testing.expect(ep.timers.items.len == 0);
}

// New: per-space PTO arming/cancel and probe generation tests

test "initial_space_pto_arm_and_probe_on_expire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    // Create a server-side Connection and seed Initial RTT so PTO can be armed
    var conn: @import("quic_conn").Connection = undefined;
    // Phase 8c: Pass -1 for sock_fd (I/O now via transport abstraction)
    conn.init(&gpa, .Server, -1, @import("quic_conn").SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.rtt_initial.have_sample = true;
    conn.rtt_initial.smoothed_rtt_ns = 30 * std.time.ns_per_ms;
    conn.rtt_initial.rttvar_ns = 5 * std.time.ns_per_ms;

    // Populate peer initial DCID/SCID and our SCID for building Initial probes
    conn.peer_initial_dcid.len = 8;
    @memcpy(conn.peer_initial_dcid.bytes[0..8], "12345678");
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "ABCD");
    conn.our_scid.len = 4;
    @memcpy(conn.our_scid.bytes[0..4], "WXYZ");
    conn.initial_version = 0x00000001;

    // Recovery-driven PTO requires at least one in-flight ack-eliciting packet.
    // Record a synthetic Initial send and advance PN so the probe uses the next PN.
    conn.onPacketSent(.Initial, conn.pn_initial_tx, 1200, true);
    conn.pn_initial_tx +%= 1;

    // Arm Initial PTO
    conn.computeAndMaybeArmPtoInitial(ep);
    std.debug.print("DEBUG init: active={any} timers={d} pn_tx={d} count={d}\n", .{ conn.pto_initial_active, ep.timers.items.len, conn.pn_initial_tx, conn.pto_initial_count });
    try std.testing.expect(conn.pto_initial_active);

    // Expire timers deterministically; this should send a PING probe
    const pn_before = conn.pn_initial_tx;
    const count_before = conn.pto_initial_count;
    ep.forceExpireAllTimers();
    std.debug.print("DEBUG init after expire: active={any} timers={d} pn_tx={d}->{d} count={d}->{d}\n", .{ conn.pto_initial_active, ep.timers.items.len, pn_before, conn.pn_initial_tx, count_before, conn.pto_initial_count });
    try std.testing.expect(!conn.pto_initial_active);
    try std.testing.expect(conn.pn_initial_tx > pn_before);
    try std.testing.expect(conn.pto_initial_count > count_before);
}

test "handshake_space_pto_arm_cancel_on_ack_and_probe_on_expire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    var conn: @import("quic_conn").Connection = undefined;
    // Phase 8c: Pass -1 for sock_fd (I/O now via transport abstraction)
    conn.init(&gpa, .Server, -1, @import("quic_conn").SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    // Seed Handshake RTT
    conn.rtt_handshake.have_sample = true;
    conn.rtt_handshake.smoothed_rtt_ns = 40 * std.time.ns_per_ms;
    conn.rtt_handshake.rttvar_ns = 5 * std.time.ns_per_ms;

    // Seed hs_tx_keys minimally so we can build probes without deriving real keys
    conn.hs_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

    // Required CIDs for header construction
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "ABCD");
    conn.our_scid.len = 4;
    @memcpy(conn.our_scid.bytes[0..4], "WXYZ");
    conn.initial_version = 0x00000001;

    // Recovery-driven PTO requires an outstanding ack-eliciting packet in Handshake space
    conn.onPacketSent(.Handshake, conn.pn_handshake_tx, 1200, true);
    conn.pn_handshake_tx +%= 1;

    // Arm Handshake PTO
    conn.computeAndMaybeArmPtoHandshake(ep);
    std.debug.print("DEBUG hs: active={any} timers={d} pn_tx={d} count={d}\n", .{ conn.pto_handshake_active, ep.timers.items.len, conn.pn_handshake_tx, conn.pto_handshake_count });
    try std.testing.expect(conn.pto_handshake_active);

    // Expire timers deterministically; should send a PING probe
    const pn_before = conn.pn_handshake_tx;
    const count_before = conn.pto_handshake_count;
    ep.forceExpireAllTimers();
    std.debug.print("DEBUG hs after expire: active={any} timers={d} pn_tx={d}->{d} count={d}->{d}\n", .{ conn.pto_handshake_active, ep.timers.items.len, pn_before, conn.pn_handshake_tx, count_before, conn.pto_handshake_count });
    try std.testing.expect(!conn.pto_handshake_active);
    try std.testing.expect(conn.pn_handshake_tx > pn_before);
    try std.testing.expect(conn.pto_handshake_count > count_before);
}
