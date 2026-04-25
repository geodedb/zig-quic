const std = @import("std");
const conn_mod = @import("quic_conn");
const recovery = @import("quic_recovery");

test "RFC 9002 section 6.2.4 PTO expiry sends application probe packet" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Client, 0, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "SRV1");
    conn.pto_app_active = true;

    const pn_before = conn.pn_app_tx;
    conn.setPtoExpiredApp();

    try std.testing.expectEqual(@as(u32, 1), conn.pto_app_count);
    try std.testing.expectEqual(pn_before + 1, conn.pn_app_tx);
    try std.testing.expect(conn.rec.getBytesInFlight() > 0);
}

test "RFC 9002 section 6.2 ACK-only packets do not reset PTO backoff" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();

    rec.pto_count = 2;
    try rec.onPacketSent(.Application, 1, 64, false, 1_000);

    const acked = [_]u64{1};
    const result = rec.onAckReceived(.Application, &acked, 0, 10_000);

    try std.testing.expectEqual(@as(usize, 64), result.bytes_acked);
    try std.testing.expectEqual(@as(u32, 2), rec.pto_count);
}

test "RFC 9002 section 6.1.1 packet number gaps trigger threshold loss" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();

    const packet_size: usize = 1200;
    try rec.onPacketSent(.Application, 1, packet_size, true, 5_000);
    try rec.onPacketSent(.Application, 2, packet_size, true, 5_000);
    try rec.onPacketSent(.Application, 3, packet_size, true, 5_000);
    try rec.onPacketSent(.Application, 4, packet_size, true, 5_000);
    try rec.onPacketSent(.Application, 5, packet_size, true, 5_000);

    const acked = [_]u64{5};
    const result = rec.onAckReceived(.Application, &acked, 0, 6_000);

    try std.testing.expectEqual(packet_size, result.bytes_acked);
    try std.testing.expectEqual(@as(usize, packet_size * 2), result.bytes_lost);
    try std.testing.expectEqual(.unknown, rec.getPacketDeliveryState(.Application, 1));
    try std.testing.expectEqual(.unknown, rec.getPacketDeliveryState(.Application, 2));
    try std.testing.expectEqual(.in_flight, rec.getPacketDeliveryState(.Application, 3));
    try std.testing.expectEqual(.in_flight, rec.getPacketDeliveryState(.Application, 4));
}

test "RFC 9002 section 13.2.1 ACK delay affects RTT samples" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Application, 1, 1200, true, 0);
    const first = [_]u64{1};
    _ = rec.onAckReceived(.Application, &first, 0, 100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), rec.rtt.latest_rtt_ns);

    try rec.onPacketSent(.Application, 2, 1200, true, 200 * std.time.ns_per_ms);
    const second = [_]u64{2};
    _ = rec.onAckReceived(.Application, &second, 50 * std.time.ns_per_ms, 350 * std.time.ns_per_ms);

    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), rec.rtt.latest_rtt_ns);
}

test "RFC 9002 section 7.8 underutilized congestion window suppresses pacing delay" {
    const cwnd: usize = 12_000;
    const rtt_ns: u64 = 100 * std.time.ns_per_ms;
    const packet_size: usize = 1200;

    try std.testing.expectEqual(@as(u64, 0), recovery.computePacingDelayNs(cwnd, cwnd / 2, rtt_ns, packet_size));
    try std.testing.expect(recovery.computePacingDelayNs(cwnd, cwnd - packet_size, rtt_ns, packet_size) > 0);
}
