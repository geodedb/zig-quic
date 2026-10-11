const std = @import("std");
const conn_mod = @import("quic_conn");
const recovery = @import("quic_recovery");

test "SONNY-4808 discarded packet number space releases only its outstanding credit once" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    try rec.onPacketSent(.Initial, 0, 1200, true, 0);
    try rec.onPacketSent(.Initial, 1, 1000, true, 100);
    try rec.onPacketSent(.Handshake, 0, 800, true, 200);
    try rec.onPacketSent(.Application, 0, 600, true, 300);
    _ = rec.onAckReceived(.Initial, &.{1}, 0, 1000);
    const cwnd = rec.getCwnd();
    rec.pto_count = 3;
    try std.testing.expectEqual(@as(usize, 1200), rec.discardSpace(.Initial));
    try std.testing.expectEqual(@as(usize, 1400), rec.getBytesInFlight());
    try std.testing.expectEqual(@as(usize, 1400), rec.bytesInFlightSnapshot());
    try std.testing.expectEqual(cwnd, rec.getCwnd());
    try std.testing.expectEqual(@as(u32, 0), rec.pto_count);
    try std.testing.expectEqual(@as(?u64, null), rec.computeSpacePtoTimeNs(.Initial, 2000));
    try std.testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(10 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 0), rec.onAckReceived(.Initial, &.{0}, 0, 10 * std.time.ns_per_ms).bytes_acked);
    try std.testing.expectEqual(@as(usize, 0), rec.discardSpace(.Initial));
    try std.testing.expectEqual(@as(usize, 1400), rec.getBytesInFlight());
    try std.testing.expectEqual(@as(usize, 800), rec.discardSpace(.Handshake));
    try std.testing.expectEqual(@as(usize, 600), rec.getBytesInFlight());
    try std.testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Application, 0));
    try std.testing.expectEqual(cwnd, rec.getCwnd());
}

test "SONNY-4807 time loss cannot retire packets newer than the largest acknowledged packet" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    try rec.onPacketSent(.Application, 1, 1200, true, 0);
    _ = rec.onAckReceived(.Application, &.{1}, 0, std.time.ns_per_ms);
    try rec.onPacketSent(.Application, 2, 1200, true, 2 * std.time.ns_per_ms);
    const result = rec.onAckReceived(.Application, &.{1}, 0, 20 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_lost);
    try std.testing.expectEqual(@as(usize, 1200), rec.getBytesInFlight());
    try std.testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Application, 2));
}

test "SONNY-4807 PTO deadline cannot become time loss without a later packet ACK" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    rec.rtt.onAck(std.time.ns_per_ms, 0);
    try rec.onPacketSent(.Application, 0, 1200, true, 0);
    const pto = rec.computeSpacePtoTimeNs(.Application, 0).?;
    try std.testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(pto + 1));
    try std.testing.expectEqual(@as(usize, 1200), rec.getBytesInFlight());
    try std.testing.expect(rec.computeSpacePtoTimeNs(.Application, pto + 1) != null);
}

test "SONNY-4807 time loss waits for the configured timer granularity after submillisecond RTT" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    rec.timer_granularity_ns = 2 * std.time.ns_per_ms;
    rec.rtt.onAck(10_000, 0);
    try rec.onPacketSent(.Application, 1, 1200, true, 0);
    try rec.onPacketSent(.Application, 2, 1200, true, 10_000);
    const result = rec.onAckReceived(.Application, &.{2}, 0, 100_000);
    try std.testing.expectEqual(@as(usize, 1200), result.bytes_acked);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_lost);
    try std.testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(rec.timer_granularity_ns - 1));
    try std.testing.expectEqual(@as(usize, 1200), rec.onLossTimeExpired(rec.timer_granularity_ns));
    try std.testing.expectEqual(@as(usize, 0), rec.getBytesInFlight());
}

test "SONNY-4807 time loss timer retires only earlier packets in the acknowledged space" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    rec.rtt.onAck(100 * std.time.ns_per_ms, 0);
    try rec.onPacketSent(.Application, 1, 1200, true, 0);
    try rec.onPacketSent(.Application, 2, 1200, true, std.time.ns_per_ms);
    try rec.onPacketSent(.Application, 3, 1200, true, 2 * std.time.ns_per_ms);
    try rec.onPacketSent(.Handshake, 0, 1200, true, 0);
    const result = rec.onAckReceived(.Application, &.{2}, 0, 100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_lost);
    try std.testing.expectEqual(@as(usize, 1200), rec.onLossTimeExpired(200 * std.time.ns_per_ms));
    try std.testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Application, 3));
    try std.testing.expectEqual(recovery.Recovery.PacketDeliveryState.in_flight, rec.getPacketDeliveryState(.Handshake, 0));
    try std.testing.expectEqual(@as(usize, 2400), rec.getBytesInFlight());
}

test "SONNY-4807 packet zero ACK initializes RTT and protects newer packets" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    try rec.onPacketSent(.Application, 0, 1200, true, 0);
    try rec.onPacketSent(.Application, 1, 1200, true, 100_000);
    const result = rec.onAckReceived(.Application, &.{0}, 0, std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1200), result.bytes_acked);
    try std.testing.expect(rec.rtt.have_sample);
    try std.testing.expectEqual(@as(u64, std.time.ns_per_ms), rec.rtt.latest_rtt_ns);
    try std.testing.expectEqual(@as(?u64, 0), rec.spaces[@intFromEnum(recovery.PacketNumberSpace.Application)].largest_acked);
    try std.testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(100 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 1200), rec.getBytesInFlight());
}

test "SONNY-4807 parallel loss scan cannot schedule loss for newer packets" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    try rec.onPacketSent(.Application, 1, 1200, true, 0);
    _ = rec.onAckReceived(.Application, &.{1}, 0, std.time.ns_per_ms);
    for (2..1030) |pn| try rec.onPacketSent(.Application, pn, 1200, true, 2 * std.time.ns_per_ms);
    const result = rec.onAckReceived(.Application, &.{1}, 0, 2 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_lost);
    try std.testing.expectEqual(@as(?u64, null), rec.spaces[@intFromEnum(recovery.PacketNumberSpace.Application)].loss_time_ns);
    try std.testing.expectEqual(@as(usize, 0), rec.onLossTimeExpired(20 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 1028 * 1200), rec.getBytesInFlight());
}

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
    const congestion_before = rec.getCongestionState();

    const acked = [_]u64{1};
    const result = rec.onAckReceived(.Application, &acked, 0, 10_000);

    // ACK-only packets are excluded from recovery's in-flight set. An ACK
    // covering one must not manufacture congestion credit or reset backoff.
    try std.testing.expectEqual(@as(usize, 0), result.bytes_acked);
    try std.testing.expectEqual(@as(usize, 0), rec.getBytesInFlight());
    try std.testing.expectEqual(congestion_before.cwnd, rec.getCongestionState().cwnd);
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
