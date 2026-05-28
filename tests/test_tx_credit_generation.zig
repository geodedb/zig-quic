const std = @import("std");

const quic_conn = @import("quic_conn");

// CANARY: REQ=REQ-QUIC-HC-087; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PerConnectionTxCreditWake; STATUS=TESTED; TEST=tx_credit_generation_initializes_from_allocator_fill_bytes; OWNER=transport; UPDATED=2026-05-28
test "tx_credit_generation_initializes_from_allocator_fill_bytes" {
    var allocator = std.testing.allocator;
    var conn: quic_conn.Connection = undefined;
    @memset(std.mem.asBytes(&conn), 0xaa);

    conn.init(&allocator, .Server, -1, quic_conn.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    try std.testing.expectEqual(@as(u32, 0), conn.tx_credit_generation.load(.acquire));
}

// CANARY: REQ=REQ-QUIC-HC-087; FEATURE="QUIC High-Concurrency Requests"; ASPECT=PerConnectionTxCreditWake; STATUS=TESTED; TEST=tx_credit_generation_advances_for_handshake_space_ack_credit; OWNER=transport; UPDATED=2026-05-28
test "tx_credit_generation_advances_for_handshake_space_ack_credit" {
    var allocator = std.testing.allocator;
    var conn: quic_conn.Connection = undefined;
    conn.init(&allocator, .Server, -1, quic_conn.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    conn.onPacketSent(.Initial, 1, 1200, true);
    conn.onAckReceivedSpace(.Initial, 1, 0, &.{}, null);
    try std.testing.expectEqual(@as(u32, 1), conn.tx_credit_generation.load(.acquire));

    conn.onPacketSent(.Handshake, 1, 1200, true);
    conn.onAckReceivedSpace(.Handshake, 1, 0, &.{}, null);
    try std.testing.expectEqual(@as(u32, 2), conn.tx_credit_generation.load(.acquire));

    conn.onPacketSent(.Application, 1, 1200, true);
    conn.onAckReceivedSpace(.Application, 1, 0, &.{}, null);
    try std.testing.expectEqual(@as(u32, 3), conn.tx_credit_generation.load(.acquire));

    conn.onAckReceivedSpace(.Initial, 99, 0, &.{}, null);
    try std.testing.expectEqual(@as(u32, 3), conn.tx_credit_generation.load(.acquire));
}

fn makeReadyServerConn(allocator: *std.mem.Allocator, peer: quic_conn.SockAddr) quic_conn.Connection {
    var conn: quic_conn.Connection = undefined;
    conn.init(allocator, .Server, -1, peer);
    conn.peer_finished_verified = true;
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "PEER");
    conn.peer_initial_scid_set = true;
    conn.address_validated = true;
    return conn;
}

fn fillCongestionWindow(conn: *quic_conn.Connection) void {
    conn.rec.setInitialCongestionWindowPackets(2);
    const cc = conn.rec.getCongestionState();
    conn.onPacketSent(.Application, 99, cc.cwnd, true);
}

// CANARY: REQ=REQ-QUIC-HC-125; FEATURE="QUIC High-Concurrency Requests"; ASPECT=TrustedLocalCwndBypass; STATUS=TESTED; TEST=localhost_cwnd_exemption_allows_stream_write_when_congestion_window_is_full; OWNER=transport; UPDATED=2026-05-28
test "localhost_cwnd_exemption_allows_stream_write_when_congestion_window_is_full" {
    var allocator = std.testing.allocator;
    var conn = makeReadyServerConn(&allocator, quic_conn.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    fillCongestionWindow(&conn);
    const cc = conn.rec.getCongestionState();
    try std.testing.expect(cc.bytes_in_flight >= cc.cwnd);

    const written = try conn.writeStream(0, "ok", false);
    try std.testing.expectEqual(@as(usize, 2), written);
}

// CANARY: REQ=REQ-QUIC-HC-125; FEATURE="QUIC High-Concurrency Requests"; ASPECT=TrustedLocalCwndBypass; STATUS=TESTED; TEST=remote_peer_still_obeys_stream_congestion_window_gate; OWNER=transport; UPDATED=2026-05-28
test "remote_peer_still_obeys_stream_congestion_window_gate" {
    var allocator = std.testing.allocator;
    var conn = makeReadyServerConn(&allocator, quic_conn.SockAddr.ipv4(10, 0, 0, 1, 4433));
    defer conn.deinit();

    fillCongestionWindow(&conn);
    const cc = conn.rec.getCongestionState();
    try std.testing.expect(cc.bytes_in_flight >= cc.cwnd);

    const written = try conn.writeStream(0, "ok", false);
    try std.testing.expectEqual(@as(usize, 0), written);
}
