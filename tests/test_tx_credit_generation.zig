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
