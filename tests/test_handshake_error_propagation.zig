const std = @import("std");
const conn_mod = @import("quic_conn");

fn fakePeer() conn_mod.SockAddr {
    return conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);
}

fn failSender(_: *anyopaque, _: *conn_mod.Connection, _: []const u8) anyerror!usize {
    return error.InjectedSendFailure;
}

test "HANDSHAKE_DONE send failure does not mark frame as sent" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Server, -1, fakePeer());
    defer conn.deinit();

    conn.peer_finished_verified = true;
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

    var sender_context: u8 = 0;
    conn.setSender(@ptrCast(&sender_context), failSender);

    try std.testing.expectError(error.InjectedSendFailure, conn.sendHandshakeDoneControl());
    try std.testing.expect(!conn.handshake_done_sent);
    try std.testing.expect(!conn.initial_keys_dropped);
}

test "malformed peer transport parameters fail before being marked applied" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Server, -1, fakePeer());
    defer conn.deinit();

    const malformed = [_]u8{0xff};

    try std.testing.expectError(error.MalformedTransportParams, conn.applyPeerTransportParameters(&malformed));
    try std.testing.expect(!conn.transport_params_applied);
    try std.testing.expect(conn.peer_transport_params_raw == null);
}
