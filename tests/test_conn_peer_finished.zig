const std = @import("std");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");

fn makeConn(allocator: *std.mem.Allocator, role: conn_mod.Role) conn_mod.Connection {
    var conn: conn_mod.Connection = undefined;
    conn.init(allocator, role, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    conn.app_tx_keys = packet.AeadKeys{
        .key = [_]u8{0} ** 16,
        .iv = [_]u8{0} ** 12,
        .hp = [_]u8{0} ** 16,
    };
    return conn;
}

fn drivePeerFinished(conn: *conn_mod.Connection, verified: bool) !void {
    // Directly update peer finished status (Context handles this internally now)
    conn.updatePeerFinishedStatus(verified);
}

fn expectHasConfirmed(conn: *conn_mod.Connection, expected: bool) !void {
    try std.testing.expectEqual(expected, conn.peer_finished_verified);
    try std.testing.expectEqual(expected, conn.hasConfirmedAppTxKeys());
}

test "connection updates peer Finished gating via TLS callback (client role)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn = makeConn(&alloc, .Client);
    defer conn.deinit();

    try expectHasConfirmed(&conn, false);
    try drivePeerFinished(&conn, true);
    try expectHasConfirmed(&conn, true);

    // Clearing keys should drop confirmation even if TLS still marks verified.
    conn.app_tx_keys = null;
    try std.testing.expect(!conn.hasConfirmedAppTxKeys());

    // Reinstall keys and revoke Finished to verify rollback path.
    conn.app_tx_keys = packet.AeadKeys{
        .key = [_]u8{0xaa} ** 16,
        .iv = [_]u8{0xbb} ** 12,
        .hp = [_]u8{0xcc} ** 16,
    };
    try drivePeerFinished(&conn, false);
    try expectHasConfirmed(&conn, false);
}

test "connection updates peer Finished gating via TLS callback (server role)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn = makeConn(&alloc, .Server);
    defer conn.deinit();

    try expectHasConfirmed(&conn, false);
    try drivePeerFinished(&conn, true);
    try expectHasConfirmed(&conn, true);

    try drivePeerFinished(&conn, false);
    try expectHasConfirmed(&conn, false);
}
