const std = @import("std");
const quic = @import("quic_conn");

// Test enforcement of active_connection_id_limit using issued_cids counter helpers.

test "active_connection_id_limit_enforcement" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);
    defer conn.deinit();

    // Default limit 2, issued_cids starts at 1 (initial SCID)
    try std.testing.expect(conn.active_connection_id_limit == 2);
    try std.testing.expect(conn.issued_cids == 1);
    try std.testing.expect(conn.canIssueNewConnectionId());
    try conn.onIssuedNewConnectionId(); // now issued_cids == 2
    try std.testing.expect(conn.issued_cids == 2);
    try std.testing.expect(!conn.canIssueNewConnectionId());
    const err = conn.onIssuedNewConnectionId();
    try std.testing.expect(err == error.ActiveConnectionIdLimitReached);
}
