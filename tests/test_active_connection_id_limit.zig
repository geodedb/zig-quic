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

test "peer exceeding advertised CID limit yields ConnectionIdLimitError (NEWGAP-03)" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);
    defer conn.deinit();

    const token = [_]u8{0} ** 16;
    // The peer_cids store holds 8 entries (== our advertised
    // active_connection_id_limit). Filling all 8 with distinct active CIDs is
    // allowed; a 9th distinct active CID with no retirement must be rejected
    // with CONNECTION_ID_LIMIT_ERROR rather than evicting a live CID.
    var seq: u64 = 0;
    while (seq < 8) : (seq += 1) {
        const cid = [_]u8{ @intCast(seq), 0xAA, 0xBB, 0xCC };
        try conn.onNewConnectionId(seq, 0, &cid, token);
    }
    const overflow_cid = [_]u8{ 0xFF, 0xAA, 0xBB, 0xCC };
    const result = conn.onNewConnectionId(8, 0, &overflow_cid, token);
    try std.testing.expectError(error.ConnectionIdLimitError, result);

    // A frame that retires older CIDs makes room and must succeed.
    const fresh_cid = [_]u8{ 0x9A, 0xAA, 0xBB, 0xCC };
    try conn.onNewConnectionId(8, 8, &fresh_cid, token); // retire_prior_to=8 frees seq 0..7
}
