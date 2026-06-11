const std = @import("std");
const quic = @import("quic_conn");

// Verify that retiring a previously issued CID frees inventory allowing another issuance within the limit.
// Sequence 0 (initial) counts toward issued_cids but is never advertised again. We issue seq 1, then retire it
// and confirm a subsequent issuance succeeds reusing capacity.

test "cid retirement frees slot for re-issuance" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);
    defer conn.deinit();

    try std.testing.expect(conn.active_connection_id_limit == 2);
    try std.testing.expect(conn.issued_cids == 1); // initial

    const seq1 = try conn.issueNewConnectionId();
    try std.testing.expect(seq1 == 1);
    try std.testing.expect(conn.issued_cids == 2);
    // Further issuance should now fail due to limit.
    const err1 = conn.issueNewConnectionId();
    try std.testing.expect(err1 == error.ActiveConnectionIdLimitReached);

    // Simulate peer RETIRE_CONNECTION_ID for sequence 1
    conn.onRetireConnectionId(1);
    // issued_cids should have decremented (back to 1)
    try std.testing.expect(conn.issued_cids == 1);

    // Now issuance should succeed again (allocating sequence 2)
    const seq2 = try conn.issueNewConnectionId();
    try std.testing.expect(seq2 == 2);
    try std.testing.expect(conn.issued_cids == 2);
}

test "cid lifecycle proactively fills supply and replaces retired cid" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);
    defer conn.deinit();

    conn.active_connection_id_limit = 4;
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;

    try std.testing.expectEqual(@as(usize, 3), try conn.ensureLocalConnectionIdSupply());
    try std.testing.expectEqual(@as(u64, 4), conn.issued_cids);
    try std.testing.expect(conn.pending_new_cid.count() != 0);

    conn.pending_new_cid = std.bit_set.IntegerBitSet(8).initEmpty();
    conn.onRetireConnectionId(1);
    try std.testing.expectEqual(@as(u64, 4), conn.issued_cids);
    try std.testing.expectEqual(@as(u64, 5), conn.next_cid_sequence);
    try std.testing.expect(conn.pending_new_cid.count() != 0);
}
