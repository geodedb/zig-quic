const std = @import("std");
const quic = @import("../quic.zig");

// Verify that retiring a previously issued CID frees inventory allowing another issuance within the limit.
// Sequence 0 (initial) counts toward issued_cids but is never advertised again. We issue seq 1, then retire it
// and confirm a subsequent issuance succeeds reusing capacity.

test "cid retirement frees slot for re-issuance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var prng = std.rand.DefaultPrng.init(0xabcdef01);

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);

    try std.testing.expect(conn.active_connection_id_limit == 2);
    try std.testing.expect(conn.issued_cids == 1); // initial

    const seq1 = try conn.issueNewConnectionId(&prng);
    try std.testing.expect(seq1 == 1);
    try std.testing.expect(conn.issued_cids == 2);
    // Further issuance should now fail due to limit.
    const err1 = conn.issueNewConnectionId(&prng);
    try std.testing.expect(err1 == error.ActiveConnectionIdLimitReached);

    // Simulate peer RETIRE_CONNECTION_ID for sequence 1
    conn.onRetireConnectionId(1);
    // issued_cids should have decremented (back to 1)
    try std.testing.expect(conn.issued_cids == 1);

    // Now issuance should succeed again (allocating sequence 2)
    const seq2 = try conn.issueNewConnectionId(&prng);
    try std.testing.expect(seq2 == 2);
    try std.testing.expect(conn.issued_cids == 2);
}
