const std = @import("std");
const quic = @import("quic_conn");

// RFC 9000 §5.1.2 caps the number of active connection IDs an endpoint may
// issue before receiving RETIRE_CONNECTION_ID frames from the peer. Ensure the
// helper enforces the advertised limit.
test "issue_new_connection_id_respects_limit" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);
    defer conn.deinit();

    // Default limit =2; initial SCID counts as one issued. We can issue one more.
    const seq0 = try conn.issueNewConnectionId();
    try std.testing.expect(seq0 == 1); // second CID sequence
    // Next issuance should fail.
    const err = conn.issueNewConnectionId();
    try std.testing.expect(err == error.ActiveConnectionIdLimitReached);
}
