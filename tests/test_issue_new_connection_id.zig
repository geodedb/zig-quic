const std = @import("std");
const quic = @import("../quic.zig");

test "issue_new_connection_id_respects_limit" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var prng = std.rand.DefaultPrng.init(0x12345678);

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);

    // Default limit =2; initial SCID counts as one issued. We can issue one more.
    const seq0 = try conn.issueNewConnectionId(&prng);
    try std.testing.expect(seq0 == 1); // second CID sequence
    // Next issuance should fail.
    const err = conn.issueNewConnectionId(&prng);
    try std.testing.expect(err == error.ActiveConnectionIdLimitReached);
}
