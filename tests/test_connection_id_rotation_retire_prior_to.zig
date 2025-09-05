const std = @import("std");
const quic = @import("../quic.zig");

// Test rotation logic and retire_prior_to advancement when active limit is reached.
// Scenario: limit=2 (default). Initial seq0 present. Issue seq1 (limit reached). Attempt rotating issuance:
// rotation retires seq1 and issues seq2 while advertising retire_prior_to=2 after retirement.
// Then another rotation retires seq2 and issues seq3 with retire_prior_to=3, etc.

test "cid rotation advances retire_prior_to" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();
    var prng = std.rand.DefaultPrng.init(0x1234abcd);

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4444);
    conn.init(&A, .Server, 0, peer);

    try std.testing.expect(conn.active_connection_id_limit == 2);
    try std.testing.expect(conn.retired_prior_to == 0);

    const s1 = try conn.issueNewConnectionId(&prng); // seq1
    try std.testing.expect(s1 == 1);
    try std.testing.expect(conn.retired_prior_to == 0);

    // At limit now. Rotate (should retire seq1 locally, advance retired_prior_to to 2, issue seq2)
    const s2 = try conn.issueNewConnectionIdRotating(&prng);
    try std.testing.expect(s2 == 2);
    try std.testing.expect(conn.retired_prior_to == 2);

    // Another rotation: retire seq2, advance retired_prior_to to 3, issue seq3
    const s3 = try conn.issueNewConnectionIdRotating(&prng);
    try std.testing.expect(s3 == 3);
    try std.testing.expect(conn.retired_prior_to == 3);
}
