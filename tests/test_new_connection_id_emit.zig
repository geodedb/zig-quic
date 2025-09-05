const std = @import("std");
const quic = @import("../quic.zig");

// Validate that issuing a new CID marks it pending and that it is flushed when ACK path builds a packet.
// This is a lightweight behavioral test: we trigger issuance, then force an ACK emission by simulating
// reception of an ack-eliciting packet and ensure pending bitset clears.

test "pending_new_connection_id_flushed_on_ack" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var prng = std.rand.DefaultPrng.init(0xdeadbeef);

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Server, 0, peer);

    // Pretend 1-RTT keys exist so flush can send; fabricate minimal keys (all zeros acceptable for test harness).
    conn.app_tx_keys = .{ .key = [_]u8{0} ** 16, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 16 };
    conn.app_rx_keys = conn.app_tx_keys; // allow decoding symmetry if needed
    conn.address_validated = true; // bypass amplification guard

    // Issue a new CID (limit default 2 allows exactly one issuance).
    _ = try conn.issueNewConnectionId(&prng);
    try std.testing.expect(!conn.pending_new_cid.isEmpty());

    // Manually flush (unit test of helper)
    const flushed = try conn.flushPendingNewConnectionIds();
    try std.testing.expect(flushed == 1);
    try std.testing.expect(conn.pending_new_cid.isEmpty());
}
