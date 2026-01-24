const std = @import("std");
const conn_mod = @import("quic_conn");

test "stateless reset: retire_prior_to tears down tokens during active traffic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var c = conn_mod.Connection{};
    const peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 6000);
    c.init(&A, .Client, -1, peer);
    defer c.deinit();

    // Install three tokens at sequences 0,1,2
    const tok0: [16]u8 = .{ 0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const tok1: [16]u8 = .{ 0xA1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const tok2: [16]u8 = .{ 0xA2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    c.onNewConnectionId(0, 0, tok0);
    c.onNewConnectionId(1, 0, tok1);
    c.onNewConnectionId(2, 0, tok2);

    // A packet ending with tok0 matches now.
    var pkt: [37]u8 = undefined;
    @memset(&pkt, 0x11);
    pkt[0] = 0x40;
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok0);
    try std.testing.expect(c.looksLikeStatelessReset(&pkt));

    // Peer advertises retire_prior_to = 2; tokens with index < 2 must be removed.
    const tok3: [16]u8 = .{ 0xA3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    c.onNewConnectionId(3, 2, tok3);

    // Now a packet ending with tok0 should no longer match (retired), tok1 retired too.
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok0);
    try std.testing.expect(!c.looksLikeStatelessReset(&pkt));
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok1);
    try std.testing.expect(!c.looksLikeStatelessReset(&pkt));

    // Packets ending with tok2 or tok3 must still be recognized.
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok2);
    try std.testing.expect(c.looksLikeStatelessReset(&pkt));
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok3);
    try std.testing.expect(c.looksLikeStatelessReset(&pkt));
}
