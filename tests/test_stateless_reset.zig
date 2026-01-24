const std = @import("std");
const conn_mod = @import("quic_conn");

test "stateless reset detection closes connection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var c = conn_mod.Connection{};
    // minimal init
    const sa = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);
    c.init(&A, .Client, -1, sa);
    defer c.deinit();

    // Install a known stateless reset token at sequence 0
    const tok: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    c.onNewConnectionId(0, 0, tok);

    // Craft a random-looking short-header packet with the token at the end
    var pkt: [37]u8 = undefined; // arbitrary length > 5 + 16
    @memset(&pkt, 0xAA);
    pkt[0] = 0x40; // short header first byte with reserved pattern
    // copy token at the end
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok);

    try std.testing.expect(c.looksLikeStatelessReset(&pkt));
}
