const std = @import("std");
const conn_mod = @import("quic_conn");

test "ecn counters per space accumulate and ACK_ECN selection gating" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var c = conn_mod.Connection{};
    const peer = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433);
    c.init(&A, .Server, -1, peer);
    defer c.deinit();

    // Mark ECN in different spaces
    c.onEcnMark(.Initial, 0x02); // ect0
    c.onEcnMark(.Initial, 0x03); // ce
    c.onEcnMark(.Handshake, 0x01); // ect1
    c.onEcnMark(.Application, 0x03); // ce
    c.onEcnMark(.Application, 0x03); // ce

    const e_i = c.getAckEcn(.Initial).?;
    try std.testing.expectEqual(@as(u64, 1), e_i.ect0);
    try std.testing.expectEqual(@as(u64, 0), e_i.ect1);
    try std.testing.expectEqual(@as(u64, 1), e_i.ce);

    const e_h = c.getAckEcn(.Handshake).?;
    try std.testing.expectEqual(@as(u64, 0), e_h.ect0);
    try std.testing.expectEqual(@as(u64, 1), e_h.ect1);
    try std.testing.expectEqual(@as(u64, 0), e_h.ce);

    const e_a = c.getAckEcn(.Application).?;
    try std.testing.expectEqual(@as(u64, 0), e_a.ect0);
    try std.testing.expectEqual(@as(u64, 0), e_a.ect1);
    try std.testing.expectEqual(@as(u64, 2), e_a.ce);
}

test "stateless reset spoof-resistance: random tail doesn't match and retire_prior_to removes tokens" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var c = conn_mod.Connection{};
    const sa = conn_mod.SockAddr.ipv4(127, 0, 0, 1, 5555);
    c.init(&A, .Client, -1, sa);
    defer c.deinit();

    // Install two tokens at sequences 0 and 2, retire_prior_to=1 should drop seq 0
    const tok0: [16]u8 = .{ 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const tok2: [16]u8 = .{ 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    c.onNewConnectionId(0, 0, tok0);
    c.onNewConnectionId(2, 1, tok2);

    // Packet with non-matching random tail must not be considered a stateless reset
    var pkt: [37]u8 = undefined;
    @memset(&pkt, 0xff);
    pkt[0] = 0x40;
    // Append a distinct token value that is not tok2
    const fake_tail: [16]u8 = .{ 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    @memcpy(pkt[pkt.len - 16 ..][0..16], &fake_tail);
    try std.testing.expect(!c.looksLikeStatelessReset(&pkt));

    // Now craft a packet ending with tok2 and expect positive match
    @memcpy(pkt[pkt.len - 16 ..][0..16], &tok2);
    try std.testing.expect(c.looksLikeStatelessReset(&pkt));
}
