const std = @import("std");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");

// End-to-end: when ECN CE is observed on an Initial, server emits ACK_ECN in Initial space.
test "initial space: ECN CE triggers ACK_ECN in server Initial ACK" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    ep.test_capture_enabled = true;
    ep.captureClear();

    var c = try ep.connectClient("127.0.0.1:4567");

    // Build a minimal client Initial (PING) protected with client Initial keys.
    const initial = ks.deriveInitialSecret(false, c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
    const pair = ks.deriveClientServerInitial(initial);
    const cli = ks.deriveKeyIvHp(pair.client);
    const srv = ks.deriveKeyIvHp(pair.server);
    var fb = std.ArrayList(u8){};
    defer fb.deinit(alloc);
    _ = (frame.Frame{ .ping = {} }).write(fb.writer(alloc)) catch {};
    const init_pkt = try packet.encodeInitialProtected(
        A,
        packet.QUIC_V1,
        c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
        c.our_scid.bytes[0..c.our_scid.len],
        &[_]u8{},
        1,
        2,
        fb.items,
        .{ .key = cli.key, .iv = cli.iv, .hp = cli.hp },
    );
    defer A.free(init_pkt);

    // Inject with ECN CE (0b11) so server records CE and emits ACK_ECN in Initial.
    ep.testInjectWithEcn(c.peer, init_pkt, 0x03);

    // Expect a captured Initial ACK from server; decode with server Initial keys and assert ACK_ECN.
    try std.testing.expect(ep.captureLen() > 0);
    const cap = ep.capturePop().?;
    defer A.free(cap.bytes);

    const dec = try packet.decodeInitialProtected(A, cap.bytes, .{ .key = srv.key, .iv = srv.iv, .hp = srv.hp });
    defer A.free(dec.payload);

    const pr = try frame.decodeOne(dec.payload);
    try std.testing.expect(std.mem.eql(u8, @tagName(pr.f), "ack"));
    const ack = pr.f.ack;
    try std.testing.expect(ack.ecn != null);
    try std.testing.expectEqual(@as(u64, 1), ack.ecn.?.ce);
    try std.testing.expectEqual(@as(u64, 0), ack.ecn.?.ect0);
    try std.testing.expectEqual(@as(u64, 0), ack.ecn.?.ect1);
}
