const std = @import("std");
const endpoint = @import("quic_endpoint");
const pkt = @import("quic_packet");
const tls13 = @import("quic_tls13");

test "rx key update: exhaust previous-key allowance then reject further prev-phase" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();

    // Build minimal handshake secrets
    var cli = tls13.Engine.init(A, .Client);
    defer cli.deinit();
    var srv = tls13.Engine.init(A, .Server);
    defer srv.deinit();
    _ = try cli.queueMinimalClientHelloAuto();
    var buf: [512]u8 = undefined;
    var n = cli.popCrypto(&buf);
    srv.onCryptoRecv(buf[0..n]);
    _ = try srv.queueMinimalServerHelloAuto();
    n = srv.popCrypto(&buf);
    cli.onCryptoRecv(buf[0..n]);
    if (cli.ecdhe_secret == null or srv.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 3;
        cli.setEcdhe(&shared);
        srv.setEcdhe(&shared);
    }
    const th = cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(srv.ecdhe_secret.?, th);

    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:3");
    const rx0 = tls13.deriveQuicAppKeys(app_srv.client_app, false);
    const tx0 = tls13.deriveQuicAppKeys(app_cli.client_app, false);
    c.app_rx_secret = app_srv.client_app;
    c.app_tx_secret = app_cli.client_app;
    c.app_rx_keys = .{ .key = rx0.key, .iv = rx0.iv, .hp = rx0.hp };
    c.app_tx_keys = .{ .key = tx0.key, .iv = tx0.iv, .hp = tx0.hp };
    c.rx_key_phase = false;
    c.tx_key_phase = false;

    // Promote RX by sending kp=1
    const next_rx_secret = @import("quic_tls").updateTrafficSecret(c.app_rx_secret.?);
    const next_rx = tls13.deriveQuicAppKeys(next_rx_secret, false);
    const dcid = c.our_scid.bytes[0..c.our_scid.len];
    const payload = "xxxxxxxxxxxxxxxx";
    const pkt1 = try pkt.encodeShortProtected(A, dcid, 1, 2, payload, .{ .key = next_rx.key, .iv = next_rx.iv, .hp = next_rx.hp }, true);
    defer A.free(pkt1);
    ep.testInject(c.peer, pkt1);
    try std.testing.expect(c.rx_prev_keys != null);
    const allow0 = c.rx_prev_allow;
    try std.testing.expect(allow0 > 0);

    // Consume entire allowance with previous-phase packets
    var pn: u32 = 2;
    var i: u32 = 0;
    while (i < allow0) : (i += 1) {
        const prevp = try pkt.encodeShortProtected(A, dcid, pn, 2, payload, rx0, false);
        defer A.free(prevp);
        ep.testInject(c.peer, prevp);
        pn += 1;
    }
    try std.testing.expectEqual(@as(u32, 0), c.rx_prev_allow);
    try std.testing.expect(c.rx_prev_keys == null);

    const before_fail = c.aead_rx_invalid_count;
    // One more previous-phase packet should be rejected (auth failure counted)
    const prev_extra = try pkt.encodeShortProtected(A, dcid, pn, 2, payload, rx0, false);
    defer A.free(prev_extra);
    ep.testInject(c.peer, prev_extra);
    try std.testing.expect(c.aead_rx_invalid_count >= before_fail + 1);
}

test "tx key update: rapid trigger then finalize on ACK zeroizes prev keys" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var A = gpa.allocator();
    var ep = try endpoint.Endpoint.init(A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:4");
    // Seed app secrets/keys (zeros OK for structure)
    c.app_tx_secret = .{0} ** tls13.H.digest_length;
    c.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    const start_phase = c.tx_key_phase;
    // Simulate sending enough packets to trigger TX update
    var k: usize = 0;
    while (!c.tx_update_in_progress and k < 100) : (k += 1) {
        c.onShortHeaderPacketSent(1200, true);
    }
    try std.testing.expect(c.tx_update_in_progress);
    try std.testing.expect(c.tx_prev_keys != null);
    try std.testing.expect(c.tx_key_phase != start_phase);
    const start_pn = c.tx_update_start_pn;
    // Now ACK a PN >= start to finalize
    var empty = [_]@import("quic_frame").AckRange{};
    c.onAckReceivedSpace(.Application, start_pn, 0, empty[0..0], null);
    try std.testing.expect(!c.tx_update_in_progress);
    try std.testing.expect(c.tx_prev_keys == null);
}
