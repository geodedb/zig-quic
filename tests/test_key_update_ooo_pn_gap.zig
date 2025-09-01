const std = @import("std");
const endpoint = @import("quic_endpoint");
const pkt = @import("quic_packet");
const tls13 = @import("quic_tls13");

// Focused test: out-of-order key-phase across PN gaps. We trigger a key update (kp=1),
// then deliver a burst of current-phase packets to advance PN, followed by previous-phase
// packets that arrive out of order across a PN gap. Expect acceptance only within the
// rx_prev_allow window, after which further prev-phase packets are dropped and counted.
test "key update: OOO prev-phase across PN gaps accepted only within window" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    // Minimal handshake-derived secrets
    var cli = tls13.Engine.init(A, .Client);
    defer cli.deinit();
    var srv = tls13.Engine.init(A, .Server);
    defer srv.deinit();

    _ = try cli.queueMinimalClientHelloAuto();
    var tmp: [512]u8 = undefined;
    var n = cli.popCrypto(&tmp);
    srv.onCryptoRecv(tmp[0..n]);
    _ = try srv.queueMinimalServerHelloAuto();
    n = srv.popCrypto(&tmp);
    cli.onCryptoRecv(tmp[0..n]);
    if (cli.ecdhe_secret == null or srv.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 7;
        cli.setEcdhe(&shared);
        srv.setEcdhe(&shared);
    }
    const th = cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(srv.ecdhe_secret.?, th);

    var ep = try endpoint.Endpoint.init(&A, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:11");

    // Program App RX/TX keys
    const rx0 = tls13.deriveQuicAppKeys(app_srv.client_app, false);
    const tx0 = tls13.deriveQuicAppKeys(app_cli.client_app, false);
    c.app_rx_secret = app_srv.client_app;
    c.app_tx_secret = app_cli.client_app;
    c.app_rx_keys = .{ .key = rx0.key, .iv = rx0.iv, .hp = rx0.hp };
    c.app_tx_keys = .{ .key = tx0.key, .iv = tx0.iv, .hp = tx0.hp };
    c.rx_key_phase = false;
    c.tx_key_phase = false;

    const dcid = c.our_scid.bytes[0..c.our_scid.len];
    const pn_len: u3 = 2;
    const payload = "qqqqqqqqqq";

    // 1) Promote RX by sending a kp=1 packet using NEXT secret/keys
    const next_rx_secret = @import("quic_tls").updateTrafficSecret(c.app_rx_secret.?);
    const next_rx = tls13.deriveQuicAppKeys(next_rx_secret, false);
    const p_promote = try pkt.encodeShortProtected(A, dcid, 1, pn_len, payload, next_rx, true);
    defer A.free(p_promote);
    ep.testInject(c.peer, p_promote);
    try std.testing.expect(c.rx_key_phase == true);
    const prev_allow0 = c.rx_prev_allow;
    try std.testing.expect(prev_allow0 > 0);

    // 2) Send a burst of current-phase packets to advance PN significantly (gap)
    var pn: u32 = 2;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const p = try pkt.encodeShortProtected(A, dcid, pn, pn_len, payload, next_rx, true);
        defer A.free(p);
        ep.testInject(c.peer, p);
        pn += 1;
    }

    const allow_before_prev = c.rx_prev_allow;
    // 3) Deliver previous-phase packets out of order across the PN gap; accept within window
    var consumed: u32 = 0;
    var j: usize = 0;
    while (j < 4 and c.rx_prev_allow > 0) : (j += 1) {
        const pprev = try pkt.encodeShortProtected(A, dcid, pn + 10 + @as(u32, @intCast(j)), pn_len, payload, rx0, false);
        defer A.free(pprev);
        ep.testInject(c.peer, pprev);
        consumed += 1;
    }
    try std.testing.expect(c.rx_prev_allow <= allow_before_prev);

    // 4) Exhaust remaining window and observe zeroization
    while (c.rx_prev_allow > 0) {
        const pprev2 = try pkt.encodeShortProtected(A, dcid, pn + 100, pn_len, payload, rx0, false);
        defer A.free(pprev2);
        ep.testInject(c.peer, pprev2);
    }
    try std.testing.expectEqual(@as(u32, 0), c.rx_prev_allow);
    try std.testing.expect(c.rx_prev_keys == null);

    // 5) Further previous-phase packets must be dropped and counted as auth failures
    const before_fail = c.aead_rx_invalid_count;
    const pprev_extra = try pkt.encodeShortProtected(A, dcid, pn + 200, pn_len, payload, rx0, false);
    defer A.free(pprev_extra);
    ep.testInject(c.peer, pprev_extra);
    try std.testing.expect(c.aead_rx_invalid_count >= before_fail + 1);
}
