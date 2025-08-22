const std = @import("std");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const tls13 = @import("quic_tls13");

// Exercise endpoint short-header RX Key Update acceptance logic:
// 1) Peer sends with next-phase keys (kp=1) -> endpoint promotes to NEXT, toggles rx_key_phase, preserves prev keys with allowance.
// 2) Subsequently accept packets with previous keys (kp=0) and observe bounded window decrement.

test "rx key update: promote on next-phase and consume prev window" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    // Minimal handshake-derived app secrets using deterministic ECDHE fallback.
    var eng_cli = tls13.Engine.init(alloc, .Client);
    defer eng_cli.deinit();
    var eng_srv = tls13.Engine.init(alloc, .Server);
    defer eng_srv.deinit();

    _ = try eng_cli.queueMinimalClientHelloAuto();
    var tmp: [512]u8 = undefined;
    const n1 = eng_cli.popCrypto(&tmp);
    eng_srv.onCryptoRecv(tmp[0..n1]);
    _ = try eng_srv.queueMinimalServerHelloAuto();
    const n2 = eng_srv.popCrypto(&tmp);
    eng_cli.onCryptoRecv(tmp[0..n2]);

    if (eng_cli.ecdhe_secret == null or eng_srv.ecdhe_secret == null) {
        var shared: [32]u8 = undefined;
        @memset(&shared, 0x11);
        eng_cli.setEcdhe(&shared);
        eng_srv.setEcdhe(&shared);
    }

    const th = eng_cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(eng_cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(eng_srv.ecdhe_secret.?, th);

    // Endpoint and a client-side connection (role doesn't matter for RX test, we program keys directly).
    var ep = try endpoint.Endpoint.init(&alloc, "127.0.0.1:0", &.{ .alpn = &[_][]const u8{} });
    defer ep.deinit();
    var c = try ep.connectClient("127.0.0.1:1");
    // NOTE: Endpoint owns connection lifecycle; no manual destroy here.

    // Program application RX/TX keys and secrets as if handshake completed (QUIC v1).
    // Client reads from server_app; writes with client_app.
    const rx0 = tls13.deriveQuicAppKeys(app_srv.client_app, false);
    const tx0 = tls13.deriveQuicAppKeys(app_cli.client_app, false);
    c.app_rx_secret = app_srv.client_app;
    c.app_tx_secret = app_cli.client_app;
    c.app_rx_keys = .{ .key = rx0.key, .iv = rx0.iv, .hp = rx0.hp };
    c.app_tx_keys = .{ .key = tx0.key, .iv = tx0.iv, .hp = tx0.hp };
    c.rx_key_phase = false;
    c.tx_key_phase = false;

    // Craft a short packet from peer using NEXT-phase keys (kp=1) to trigger promotion.
    const next_rx_secret = @import("quic_tls").updateTrafficSecret(c.app_rx_secret.?);
    const next_rx = tls13.deriveQuicAppKeys(next_rx_secret, false);

    const dcid = c.our_scid.bytes[0..c.our_scid.len];
    const payload = "abcdefghijklmnopqrst"; // ensure enough bytes for HP sample
    const pn_len: u3 = 4;

    const pkt1 = try packet.encodeShortProtected(
        alloc,
        dcid,
        1,
        pn_len,
        payload,
        .{ .key = next_rx.key, .iv = next_rx.iv, .hp = next_rx.hp },
        true, // key phase bit = 1
    );
    defer alloc.free(pkt1);

    const prev_key_before = c.app_rx_keys.?.key; // snapshot

    // Inject into endpoint RX path; should promote to NEXT.
    ep.testInject(c.peer, pkt1);

    // Validate promotion effects.
    try std.testing.expect(c.rx_key_phase == true);
    try std.testing.expect(c.app_rx_secret != null);
    try std.testing.expect(std.mem.eql(u8, &c.app_rx_secret.?, &next_rx_secret));
    try std.testing.expect(c.rx_prev_keys != null);
    try std.testing.expect(std.mem.eql(u8, &c.rx_prev_keys.?.key, &prev_key_before));
    try std.testing.expectEqual(@as(u32, 16), c.rx_prev_allow);

    // Now craft a packet using PREVIOUS keys (kp=0), which must be accepted during the window.
    const pkt_prev = try packet.encodeShortProtected(
        alloc,
        dcid,
        2,
        pn_len,
        payload,
        .{ .key = rx0.key, .iv = rx0.iv, .hp = rx0.hp },
        false, // key phase bit = 0
    );
    defer alloc.free(pkt_prev);

    ep.testInject(c.peer, pkt_prev);
    try std.testing.expectEqual(@as(u32, 15), c.rx_prev_allow);
    try std.testing.expect(c.rx_prev_keys != null);

    // Send a handful more previous-key packets and ensure allowance does not increase.
    const before = c.rx_prev_allow;
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        const pn = 3 + i;
        const pktp = try packet.encodeShortProtected(
            alloc,
            dcid,
            pn,
            pn_len,
            payload,
            .{ .key = rx0.key, .iv = rx0.iv, .hp = rx0.hp },
            false,
        );
        defer alloc.free(pktp);
        ep.testInject(c.peer, pktp);
    }
    try std.testing.expect(c.rx_prev_allow <= before);
}
