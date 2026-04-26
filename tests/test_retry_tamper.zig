const std = @import("std");
const compat = @import("compat");
const endpoint = @import("quic_endpoint");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const test_certs = @import("test_certs");

// Flip one byte in Retry payload/tag -> verifyRetry must fail and client must ignore.
test "client_ignores_tampered_retry" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    var cfg = @import("config.zig").QuicConfig{
        .alpn = &[_][]const u8{},
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
    };
    var ep = try endpoint.Endpoint.init(alloc, "127.0.0.1:4433", &cfg);
    defer ep.deinit();
    ep.cfg.enable_retry = true;
    ep.cfg.token_secret = "test-secret";
    ep.cfg.token_expiry_ms = 60000;
    ep.test_capture_enabled = true;

    ep.captureClear();

    // Create a client connection object to register client-side state (ODCID, mappings).
    var c = try ep.connectClient("127.0.0.1:1");

    // Build a minimal client Initial without token to elicit a Retry from the server path.
    const initial = ks.deriveInitialSecret(false, c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len]);
    const pair = ks.deriveClientServerInitial(initial);
    const txk = ks.deriveKeyIvHp(pair.client);
    const tx_keys: packet.InitialKeys = .{ .key = txk.key, .iv = txk.iv, .hp = txk.hp };

    var frames_buf = std.ArrayList(u8).empty;
    defer frames_buf.deinit(alloc);
    _ = (frame.Frame{ .ping = {} }).write(compat.arrayListWriter(&frames_buf, alloc)) catch {};

    const initial_pkt = try packet.encodeInitialProtected(
        alloc,
        packet.QUIC_V1,
        c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len],
        c.our_scid.bytes[0..c.our_scid.len],
        &[_]u8{}, // no token
        1,
        4,
        frames_buf.items,
        tx_keys,
    );
    defer alloc.free(initial_pkt);

    // Inject into endpoint (server receives Initial and sends Retry)
    ep.testInject(c.peer, initial_pkt);

    // Pop Retry
    try std.testing.expect(ep.captureLen() > 0);
    const cap_opt = ep.capturePop();
    try std.testing.expect(cap_opt != null);
    const cap = cap_opt.?;
    defer alloc.free(cap.bytes);

    const odcid = c.peer_initial_dcid.bytes[0..c.peer_initial_dcid.len];
    try std.testing.expect(packet.verifyRetry(odcid, cap.bytes));

    // Tamper: flip last byte of the integrity tag
    var tampered = try alloc.alloc(u8, cap.bytes.len);
    defer alloc.free(tampered);
    @memcpy(tampered, cap.bytes);
    tampered[tampered.len - 1] ^= 0x01;

    // Sanity: verification should now fail
    try std.testing.expect(!packet.verifyRetry(odcid, tampered));

    // Clear capture ring to observe only client reaction
    ep.captureClear();

    // Inject tampered Retry from the server peer to the endpoint (client side code path)
    ep.testInject(c.peer, tampered);

    // Expect: client ignored it (no new Initial sent, no token stored)
    try std.testing.expectEqual(@as(usize, 0), ep.captureLen());
    try std.testing.expectEqual(@as(usize, 0), c.initial_token.items.len);
}
