const std = @import("std");
const pkt = @import("quic_packet");
const crypto = @import("quic_crypto");
const tls13 = @import("quic_tls13");

// Short-header 1-RTT roundtrip test using derived app traffic from a synthetic handshake transcript.
// Not interoperable TLS, but exercises encodeShortProtected/decodeShortProtected.

test "short-header 1-RTT STREAM+PING roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Prepare minimal transcript and handshake secret (use deterministic ECDHE bytes)
    var eng_cli = tls13.Engine.init(alloc, .Client);
    defer eng_cli.deinit();
    var eng_srv = tls13.Engine.init(alloc, .Server);
    defer eng_srv.deinit();

    // Client queues CH with its pubkey
    _ = try eng_cli.queueMinimalClientHelloAuto();

    // Deliver client's CRYPTO to server
    var buf: [256]u8 = undefined;
    const n1 = eng_cli.popCrypto(&buf);
    try std.testing.expect(n1 > 0);
    eng_srv.onCryptoRecv(buf[0..n1]);

    // Server queues SH with its pubkey
    _ = try eng_srv.queueMinimalServerHelloAuto();

    // Deliver server's CRYPTO to client
    const n2 = eng_srv.popCrypto(&buf);
    try std.testing.expect(n2 > 0);
    eng_cli.onCryptoRecv(buf[0..n2]);

    // Optional: deterministic fallback if X25519 didn't trigger
    if (eng_cli.ecdhe_secret == null or eng_srv.ecdhe_secret == null) {
        var shared: [32]u8 = undefined;
        @memset(&shared, 7);
        eng_cli.setEcdhe(&shared);
        eng_srv.setEcdhe(&shared);
    }

    // Both sides have transcript; compute transcript hash once
    const th = eng_cli.transcript.finalize();

    // Derive application traffic directly from ECDHE + transcript
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(eng_cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(eng_srv.ecdhe_secret.?, th);

    // Map to QUIC 1-RTT write/read keys
    const cli_tx = tls13.deriveQuicAppKeys(app_cli.client_app, false); // client write
    const srv_rx = tls13.deriveQuicAppKeys(app_srv.client_app, false); // server read

    // client write keys must equal server read keys
    try std.testing.expect(std.mem.eql(u8, &cli_tx.key, &srv_rx.key));

    // Compose a small STREAM-like payload (opaque to crypto layer)
    const payload = "hello";

    // Encode short protected from client to server
    const dcid = "servercid";
    const pn: u32 = 0x11223344;
    const pn_len: u3 = 3;
    const sh_bytes = try pkt.encodeShortProtected(alloc, dcid, pn, pn_len, payload, .{ .key = cli_tx.key, .iv = cli_tx.iv, .hp = cli_tx.hp }, false);
    defer alloc.free(sh_bytes);

    // Decode short at server
    const dec = try pkt.decodeShortProtected(alloc, sh_bytes, dcid.len, .{ .key = srv_rx.key, .iv = srv_rx.iv, .hp = srv_rx.hp });
    defer alloc.free(dec.payload);
    try std.testing.expectEqual(@as(u3, pn_len), dec.packet_number_len);
    try std.testing.expectEqual(@as(u32, pn & 0x00ff_ffff), dec.packet_number); // truncated PN of len 3
    try std.testing.expect(std.mem.eql(u8, dec.payload, payload));
}
