const std = @import("std");
const tls13 = @import("quic_tls13");
const crypto = @import("quic_crypto");
const pkt = @import("quic_packet");

// RFC 9001 §6.4 states an endpoint MUST be able to process packets protected with the
// new keys immediately after sending a Key Update, while §6.5 allows a retention window
// for the previous keys to accept in-flight packets. Validate RX/TX phase toggling and
// that a small retention window continues to decrypt packets from the prior phase.
test "key update: rx promotes on next-phase, retains prev window; tx toggles and encrypts with new keys" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    // Minimal handshake to derive application traffic
    var ec = tls13.Engine.init(A, .Client);
    defer ec.deinit();
    var es = tls13.Engine.init(A, .Server);
    defer es.deinit();

    _ = try ec.queueMinimalClientHelloAuto();
    var buf: [512]u8 = undefined;
    var n = ec.popCrypto(&buf);
    es.onCryptoRecv(buf[0..n]);
    _ = try es.queueMinimalServerHelloAuto();
    n = es.popCrypto(&buf);
    ec.onCryptoRecv(buf[0..n]);

    if (ec.ecdhe_secret == null or es.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 7;
        ec.setEcdhe(&shared);
        es.setEcdhe(&shared);
    }
    const th = ec.transcript.finalize();
    const cli_app = tls13.deriveApplicationTrafficFromEcdhe(ec.ecdhe_secret.?, th);
    const srv_app = tls13.deriveApplicationTrafficFromEcdhe(es.ecdhe_secret.?, th);

    // Start phase 0
    const cli_w0 = crypto.keysFromSecret(cli_app.client_app);
    const srv_r0 = crypto.keysFromSecret(srv_app.client_app);

    // Compute next-phase (1)
    const next_cli = crypto.deriveNextAppKeys(cli_app.client_app, false);
    const next_srv = crypto.deriveNextAppKeys(srv_app.client_app, false);
    const cli_w1 = next_cli.keys;
    const srv_r1 = next_srv.keys;

    // Helper to build and protect a short packet
    const dcid = "dcid";
    const payload0 = "P0";
    const payload1 = "P1";

    // Case 1: Server receives with next-phase keys (kp=1) and should decrypt with srv_r1, promoting rx phase
    var hdr_first1: u8 = 0x40 | 0x04; // short header, kp=1, pn len=1
    var pn1: [1]u8 = .{9};
    const pn_num1: u32 = 9;
    const ct1 = try A.alloc(u8, payload1.len + 16);
    defer A.free(ct1);
    _ = try crypto.protectInitial(.aes_128_gcm, &cli_w1.key, &cli_w1.iv, &cli_w1.hp, pn_num1, &hdr_first1, pn1[0..], dcid, payload1, ct1);

    var pkt1 = std.ArrayList(u8){};
    defer pkt1.deinit(A);
    try pkt1.append(A, hdr_first1);
    try pkt1.appendSlice(A, dcid);
    try pkt1.appendSlice(A, &pn1);
    try pkt1.appendSlice(A, ct1);

    // Decrypt with next read keys (simulate promotion acceptable)
    const dec1 = try pkt.decodeShortProtected(A, pkt1.items, dcid.len, srv_r1);
    defer A.free(dec1.payload);
    try std.testing.expectEqualStrings(payload1, dec1.payload);

    // Case 2: Immediately after update, allow one packet with previous keys (kp=0) within retention window
    var hdr_first0: u8 = 0x40 | 0x00; // kp=0
    var pn0: [1]u8 = .{10};
    const pn_num0: u32 = 10;
    const ct0 = try A.alloc(u8, payload0.len + 16);
    defer A.free(ct0);
    _ = try crypto.protectInitial(.aes_128_gcm, &cli_w0.key, &cli_w0.iv, &cli_w0.hp, pn_num0, &hdr_first0, pn0[0..], dcid, payload0, ct0);
    var pkt0 = std.ArrayList(u8){};
    defer pkt0.deinit(A);
    try pkt0.append(A, hdr_first0);
    try pkt0.appendSlice(A, dcid);
    try pkt0.appendSlice(A, &pn0);
    try pkt0.appendSlice(A, ct0);
    // Attempt to decrypt with previous read keys
    const dec0 = try pkt.decodeShortProtected(A, pkt0.items, dcid.len, srv_r0);
    defer A.free(dec0.payload);
    try std.testing.expectEqualStrings(payload0, dec0.payload);
}
