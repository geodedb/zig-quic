const std = @import("std");
const tls13 = @import("quic_tls13");
const crypto = @import("quic_crypto");
const pkt = @import("quic_packet");

// Key Update scaffolding: derive next app traffic secret and verify decrypt with toggled key phase.

test "key update: derive next secret and decrypt with toggled key phase" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    // Simulate handshake and app secrets
    var eng_cli = tls13.Engine.init(a, .Client);
    defer eng_cli.deinit();
    var eng_srv = tls13.Engine.init(a, .Server);
    defer eng_srv.deinit();

    _ = try eng_cli.queueMinimalClientHelloAuto();
    var buf: [256]u8 = undefined;
    const n1 = eng_cli.popCrypto(&buf);
    eng_srv.onCryptoRecv(buf[0..n1]);

    _ = try eng_srv.queueMinimalServerHelloAuto();
    const n2 = eng_srv.popCrypto(&buf);
    eng_cli.onCryptoRecv(buf[0..n2]);

    if (eng_cli.ecdhe_secret == null or eng_srv.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 9;
        eng_cli.setEcdhe(&shared);
        eng_srv.setEcdhe(&shared);
    }

    const th = eng_cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(eng_cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(eng_srv.ecdhe_secret.?, th);

    // Derive next-phase secrets/keys (client initiates update)
    const next_cli = crypto.deriveNextAppKeys(app_cli.client_app, false);
    const next_srv = crypto.deriveNextAppKeys(app_srv.client_app, false);
    const cli_w1 = next_cli.keys; // client write phase 1
    const srv_r1 = next_srv.keys; // server read phase 1

    // Encode a short packet with next keys and key phase = 1
    const dcid = "s-cid";
    var header_first: u8 = 0x40 | 0x04 | 0; // short, kp=1, pn len=1
    const pn_len: u3 = 1;
    const pn: u32 = 7;

    var header = std.ArrayList(u8){};
    defer header.deinit(alloc);
    try header.append(alloc, header_first);
    try header.appendSlice(alloc, dcid);
    const prefix = header.items[1..];

    var pn_bytes: [1]u8 = .{@as(u8, @intCast(pn))};
    const payload = "upd";

    const ct = try a.alloc(u8, payload.len + 16);
    defer a.free(ct);
    _ = try crypto.protectInitial(.aes_128_gcm, &cli_w1.key, &cli_w1.iv, &cli_w1.hp, pn, &header_first, pn_bytes[0..], prefix, payload, ct);

    // Build packet bytes (short header): first | dcid | pn | ct
    var packet = std.ArrayList(u8){};
    defer packet.deinit(alloc);
    try packet.append(alloc, header_first);
    try packet.appendSlice(alloc, dcid);
    try packet.appendSlice(alloc, &pn_bytes);
    try packet.appendSlice(alloc, ct);

    // Build HP sample for AES (PN start + 4)
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], packet.items[1 + dcid.len + 4 .. 1 + dcid.len + 4 + 16]);

    // Unprotect header and PN using next read keys
    var hdr_first_m = packet.items[0];
    var pn_buf: [4]u8 = .{0} ** 4;
    pn_buf[0] = pn_bytes[0];
    try crypto.headerUnprotect(.aes_128_gcm, &srv_r1.hp, &sample16, &hdr_first_m, pn_buf[0..pn_len]);

    // AAD and decrypt with next keys
    var aad = std.ArrayList(u8){};
    defer aad.deinit(alloc);
    try aad.append(alloc, hdr_first_m);
    try aad.appendSlice(alloc, dcid);
    try aad.appendSlice(alloc, pn_buf[0..pn_len]);

    const pt = try a.alloc(u8, payload.len);
    defer a.free(pt);
    const got = try crypto.aeadDecrypt(.aes_128_gcm, &srv_r1.key, &srv_r1.iv, pn, aad.items, packet.items[1 + dcid.len + pn_len ..], pt);
    try std.testing.expectEqual(@as(usize, payload.len), got);
    try std.testing.expect(std.mem.eql(u8, pt, payload));

    // Sanity: decode key phase bit
    const kp = crypto.decodeShortHeaderKeyPhaseAndPnLen(header_first);
    try std.testing.expect(kp.key_phase == true);
    try std.testing.expectEqual(@as(u3, 1), kp.pn_len);
}
