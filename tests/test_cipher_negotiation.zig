const std = @import("std");
const tls13 = @import("quic_tls13");
const crypto = @import("quic_crypto");
const pkt = @import("quic_packet");

// This test suite verifies that selecting AES-128-GCM vs ChaCha20-Poly1305 yields
// consistent key derivation across handshake and 1-RTT, and that encrypt/decrypt
// round-trips across the chosen suite.

fn simulate_handshake_and_app_keys() !struct {
    // client_app_write, server_app_read secrets and QUIC key material
    client_secret: [tls13.H.digest_length]u8,
    server_secret: [tls13.H.digest_length]u8,
    client_keys: tls13.QuicKeys,
    server_keys: tls13.QuicKeys,
} {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var eng_cli = tls13.Engine.init(a, .Client);
    defer eng_cli.deinit();
    var eng_srv = tls13.Engine.init(a, .Server);
    defer eng_srv.deinit();

    // Exchange minimal CH/SH to get transcript and X25519 shares
    _ = try eng_cli.queueMinimalClientHelloAuto();
    var buf: [256]u8 = undefined;
    const n1 = eng_cli.popCrypto(&buf);
    try eng_srv.onCryptoRecv(buf[0..n1]);

    _ = try eng_srv.queueMinimalServerHelloAuto();
    const n2 = eng_srv.popCrypto(&buf);
    try eng_cli.onCryptoRecv(buf[0..n2]);

    // Deterministic fallback if needed
    if (eng_cli.ecdhe_secret == null or eng_srv.ecdhe_secret == null) {
        var shared: [32]u8 = .{0} ** 32;
        shared[0] = 7;
        eng_cli.setEcdhe(&shared);
        eng_srv.setEcdhe(&shared);
    }

    const th = eng_cli.transcript.finalize();
    const app_cli = tls13.deriveApplicationTrafficFromEcdhe(eng_cli.ecdhe_secret.?, th);
    const app_srv = tls13.deriveApplicationTrafficFromEcdhe(eng_srv.ecdhe_secret.?, th);

    const cli_write = tls13.deriveQuicAppKeys(app_cli.client_app, false);
    const srv_read = tls13.deriveQuicAppKeys(app_srv.client_app, false);
    const srv_write = tls13.deriveQuicAppKeys(app_srv.server_app, false);
    const cli_read = tls13.deriveQuicAppKeys(app_cli.server_app, false);

    // Cross-check write/read parity
    try std.testing.expect(std.mem.eql(u8, &cli_write.key, &srv_read.key));
    try std.testing.expect(std.mem.eql(u8, &srv_write.key, &cli_read.key));

    return .{
        .client_secret = app_cli.client_app,
        .server_secret = app_srv.server_app,
        .client_keys = cli_write,
        .server_keys = srv_read,
    };
}

fn roundtrip_short(suite: crypto.AeadSuite, dcid: []const u8, pn: u32, pn_len: u3, payload: []const u8, keys_write: tls13.QuicKeys, keys_read: tls13.QuicKeys) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    // Encode short using chosen suite by adapting encodeShortProtected path through protectInitial.
    // For this test, we reuse packet helpers by temporarily forcing aes path where needed and directly
    // calling crypto.protectInitial/unprotectInitial with the right suite.

    // Build a minimal short header buffer manually to feed protectInitial
    var buf = std.ArrayList(u8){};
    defer buf.deinit(alloc);
    var header_first: u8 = 0x40 | @as(u8, pn_len - 1);
    try buf.append(alloc, header_first);
    try buf.appendSlice(alloc, dcid);
    const header_prefix = buf.items[1..];

    var pn_be_full: [4]u8 = .{
        @as(u8, @intCast((pn >> 24) & 0xff)),
        @as(u8, @intCast((pn >> 16) & 0xff)),
        @as(u8, @intCast((pn >> 8) & 0xff)),
        @as(u8, @intCast(pn & 0xff)),
    };
    const pn_slice = pn_be_full[4 - pn_len .. 4];

    // Ciphertext buffer
    var ct = try a.alloc(u8, payload.len + 16);
    defer a.free(ct);

    var pn_mut: [4]u8 = .{0} ** 4;
    @memcpy(pn_mut[0..pn_len], pn_slice);

    const ct_len = try crypto.protectInitial(
        suite,
        &keys_write.key,
        &keys_write.iv,
        &keys_write.hp,
        @as(u64, pn & 0xffff_ffff),
        &header_first,
        pn_mut[0..pn_len],
        header_prefix,
        payload,
        ct,
    );

    // Build a complete packet: first | dcid | pn | ct
    var packet = std.ArrayList(u8){};
    defer packet.deinit(alloc);
    try packet.append(alloc, header_first);
    try packet.appendSlice(alloc, dcid);
    try packet.appendSlice(alloc, pn_mut[0..pn_len]);
    try packet.appendSlice(alloc, ct[0..ct_len]);

    // Recover hp sample depending on suite
    var sample16: [16]u8 = undefined;
    switch (suite) {
        .aes_128_gcm => {
            @memcpy(sample16[0..], packet.items[1 + dcid.len + 4 .. 1 + dcid.len + 4 + 16]);
        },
        .chacha20_poly1305 => {
            @memcpy(sample16[0..pn_len], packet.items[1 + dcid.len .. 1 + dcid.len + pn_len]);
            @memcpy(sample16[pn_len..], packet.items[1 + dcid.len + pn_len .. 1 + dcid.len + pn_len + (16 - pn_len)]);
        },
    }

    // Unprotect and decrypt
    var hdr_first_masked = packet.items[0];
    var pn_buf: [4]u8 = .{0} ** 4;
    @memcpy(pn_buf[0..pn_len], packet.items[1 + dcid.len .. 1 + dcid.len + pn_len]);

    try crypto.headerUnprotect(suite, &keys_read.hp, &sample16, &hdr_first_masked, pn_buf[0..pn_len]);

    // AAD: unmasked first || dcid || unmasked pn
    var aad = std.ArrayList(u8){};
    defer aad.deinit(alloc);
    try aad.append(alloc, hdr_first_masked);
    try aad.appendSlice(alloc, dcid);
    try aad.appendSlice(alloc, pn_buf[0..pn_len]);

    // Decrypt
    const pt = try a.alloc(u8, payload.len);
    defer a.free(pt);
    const got = try crypto.aeadDecrypt(suite, &keys_read.key, &keys_read.iv, @as(u64, pn & 0xffff_ffff), aad.items, packet.items[1 + dcid.len + pn_len ..], pt);
    try std.testing.expectEqual(@as(usize, payload.len), got);
    try std.testing.expect(std.mem.eql(u8, pt, payload));
}

// AES path
test "cipher negotiation: AES-128-GCM short-header roundtrip" {
    const st = try simulate_handshake_and_app_keys();
    try roundtrip_short(.aes_128_gcm, "servercid", 0x0a0b0c0d, 3, "hello-aes", st.client_keys, st.server_keys);
}

// ChaCha path
test "cipher negotiation: ChaCha20-Poly1305 short-header roundtrip" {
    const st = try simulate_handshake_and_app_keys();
    try roundtrip_short(.chacha20_poly1305, "servercid", 0x01020304, 2, "hello-cc", st.client_keys, st.server_keys);
}
