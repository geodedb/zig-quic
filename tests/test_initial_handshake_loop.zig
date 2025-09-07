const std = @import("std");
const pkt = @import("quic_packet");
const frame = @import("quic_frame");
const ks = @import("quic_tls");
const tls13 = @import("quic_tls13");

fn hex(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 1 < s.len and j < N) : ({
        i += 2;
        j += 1;
    }) {
        const hi = std.fmt.charToDigit(s[i], 16) catch 0;
        const lo = std.fmt.charToDigit(s[i + 1], 16) catch 0;
        out[j] = @as(u8, @intCast(hi * 16 + lo));
    }
    return out;
}

test "initial->handshake pipeline in-process" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Chosen DCID and Initial keys
    const dcid = hex(8, "8394c8f03e515708");
    const v2 = false;
    const initial = ks.deriveInitialSecret(v2, &dcid);
    const pair = ks.deriveClientServerInitial(initial);
    const ck = if (v2) ks.deriveKeyIvHpV2(pair.client) else ks.deriveKeyIvHp(pair.client);

    // Build a CRYPTO frame carrying minimal CH and SH envelopes (for test only)
    const ch_body = "CHLO";
    const sh_body = "SHLO";
    const ch_msg = try tls13.encodeHandshake(alloc, .client_hello, ch_body);
    defer alloc.free(ch_msg);
    const sh_msg = try tls13.encodeHandshake(alloc, .server_hello, sh_body);
    defer alloc.free(sh_msg);

    var crypto_payload = std.ArrayList(u8){};
    defer crypto_payload.deinit(alloc);
    const w = crypto_payload.writer(alloc);
    _ = try (frame.Frame{ .crypto = .{ .offset = 0, .data = ch_msg } }).write(w);
    _ = try (frame.Frame{ .crypto = .{ .offset = ch_msg.len, .data = sh_msg } }).write(w);

    // Client encodes Initial
    const initial_bytes = try pkt.encodeInitialProtected(
        alloc,
        0x00000001,
        &dcid,
        "servercid",
        &[_]u8{},
        2,
        2,
        crypto_payload.items,
        .{ .key = ck.key, .iv = ck.iv, .hp = ck.hp },
    );
    defer alloc.free(initial_bytes);

    // Server decodes Initial
    var dec = try pkt.decodeInitialProtected(alloc, initial_bytes, .{ .key = ck.key, .iv = ck.iv, .hp = ck.hp });
    defer alloc.free(dec.payload);

    // Feed CRYPTO to server TLS engine and set ecdhe_secret deterministically
    var eng = tls13.Engine.init(alloc, .Server);
    defer eng.deinit();
    eng.ecdhe_secret = &hex(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    var off: usize = 0;
    while (off < dec.payload.len) {
        const r = try frame.decodeOne(dec.payload[off..]);
        off += r.n;
        switch (r.f) {
            .crypto => |cr| eng.onCryptoRecv(cr.data),
            else => {},
        }
    }

    // Now engine has both CH and SH in transcript; compute handshake secrets
    const hs = eng.computeHandshakeSecrets() orelse return error.TestExpectedSecrets;

    // Derive server/client handshake QUIC keys
    const srv_hs = tls13.deriveQuicHandshakeKeys(hs.server, false);

    // Build a server Handshake packet carrying a CRYPTO PING payload
    var hs_frames = std.ArrayList(u8){};
    defer hs_frames.deinit(alloc);
    const w2 = hs_frames.writer(alloc);
    _ = try (frame.Frame{ .ping = {} }).write(w2);

    const hs_bytes = try pkt.encodeHandshakeProtected(
        alloc,
        0x00000001,
        dec.scid, // DCID = client's Initial SCID
        "srvcid",
        1,
        4, // use 4-byte PN to ensure HP sample availability with tiny payload
        hs_frames.items,
        .{ .key = srv_hs.key, .iv = srv_hs.iv, .hp = srv_hs.hp },
    );
    defer alloc.free(hs_bytes);

    // Client decodes server Handshake
    // Parse up to PN
    var i: usize = 0;
    try std.testing.expect((hs_bytes[0] & 0x80) != 0);
    i = 1 + 4; // first + version
    const dlen = hs_bytes[i];
    i += 1 + dlen;
    const slen = hs_bytes[i];
    i += 1 + slen;
    const len_dec = try @import("quic_varint").decode(hs_bytes[i..]);
    i += len_dec.n;
    const pn_start = i;
    if (pn_start + 4 + 16 > hs_bytes.len) return error.TestFailed;

    // Build masked header_first and pn bytes
    var header_first_masked = hs_bytes[0];
    var pn_masked: [4]u8 = .{0} ** 4;
    const pn_avail = @min(@as(usize, 4), hs_bytes.len - pn_start);
    @memcpy(pn_masked[0..pn_avail], hs_bytes[pn_start .. pn_start + pn_avail]);

    // Sample for HP (AES): PN start + 4
    var sample16: [16]u8 = undefined;
    @memcpy(sample16[0..], hs_bytes[pn_start + 4 .. pn_start + 4 + 16]);

    // Determine PN length using a temporary copy (do not mutate masked originals)
    var header_tmp = header_first_masked;
    var pn_tmp = pn_masked;
    const pn_len = try @import("quic_crypto").unmaskLongHeaderAndPn(
        .aes_128_gcm,
        &srv_hs.hp,
        &sample16,
        &header_tmp,
        &pn_tmp,
    );

    const header_prefix = hs_bytes[1..i];
    const ct = hs_bytes[pn_start + pn_len .. pn_start + @as(usize, len_dec.value)];
    if (ct.len < 16) return error.TestFailed;

    const pt = try alloc.alloc(u8, ct.len - 16);
    defer alloc.free(pt);

    // Now unprotect using masked header/pn and server handshake keys
    _ = try @import("quic_crypto").unprotectInitial(
        .aes_128_gcm,
        &srv_hs.key,
        &srv_hs.iv,
        &srv_hs.hp,
        &header_first_masked,
        pn_masked[0..pn_len],
        header_prefix,
        &sample16,
        ct,
        pt,
        0,
    );
    // Expect a PING frame (type 0x01)
    try std.testing.expect(pt.len >= 1 and pt[0] == @intFromEnum(frame.FrameType.PING));
}
