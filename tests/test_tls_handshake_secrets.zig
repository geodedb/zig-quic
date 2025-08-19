const std = @import("std");
const tls13 = @import("quic_tls13");
const ks = @import("quic_tls");

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

test "tls13 handshake traffic secrets transition (deterministic input)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var eng = tls13.Engine.init(alloc, .Client);
    defer eng.deinit();

    // Deterministic toy inputs
    const ecdhe = hex(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    eng.ecdhe_secret = &ecdhe;

    // Build proper TLS Handshake envelopes for CH/SH to trip state machine
    const ch_body = "CHLO";
    const sh_body = "SHLO";
    const ch_msg = try tls13.encodeHandshake(alloc, .client_hello, ch_body);
    defer alloc.free(ch_msg);
    const sh_msg = try tls13.encodeHandshake(alloc, .server_hello, sh_body);
    defer alloc.free(sh_msg);

    eng.queueCrypto(ch_msg) catch unreachable;
    eng.onCryptoRecv(sh_msg);

    const hs = eng.computeHandshakeSecrets() orelse return error.TestExpectedSecrets;

    // Independently compute expected via transcript + deriveHandshakeTraffic
    var t = tls13.Transcript.init();
    t.update(ch_msg);
    t.update(sh_msg);
    const th = t.finalize();
    const hs2 = tls13.deriveHandshakeTraffic(&ecdhe, th);

    try std.testing.expectEqualSlices(u8, &hs2.client_hs, &hs.client);
    try std.testing.expectEqualSlices(u8, &hs2.server_hs, &hs.server);

    // Derive QUIC handshake keys and compare to direct key schedule
    const exp_client = ks.deriveKeyIvHp(hs2.client_hs);
    const k_client = tls13.deriveQuicHandshakeKeys(hs.client, false);
    try std.testing.expectEqualSlices(u8, &exp_client.key, &k_client.key);
    try std.testing.expectEqualSlices(u8, &exp_client.iv, &k_client.iv);
    try std.testing.expectEqualSlices(u8, &exp_client.hp, &k_client.hp);
}
