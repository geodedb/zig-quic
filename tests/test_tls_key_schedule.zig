const std = @import("std");
const testlog = @import("testlog");
const ks = @import("quic_tls");

fn hexToBytes(comptime N: usize, s: []const u8) ![N]u8 {
    var out: [N]u8 = undefined;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 1 < s.len and j < N) : ({
        i += 2;
        j += 1;
    }) {
        const hi = std.fmt.charToDigit(s[i], 16) catch return error.Invalid;
        const lo = std.fmt.charToDigit(s[i + 1], 16) catch return error.Invalid;
        out[j] = @as(u8, @intCast(hi * 16 + lo));
    }
    return out;
}

test "tls_key_schedule_kat" {
    // QUIC v1 KAT (RFC 9001 A.1): dcid = 0x8394c8f03e515708
    const dcid = try hexToBytes(8, "8394c8f03e515708");
    const initial = ks.deriveInitialSecretV1(&dcid);
    const initial_expected = try hexToBytes(32, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
    try std.testing.expectEqualSlices(u8, &initial_expected, &initial);

    const pair = ks.deriveClientServerInitial(initial);
    const client_expected = try hexToBytes(32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const server_expected = try hexToBytes(32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    try std.testing.expectEqualSlices(u8, &client_expected, &pair.client);
    try std.testing.expectEqualSlices(u8, &server_expected, &pair.server);

    const ck = ks.deriveKeyIvHp(pair.client);
    const sk = ks.deriveKeyIvHp(pair.server);
    const ckey = try hexToBytes(16, "1f369613dd76d5467730efcbe3b1a22d");
    const civ = try hexToBytes(12, "fa044b2f42a3fd3b46fb255c");
    const chp = try hexToBytes(16, "9f50449e04a0e810283a1e9933adedd2");
    const skey = try hexToBytes(16, "cf3a5331653c364c88f0f379b6067e37");
    const siv = try hexToBytes(12, "0ac1493ca1905853b0bba03e");
    const shp = try hexToBytes(16, "c206b8d9b9f0f37644430b490eeaa314");
    try std.testing.expectEqualSlices(u8, &ckey, &ck.key);
    try std.testing.expectEqualSlices(u8, &civ, &ck.iv);
    try std.testing.expectEqualSlices(u8, &chp, &ck.hp);
    try std.testing.expectEqualSlices(u8, &skey, &sk.key);
    try std.testing.expectEqualSlices(u8, &siv, &sk.iv);
    try std.testing.expectEqualSlices(u8, &shp, &sk.hp);

    // Acceptance marker
    testlog.print("PASSED tls_key_schedule_kat\n", .{});
}

// Additional QUIC v2 KAT from RFC 9369 A.1 using same dcid
// initial_secret: 2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba
// client_initial_secret: 14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b
// server_initial_secret: 0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1
// client key/iv/hp: 8b1a0bc121284290a29e0971b5cd045d / 91f73e2351d8fa91660e909f / 45b95e15235d6f45a6b19cbcb0294ba9
// server key/iv/hp: 82db637861d55e1d011f19ea71d5d2a7 / dd13c276499c0249d3310652 / edf6d05c83121201b436e16877593c3a

test "tls_key_schedule_kat_v2" {
    const dcid = try hexToBytes(8, "8394c8f03e515708");
    const initial = ks.deriveInitialSecretV2(&dcid);
    const initial_expected = try hexToBytes(32, "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba");
    try std.testing.expectEqualSlices(u8, &initial_expected, &initial);

    const pair = ks.deriveClientServerInitial(initial);
    const client_expected = try hexToBytes(32, "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b");
    const server_expected = try hexToBytes(32, "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1");
    try std.testing.expectEqualSlices(u8, &client_expected, &pair.client);
    try std.testing.expectEqualSlices(u8, &server_expected, &pair.server);

    const ck = ks.deriveKeyIvHpV2(pair.client);
    const sk = ks.deriveKeyIvHpV2(pair.server);
    const ckey = try hexToBytes(16, "8b1a0bc121284290a29e0971b5cd045d");
    const civ = try hexToBytes(12, "91f73e2351d8fa91660e909f");
    const chp = try hexToBytes(16, "45b95e15235d6f45a6b19cbcb0294ba9");
    const skey = try hexToBytes(16, "82db637861d55e1d011f19ea71d5d2a7");
    const siv = try hexToBytes(12, "dd13c276499c0249d3310652");
    const shp = try hexToBytes(16, "edf6d05c83121201b436e16877593c3a");
    try std.testing.expectEqualSlices(u8, &ckey, &ck.key);
    try std.testing.expectEqualSlices(u8, &civ, &ck.iv);
    try std.testing.expectEqualSlices(u8, &chp, &ck.hp);
    try std.testing.expectEqualSlices(u8, &skey, &sk.key);
    try std.testing.expectEqualSlices(u8, &siv, &sk.iv);
    try std.testing.expectEqualSlices(u8, &shp, &sk.hp);
}
