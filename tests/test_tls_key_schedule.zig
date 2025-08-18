const std = @import("std");
const ks = @import("../src/quic/tls/key_schedule.zig");

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
    // dcid = 0x8394c8f03e515708
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
    std.debug.print("PASSED tls_key_schedule_kat\n", .{});
}
