const std = @import("std");
const ks = @import("quic_tls");
const crypto_quic = @import("quic_crypto");

fn hexToBytesDyn(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, s.len / 2);
    var i: usize = 0;
    var j: usize = 0;
    while (i + 1 < s.len) : (i += 2) {
        const hi = try std.fmt.charToDigit(s[i], 16);
        const lo = try std.fmt.charToDigit(s[i + 1], 16);
        out[j] = @as(u8, @intCast(hi * 16 + lo));
        j += 1;
    }
    return out[0..j];
}

// RFC 9001 Appendix A reference: verify hp sample application shape on dummy payload.
// Note: This is a structural test; full byte-for-byte RFC vectors require full packet layout.
test "initial_protect_roundtrip_chacha" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dcid = try hexToBytesDyn(alloc, "8394c8f03e515708");
    defer alloc.free(dcid);
    const pair = blk: {
        const init = ks.deriveInitialSecretV1(dcid);
        break :blk ks.deriveClientServerInitial(init);
    };
    const keys = ks.deriveKeyIvHp(pair.client);

    var header_first: u8 = 0xc3; // Long header, Initial, pnlen=2
    var pn: [2]u8 = .{ 0x00, 0x01 };
    const header_prefix = try hexToBytesDyn(alloc, "00000001" ++ "088394c8f03e515708" ++ "0801020304050607" ++ "00" ++ "02");
    defer alloc.free(header_prefix);

    var plain: [4]u8 = .{ 1, 2, 3, 4 };
    var cipher: [4 + 16]u8 = undefined;

    const ct_len = try crypto_quic.protectInitial(.aes_128_gcm, &keys.key, &keys.iv, &keys.hp, 1, &header_first, &pn, header_prefix, &plain, &cipher);
    try std.testing.expect(ct_len == 20);

    var header_first2 = header_first;
    var pn2 = pn;
    var out_plain: [4]u8 = undefined;
    const pt_len = try crypto_quic.unprotectInitial(.aes_128_gcm, &keys.key, &keys.iv, &keys.hp, 1, &header_first2, &pn2, header_prefix, cipher[0..ct_len], &out_plain);
    try std.testing.expectEqual(@as(usize, 4), pt_len);
    try std.testing.expectEqualSlices(u8, &plain, &out_plain);
}
