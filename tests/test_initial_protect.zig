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
// AES-128-GCM roundtrip through protectInitial/unprotectInitial.
test "initial_protect_roundtrip_aes" {
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
    const header_prefix_full = try hexToBytesDyn(alloc, "00000001" ++ "088394c8f03e515708" ++ "0801020304050607" ++ "00" ++ "02");
    defer alloc.free(header_prefix_full);
    // Our crypto expects header_prefix to exclude the first byte; the test vector here already excludes it.
    const header_prefix = header_prefix_full;

    var plain: [4]u8 = .{ 1, 2, 3, 4 };
    var cipher: [4 + 16]u8 = undefined;

    const ct_len = try crypto_quic.protectInitial(.aes_128_gcm, &keys.key, &keys.iv, &keys.hp, 1, &header_first, &pn, header_prefix, &plain, &cipher);
    try std.testing.expect(ct_len == 20);

    var header_first2 = header_first;
    var pn2 = pn;
    var out_plain: [4]u8 = undefined;
    var sample16: [16]u8 = undefined;
    // For AES and pn_len=2, offset = 4 - 2 = 2 into ciphertext
    @memcpy(sample16[0..], cipher[2..18]);
    const pt_len = try crypto_quic.unprotectInitial(.aes_128_gcm, &keys.key, &keys.iv, &keys.hp, &header_first2, &pn2, header_prefix, &sample16, cipher[0..ct_len], &out_plain, 0);
    try std.testing.expectEqual(@as(usize, 4), pt_len);
    try std.testing.expectEqualSlices(u8, &plain, &out_plain);
}

// ChaCha20-Poly1305 roundtrip through protectInitial/unprotectInitial.
// Uses ad-hoc keys (not TLS-derived) to validate AEAD + ChaCha HP sample construction.
// For ChaCha HP, the 16-byte sample starts at the start of the PN field on the packet
// and consists of the masked PN bytes followed by the first (16 - pn_len) bytes of ciphertext.
test "initial_protect_roundtrip_chacha" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Ad-hoc test keys (sizes per RFC 9001 for ChaCha20-Poly1305):
    var aead_key: [32]u8 = undefined; // 256-bit AEAD key
    var aead_iv: [12]u8 = undefined; // 96-bit IV
    var hp_key: [32]u8 = undefined; // 256-bit HP key
    // Deterministic bytes for reproducibility
    for (&aead_key, 0..) |*b, i| b.* = @as(u8, @intCast(i));
    for (&aead_iv, 0..) |*b, i| b.* = @as(u8, @intCast(0xa0 + i));
    for (&hp_key, 0..) |*b, i| b.* = @as(u8, @intCast(0x55 ^ i));

    var header_first: u8 = 0xc3; // Long header, Initial codepoint, pnlen=2 (bits 0..1 = 01 -> len=2)
    var pn: [2]u8 = .{ 0x12, 0x34 };
    // Dummy header prefix bytes (exclude first header byte): version/len/DCID/SCID/TL/PL… shape not strictly validated here
    var header_prefix: [8]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd };

    var plain: [8]u8 = .{ 9, 8, 7, 6, 5, 4, 3, 2 };
    var cipher: [8 + 16]u8 = undefined;

    const pn_val: u64 = (@as(u64, pn[0]) << 8) | pn[1];
    const ct_len = try crypto_quic.protectInitial(.chacha20_poly1305, &aead_key, &aead_iv, &hp_key, pn_val, &header_first, &pn, &header_prefix, &plain, &cipher);
    try std.testing.expect(ct_len == plain.len + 16);

    // Build ChaCha HP sample from RECEIVED packet view: masked PN + first (16 - pn_len) bytes of ciphertext
    var sample16: [16]u8 = undefined;
    const pn_len: usize = pn.len;
    @memcpy(sample16[0..pn_len], &pn);
    @memcpy(sample16[pn_len..], cipher[0 .. 16 - pn_len]);

    var header_first_rx = header_first;
    var pn_rx = pn;
    var out_plain: [8]u8 = undefined;
    const pt_len = try crypto_quic.unprotectInitial(.chacha20_poly1305, &aead_key, &aead_iv, &hp_key, &header_first_rx, &pn_rx, &header_prefix, &sample16, cipher[0..ct_len], &out_plain, 0);
    try std.testing.expectEqual(@as(usize, plain.len), pt_len);
    try std.testing.expectEqualSlices(u8, &plain, &out_plain);
}
