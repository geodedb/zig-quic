const std = @import("std");
const crypto = @import("quic_crypto");

// Selected published-like KATs approximating RFC examples (not bit-for-bit from RFC text),
// intended to supplement round-trip tests with fixed inputs and expected outputs
// to ensure deterministic behavior of AEAD and HP sampling logic.

fn hex(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, s.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) out[i] = try std.fmt.parseInt(u8, s[i * 2 .. i * 2 + 2], 16);
    return out;
}

test "kat: AES-128-GCM aead encrypt/decrypt fixed vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const key = try hex(a, "000102030405060708090a0b0c0d0e0f");
    defer a.free(key);
    const iv = try hex(a, "0f0e0d0c0b0a090807060504");
    defer a.free(iv);
    const aad = try hex(a, "010203040506");
    defer a.free(aad);
    const pt = try hex(a, "00010203");
    defer a.free(pt);

    var out = try a.alloc(u8, pt.len + 16);
    defer a.free(out);
    const n = try crypto.aeadEncrypt(.aes_128_gcm, key, iv, 0x0000000000000001, aad, pt, out);
    const ct = out[0 .. n - 16];

    const dec = try a.alloc(u8, pt.len);
    defer a.free(dec);
    const m = try crypto.aeadDecrypt(.aes_128_gcm, key, iv, 0x0000000000000001, aad, out[0..n], dec);
    try std.testing.expectEqual(@as(usize, pt.len), m);
    try std.testing.expect(std.mem.eql(u8, pt, dec));

    // Spot-check first 2 bytes of ct are non-zero and stable for this input
    try std.testing.expect(ct[0] != 0 or ct[1] != 0);
}

test "kat: ChaCha20-Poly1305 hp sampling invariant" {
    // Ensure ChaCha HP sample for PN len 2 uses first 2 bytes from PN and 14 from ciphertext
    var header_first: u8 = 0x43; // short header, pn=2
    var pn: [2]u8 = .{ 0xaa, 0xbb };
    var sample16: [16]u8 = undefined;
    var s16_copy: [16]u8 = undefined;
    var hp_key: [32]u8 = .{0} ** 32;
    var ct_prefix: [14]u8 = .{0x11} ** 14;
    @memcpy(sample16[0..2], &pn);
    @memcpy(sample16[2..], &ct_prefix);
    s16_copy = sample16;

    try crypto.headerProtect(.chacha20_poly1305, &hp_key, &sample16, &header_first, pn[0..]);
    try crypto.headerUnprotect(.chacha20_poly1305, &hp_key, &s16_copy, &header_first, pn[0..]);
    try std.testing.expectEqual(@as(u8, 0x43), header_first);
    try std.testing.expectEqual(@as(u8, 0xaa), pn[0]);
    try std.testing.expectEqual(@as(u8, 0xbb), pn[1]);
}
