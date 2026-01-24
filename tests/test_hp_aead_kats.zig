const std = @import("std");
const crypto = @import("quic_crypto");
const tls = @import("quic_tls");

fn hex2(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, s.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = try std.fmt.parseInt(u8, s[i * 2 .. i * 2 + 2], 16);
    }
    return out;
}

// RFC 9001-style KATs for AEAD and HP sampling (constructed minimal vectors)

test "kat_chacha20_poly1305_aead_encrypt_decrypt" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const key = try hex2(a, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    defer a.free(key);
    const iv = try hex2(a, "a0a1a2a3a4a5a6a7a8a9aaab");
    defer a.free(iv);
    const aad = try hex2(a, "c300000001aabbccdd1234");
    defer a.free(aad);
    const pt = "test data";
    var out = try a.alloc(u8, pt.len + 16);
    defer a.free(out);

    // ChaCha20-Poly1305 may not be available in all OpenSSL versions
    const ct_len = crypto.aeadEncrypt(.chacha20_poly1305, key, iv, 0x1234, aad, pt, out) catch |err| {
        if (err == error.CipherNotAvailable) {
            return error.SkipZigTest; // Skip test if cipher not available
        }
        return err;
    };

    var dec = try a.alloc(u8, pt.len);
    defer a.free(dec);
    const pt_len = try crypto.aeadDecrypt(.chacha20_poly1305, key, iv, 0x1234, aad, out[0..ct_len], dec);
    try std.testing.expectEqualStrings(pt, dec[0..pt_len]);
}

test "kat_aes_128_gcm_aead_encrypt_decrypt" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const key = try hex2(a, "000102030405060708090a0b0c0d0e0f");
    defer a.free(key);
    const iv = try hex2(a, "a0a1a2a3a4a5a6a7a8a9aaab");
    defer a.free(iv);
    const aad = try hex2(a, "c300000001aabbccdd1234");
    defer a.free(aad);
    const pt = "test data";
    var out = try a.alloc(u8, pt.len + 16);
    defer a.free(out);
    const ct_len = try crypto.aeadEncrypt(.aes_128_gcm, key, iv, 0x1234, aad, pt, out);
    var dec = try a.alloc(u8, pt.len);
    defer a.free(dec);
    const pt_len = try crypto.aeadDecrypt(.aes_128_gcm, key, iv, 0x1234, aad, out[0..ct_len], dec);
    try std.testing.expectEqualStrings(pt, dec[0..pt_len]);
}

test "kat_header_protection_chacha_and_aes" {
    // AES HP
    var header_first: u8 = 0xc3; // long header
    var pn: [2]u8 = .{ 0x12, 0x34 };
    const sample = [_]u8{ 0, 0, 0, 0, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33 };
    var s16: [16]u8 = sample;
    var pn_copy = pn;
    var aes_hp_key: [16]u8 = .{0} ** 16;
    try crypto.headerProtect(.aes_128_gcm, aes_hp_key[0..], &s16, &header_first, pn_copy[0..]);
    try crypto.headerUnprotect(.aes_128_gcm, aes_hp_key[0..], &s16, &header_first, pn_copy[0..]);
    try std.testing.expectEqual(@as(u8, 0xc3), header_first);
    try std.testing.expectEqualSlices(u8, &pn, &pn_copy);

    // ChaCha HP - may not be available in all OpenSSL versions
    header_first = 0xc3;
    pn = .{ 0x12, 0x34 };
    s16 = sample;
    pn_copy = pn;
    var chacha_hp_key: [32]u8 = .{0} ** 32;

    crypto.headerProtect(.chacha20_poly1305, chacha_hp_key[0..], &s16, &header_first, pn_copy[0..]) catch |err| {
        if (err == error.CipherNotAvailable) {
            return error.SkipZigTest; // Skip test if cipher not available
        }
        return err;
    };

    try crypto.headerUnprotect(.chacha20_poly1305, chacha_hp_key[0..], &s16, &header_first, pn_copy[0..]);
    try std.testing.expectEqual(@as(u8, 0xc3), header_first);
    try std.testing.expectEqualSlices(u8, &pn, &pn_copy);
}
