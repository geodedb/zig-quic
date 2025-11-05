/// OpenSSL bindings for QUIC crypto operations
/// This replaces Zig's std.crypto.aead with OpenSSL's proven AEAD implementations
/// for compatibility with other QUIC implementations (quic-go, quiche, etc.)
///
/// Uses standard OpenSSL 3.x EVP API (not BoringSSL-specific)
const std = @import("std");

// OpenSSL C API bindings
const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/err.h");
});

pub const AeadSuite = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn keyLen(self: AeadSuite) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_poly1305 => 32,
        };
    }

    pub fn nonceLen(_: AeadSuite) usize {
        return 12;
    }

    pub fn tagLen(_: AeadSuite) usize {
        return 16;
    }

    fn getCipher(self: AeadSuite) ?*const c.EVP_CIPHER {
        return switch (self) {
            .aes_128_gcm => c.EVP_aes_128_gcm(),
            .aes_256_gcm => c.EVP_aes_256_gcm(),
            // ChaCha20-Poly1305 support varies by OpenSSL version
            .chacha20_poly1305 => if (@hasDecl(c, "EVP_chacha20_poly1305")) c.EVP_chacha20_poly1305() else null,
        };
    }
};

/// Compute AEAD nonce: IV XOR packet_number
/// RFC 9001 §5.3: The nonce, N, is formed by combining the packet protection IV with the packet number.
fn makeNonce(nonce_out: *[12]u8, iv: *const [12]u8, packet_number: u64) void {
    // Copy IV
    @memcpy(nonce_out, iv);

    // XOR packet number (big-endian) into last 8 bytes
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
    for (0..8) |i| {
        nonce_out[4 + i] ^= pn_bytes[i];
    }
}

/// Decrypt packet payload using AEAD with OpenSSL EVP API
pub fn aeadDecrypt(
    suite: AeadSuite,
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
) !usize {
    if (ciphertext_and_tag.len < suite.tagLen()) return error.AuthenticationFailed;
    if (key.len != suite.keyLen()) return error.InvalidKeyLength;
    if (iv.len != suite.nonceLen()) return error.InvalidIvLength;

    const tag_len = suite.tagLen();
    const ct_len = ciphertext_and_tag.len - tag_len;
    const ct = ciphertext_and_tag[0..ct_len];
    const tag = ciphertext_and_tag[ct_len..];

    if (out_plaintext.len < ct_len) return error.BufferTooSmall;

    // Compute nonce
    var nonce: [12]u8 = undefined;
    makeNonce(&nonce, @ptrCast(iv[0..12]), packet_number);

    // Create cipher context
    const ctx = c.EVP_CIPHER_CTX_new();
    if (ctx == null) return error.OutOfMemory;
    defer c.EVP_CIPHER_CTX_free(ctx);

    const cipher = suite.getCipher() orelse return error.CipherNotAvailable;

    // Initialize for decryption
    if (c.EVP_DecryptInit_ex(ctx, cipher, null, key.ptr, &nonce) != 1) {
        return error.DecryptInitFailed;
    }

    // Set AAD
    var aad_len: c_int = 0;
    if (c.EVP_DecryptUpdate(ctx, null, &aad_len, aad.ptr, @intCast(aad.len)) != 1) {
        return error.AadSetFailed;
    }

    // Decrypt ciphertext
    var pt_len: c_int = 0;
    if (c.EVP_DecryptUpdate(ctx, out_plaintext.ptr, &pt_len, ct.ptr, @intCast(ct.len)) != 1) {
        return error.DecryptUpdateFailed;
    }

    // Set expected tag
    if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_GCM_SET_TAG, @intCast(tag.len), @constCast(tag.ptr)) != 1) {
        return error.TagSetFailed;
    }

    // Finalize and verify tag
    var final_len: c_int = 0;
    if (c.EVP_DecryptFinal_ex(ctx, out_plaintext.ptr + @as(usize, @intCast(pt_len)), &final_len) != 1) {
        return error.AuthenticationFailed;
    }

    return @intCast(pt_len + final_len);
}

/// Encrypt packet payload using AEAD with OpenSSL EVP API
pub fn aeadEncrypt(
    suite: AeadSuite,
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    plaintext: []const u8,
    out_ciphertext_and_tag: []u8,
) !usize {
    if (key.len != suite.keyLen()) return error.InvalidKeyLength;
    if (iv.len != suite.nonceLen()) return error.InvalidIvLength;

    const required_len = plaintext.len + suite.tagLen();
    if (out_ciphertext_and_tag.len < required_len) return error.BufferTooSmall;

    // Compute nonce
    var nonce: [12]u8 = undefined;
    makeNonce(&nonce, @ptrCast(iv[0..12]), packet_number);

    // Create cipher context
    const ctx = c.EVP_CIPHER_CTX_new();
    if (ctx == null) return error.OutOfMemory;
    defer c.EVP_CIPHER_CTX_free(ctx);

    const cipher = suite.getCipher() orelse return error.CipherNotAvailable;

    // Initialize for encryption
    if (c.EVP_EncryptInit_ex(ctx, cipher, null, key.ptr, &nonce) != 1) {
        return error.EncryptInitFailed;
    }

    // Set AAD
    var aad_len: c_int = 0;
    if (c.EVP_EncryptUpdate(ctx, null, &aad_len, aad.ptr, @intCast(aad.len)) != 1) {
        return error.AadSetFailed;
    }

    // Encrypt plaintext
    var ct_len: c_int = 0;
    if (c.EVP_EncryptUpdate(ctx, out_ciphertext_and_tag.ptr, &ct_len, plaintext.ptr, @intCast(plaintext.len)) != 1) {
        return error.EncryptUpdateFailed;
    }

    // Finalize
    var final_len: c_int = 0;
    if (c.EVP_EncryptFinal_ex(ctx, out_ciphertext_and_tag.ptr + @as(usize, @intCast(ct_len)), &final_len) != 1) {
        return error.EncryptFinalFailed;
    }

    const total_ct_len = @as(usize, @intCast(ct_len + final_len));

    // Get tag
    const tag_ptr = out_ciphertext_and_tag.ptr + total_ct_len;
    if (c.EVP_CIPHER_CTX_ctrl(ctx, c.EVP_CTRL_GCM_GET_TAG, @intCast(suite.tagLen()), tag_ptr) != 1) {
        return error.TagGetFailed;
    }

    return total_ct_len + suite.tagLen();
}

/// Header protection using AES-ECB (RFC 9001 §5.4.3)
pub fn headerProtect(hp_key: []const u8, sample: *const [16]u8, mask_out: *[5]u8) !void {
    if (hp_key.len != 16) return error.InvalidKeyLength;

    const ctx = c.EVP_CIPHER_CTX_new();
    if (ctx == null) return error.OutOfMemory;
    defer c.EVP_CIPHER_CTX_free(ctx);

    const cipher = c.EVP_aes_128_ecb();

    // Initialize for encryption (no IV for ECB)
    if (c.EVP_EncryptInit_ex(ctx, cipher, null, hp_key.ptr, null) != 1) {
        return error.EncryptInitFailed;
    }

    // Disable padding
    if (c.EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        return error.PaddingSetFailed;
    }

    // Encrypt 16-byte sample
    var out_buf: [16]u8 = undefined;
    var out_len: c_int = 0;
    if (c.EVP_EncryptUpdate(ctx, &out_buf, &out_len, sample, 16) != 1) {
        return error.EncryptUpdateFailed;
    }

    if (out_len != 16) return error.UnexpectedOutputLength;

    // Copy first 5 bytes to mask
    @memcpy(mask_out, out_buf[0..5]);
}

test "OpenSSL AEAD - encrypt/decrypt round-trip" {
    const key = [_]u8{ 0x08, 0xc9, 0xbe, 0xde, 0x96, 0xf5, 0x7d, 0xcd, 0x56, 0x48, 0x35, 0x05, 0x97, 0xfb, 0x89, 0x18 };
    const iv = [_]u8{ 0xd1, 0x66, 0x9e, 0x59, 0xe0, 0x15, 0xb9, 0x99, 0x55, 0xa6, 0xab, 0x48 };
    const aad = [_]u8{ 0x53, 0x4e, 0xcc, 0xa1, 0x6f, 0x10, 0xb7, 0x79, 0xb0, 0x2a, 0xa1, 0xeb, 0x9b };
    const plaintext = "GET /\r\n";
    const pn: u64 = 715254683;

    var ct_and_tag: [23]u8 = undefined;
    const ct_len = try aeadEncrypt(.aes_128_gcm, &key, &iv, pn, &aad, plaintext, &ct_and_tag);

    std.debug.print("\nOpenSSL AES-128-GCM encrypt:\n", .{});
    std.debug.print("CT+Tag ({} bytes): ", .{ct_len});
    for (ct_and_tag[0..ct_len]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    var decrypted: [7]u8 = undefined;
    const pt_len = try aeadDecrypt(.aes_128_gcm, &key, &iv, pn, &aad, ct_and_tag[0..ct_len], &decrypted);

    try std.testing.expectEqual(@as(usize, 7), pt_len);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
    std.debug.print("✓ Round-trip successful!\n", .{});
}

test "OpenSSL AEAD - decrypt quic-go ciphertext" {
    const key = [_]u8{ 0x08, 0xc9, 0xbe, 0xde, 0x96, 0xf5, 0x7d, 0xcd, 0x56, 0x48, 0x35, 0x05, 0x97, 0xfb, 0x89, 0x18 };
    const iv = [_]u8{ 0xd1, 0x66, 0x9e, 0x59, 0xe0, 0x15, 0xb9, 0x99, 0x55, 0xa6, 0xab, 0x48 };
    const aad = [_]u8{ 0x53, 0x4e, 0xcc, 0xa1, 0x6f, 0x10, 0xb7, 0x79, 0xb0, 0x2a, 0xa1, 0xeb, 0x9b };
    const pn: u64 = 715254683;

    // Ciphertext and tag from quic-go
    const ct_and_tag = [_]u8{ 0xab, 0xbc, 0xcf, 0x28, 0xd8, 0x6e, 0x25, 0xf6, 0x2b, 0x1c, 0xf3, 0xdc, 0x85, 0xd2, 0x66, 0x92, 0x2b, 0xc2, 0xc7, 0x97, 0xbb, 0x68, 0x10 };

    var decrypted: [7]u8 = undefined;
    const pt_len = try aeadDecrypt(.aes_128_gcm, &key, &iv, pn, &aad, &ct_and_tag, &decrypted);

    std.debug.print("\nOpenSSL decrypt quic-go ciphertext:\n", .{});
    std.debug.print("Decrypted ({} bytes): ", .{pt_len});
    for (decrypted[0..pt_len]) |b| std.debug.print("{x:0>2} ", .{b});
    std.debug.print("\nAs string: \"{s}\"\n", .{decrypted[0..pt_len]});

    const expected = "GET /\r\n";
    try std.testing.expectEqual(@as(usize, 7), pt_len);
    try std.testing.expectEqualSlices(u8, expected, &decrypted);
    std.debug.print("✓ Successfully decrypted quic-go's ciphertext!\n", .{});
}
