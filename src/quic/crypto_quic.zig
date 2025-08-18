// MIT License
// QUIC Initial packet AEAD and Header Protection helpers (RFC 9001/9369)
const std = @import("std");

/// Supported AEAD suites for QUIC-TLS binding.
pub const AeadSuite = enum { aes_128_gcm, chacha20_poly1305 };

/// Encrypt plaintext with associated data using the given suite.
/// The nonce is constructed as iv XOR packet_number (left-padded to iv length) per RFC 9001.
/// The output buffer must have capacity plaintext.len + 16 (tag).
pub fn aeadEncrypt(
    suite: AeadSuite,
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    switch (suite) {
        .chacha20_poly1305 => {
            if (key.len != 32 or iv.len != 12) return error.InvalidKeyIv;
            const has_chacha = @hasDecl(std.crypto.aead, "chacha20poly1305");
            if (!has_chacha) return error.NotImplemented;
            const ChaCha = std.crypto.aead.chacha20poly1305;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            try ChaCha.encrypt(out, plaintext, aad, key[0..32].*, nonce);
            return plaintext.len + 16;
        },
        .aes_128_gcm => {
            if (key.len != 16 or iv.len != 12) return error.InvalidKeyIv;
            const has_aes_gcm = @hasDecl(std.crypto.aead, "aes_gcm");
            if (!has_aes_gcm) return error.NotImplemented;
            const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            try Aes128Gcm.encrypt(out, plaintext, aad, key[0..16].*, nonce);
            return plaintext.len + 16;
        },
    }
}

/// Decrypt ciphertext+tag with associated data using the given suite.
/// Returns plaintext length on success.
pub fn aeadDecrypt(
    suite: AeadSuite,
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
) !usize {
    if (ciphertext_and_tag.len < 16) return error.AuthenticationFailed;
    const ct = ciphertext_and_tag[0 .. ciphertext_and_tag.len - 16];
    switch (suite) {
        .chacha20_poly1305 => {
            if (key.len != 32 or iv.len != 12) return error.InvalidKeyIv;
            const has_chacha = @hasDecl(std.crypto.aead, "chacha20poly1305");
            if (!has_chacha) return error.NotImplemented;
            const ChaCha = std.crypto.aead.chacha20poly1305;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            try ChaCha.decrypt(out_plaintext[0..ct.len], ciphertext_and_tag, aad, key[0..32].*, nonce);
            return ct.len;
        },
        .aes_128_gcm => {
            if (key.len != 16 or iv.len != 12) return error.InvalidKeyIv;
            const has_aes_gcm = @hasDecl(std.crypto.aead, "aes_gcm");
            if (!has_aes_gcm) return error.NotImplemented;
            const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            try Aes128Gcm.decrypt(out_plaintext[0..ct.len], ciphertext_and_tag, aad, key[0..16].*, nonce);
            return ct.len;
        },
    }
}

/// Apply header protection to the first byte and packet number bytes.
/// Mutates header[0] and pn_bytes[0..pn_len] in place. The sample must be 16 bytes.
pub fn headerProtect(
    suite: AeadSuite,
    hp_key: []const u8,
    sample16: *const [16]u8,
    header_first: *u8,
    pn_bytes: []u8,
) !void {
    if (pn_bytes.len == 0 or pn_bytes.len > 4) return error.InvalidPacketNumberLength;

    switch (suite) {
        .aes_128_gcm => {
            // TODO: Implement AES-ECB(single block) mask: mask = AES-ECB(hp_key, sample16)
            // Then apply header_first ^= mask[0] & (is_long ? 0x0f : 0x1f)
            // and pn_bytes[i] ^= mask[i+1].
            // Parameters intentionally unused until AES HP lands.
            return error.NotImplemented;
        },
        .chacha20_poly1305 => {
            if (hp_key.len != 32) return error.InvalidKey;
            var nonce: [12]u8 = undefined;
            // Per RFC 9001 §5.4.4 use bytes 4..15 of sample as 96-bit nonce
            @memcpy(nonce[0..], sample16.*[4..16]);
            var block: [64]u8 = undefined;
            chacha20Block(&block, hp_key[0..32].*, nonce, 0);
            const mask0 = block[0];
            const is_long = (header_first.* & 0x80) != 0;
            const hdr_mask: u8 = if (is_long) 0x0f else 0x1f;
            header_first.* = header_first.* ^ (mask0 & hdr_mask);
            // Packet number bytes use next mask bytes
            var i: usize = 0;
            while (i < pn_bytes.len) : (i += 1) {
                pn_bytes[i] ^= block[i + 1];
            }
            return;
        },
    }
}

/// Remove header protection (inverse of headerProtect).
pub fn headerUnprotect(
    suite: AeadSuite,
    hp_key: []const u8,
    sample16: *const [16]u8,
    header_first: *u8,
    pn_bytes: []u8,
) !void {
    // Symmetric operation; same as protect.
    return headerProtect(suite, hp_key, sample16, header_first, pn_bytes);
}

fn xorNonce(out: *[12]u8, iv: []const u8, pn: u64) void {
    @memcpy(out, iv);
    var pn_be: [12]u8 = .{0} ** 12;
    // encode pn as big-endian 64-bit at the end of 12-byte array
    pn_be[4] = @as(u8, @truncate(pn >> 56));
    pn_be[5] = @as(u8, @truncate(pn >> 48));
    pn_be[6] = @as(u8, @truncate(pn >> 40));
    pn_be[7] = @as(u8, @truncate(pn >> 32));
    pn_be[8] = @as(u8, @truncate(pn >> 24));
    pn_be[9] = @as(u8, @truncate(pn >> 16));
    pn_be[10] = @as(u8, @truncate(pn >> 8));
    pn_be[11] = @as(u8, @truncate(pn));
    for (out.*, pn_be) |*b, x| b.* = b.* ^ x;
}

// --- ChaCha20 block (minimal) for header protection ---
inline fn rotl32(x: u32, n: u5) u32 {
    return (x << n) | (x >> @as(u5, 32 - n));
}

inline fn qr(a: *u32, b: *u32, c: *u32, d: *u32) void {
    a.* +%= b.*;
    d.* ^= a.*;
    d.* = rotl32(d.*, 16);
    c.* +%= d.*;
    b.* ^= c.*;
    b.* = rotl32(b.*, 12);
    a.* +%= b.*;
    d.* ^= a.*;
    d.* = rotl32(d.*, 8);
    c.* +%= d.*;
    b.* ^= c.*;
    b.* = rotl32(b.*, 7);
}

fn chacha20Block(out: *[64]u8, key32: [32]u8, nonce12: [12]u8, counter: u32) void {
    var state: [16]u32 = .{
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // constants
        // key (little-endian)
        0,          0,          0,          0,
        0,          0,          0,          0,
        counter, // counter
        0, 0, 0, // nonce
    };
    // load key little-endian
    comptime var i: usize = 0;
    inline while (i < 8) : (i += 1) {
        const j = i * 4;
        state[4 + i] = @as(u32, key32[j]) | (@as(u32, key32[j + 1]) << 8) | (@as(u32, key32[j + 2]) << 16) | (@as(u32, key32[j + 3]) << 24);
    }
    // load nonce little-endian
    state[13] = @as(u32, nonce12[0]) | (@as(u32, nonce12[1]) << 8) | (@as(u32, nonce12[2]) << 16) | (@as(u32, nonce12[3]) << 24);
    state[14] = @as(u32, nonce12[4]) | (@as(u32, nonce12[5]) << 8) | (@as(u32, nonce12[6]) << 16) | (@as(u32, nonce12[7]) << 24);
    state[15] = @as(u32, nonce12[8]) | (@as(u32, nonce12[9]) << 8) | (@as(u32, nonce12[10]) << 16) | (@as(u32, nonce12[11]) << 24);

    var x = state; // working state
    var r: usize = 0;
    while (r < 10) : (r += 1) {
        // column rounds
        qr(&x[0], &x[4], &x[8], &x[12]);
        qr(&x[1], &x[5], &x[9], &x[13]);
        qr(&x[2], &x[6], &x[10], &x[14]);
        qr(&x[3], &x[7], &x[11], &x[15]);
        // diagonal rounds
        qr(&x[0], &x[5], &x[10], &x[15]);
        qr(&x[1], &x[6], &x[11], &x[12]);
        qr(&x[2], &x[7], &x[8], &x[13]);
        qr(&x[3], &x[4], &x[9], &x[14]);
    }
    var sum_iter: usize = 0;
    while (sum_iter < 16) : (sum_iter += 1) x[sum_iter] +%= state[sum_iter];

    // serialize little-endian
    var o: usize = 0;
    var k: usize = 0;
    while (k < 16) : (k += 1) {
        const v = x[k];
        out.*[o + 0] = @as(u8, @truncate(v));
        out.*[o + 1] = @as(u8, @truncate(v >> 8));
        out.*[o + 2] = @as(u8, @truncate(v >> 16));
        out.*[o + 3] = @as(u8, @truncate(v >> 24));
        o += 4;
    }
}
