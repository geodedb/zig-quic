// MIT License
// QUIC Initial packet AEAD and Header Protection helpers (RFC 9001/9369)
const std = @import("std");
const core = std.crypto.core;

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
            const ChaCha = std.crypto.aead.chacha20poly1305.ChaCha20Poly1305;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            var tag: [ChaCha.tag_length]u8 = undefined;
            ChaCha.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key[0..32].*);
            @memcpy(out[plaintext.len .. plaintext.len + tag.len], tag[0..]);
            return plaintext.len + tag.len;
        },
        .aes_128_gcm => {
            if (key.len != 16 or iv.len != 12) return error.InvalidKeyIv;
            const has_aes_gcm = @hasDecl(std.crypto.aead, "aes_gcm");
            if (!has_aes_gcm) return error.NotImplemented;
            const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            var tag: [Aes128Gcm.tag_length]u8 = undefined;
            Aes128Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key[0..16].*);
            @memcpy(out[plaintext.len .. plaintext.len + tag.len], tag[0..]);
            return plaintext.len + tag.len;
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
    var tag_arr: [16]u8 = undefined;
    @memcpy(tag_arr[0..], ciphertext_and_tag[ciphertext_and_tag.len - 16 ..]);
    switch (suite) {
        .chacha20_poly1305 => {
            if (key.len != 32 or iv.len != 12) return error.InvalidKeyIv;
            const has_chacha = @hasDecl(std.crypto.aead, "chacha20poly1305");
            if (!has_chacha) return error.NotImplemented;
            const ChaCha = std.crypto.aead.chacha20poly1305.ChaCha20Poly1305;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            if (!ChaCha.decrypt(out_plaintext[0..ct.len], ct, tag_arr, aad, nonce, key[0..32].*))
                return error.AuthenticationFailed;
            return ct.len;
        },
        .aes_128_gcm => {
            if (key.len != 16 or iv.len != 12) return error.InvalidKeyIv;
            const has_aes_gcm = @hasDecl(std.crypto.aead, "aes_gcm");
            if (!has_aes_gcm) return error.NotImplemented;
            const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            try Aes128Gcm.decrypt(out_plaintext[0..ct.len], ct, tag_arr, aad, nonce, key[0..16].*);
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
            // AES-based header protection per RFC 9001 §5.4.3
            if (hp_key.len != 16) return error.InvalidKey;
            var out_block: [16]u8 = undefined;
            try aesEcbEncrypt128(&out_block, hp_key[0..16].*, sample16.*);
            const mask0 = out_block[0];
            const is_long = (header_first.* & 0x80) != 0;
            const hdr_mask: u8 = if (is_long) 0x0f else 0x1f;
            header_first.* ^= (mask0 & hdr_mask);
            var i: usize = 0;
            while (i < pn_bytes.len) : (i += 1) pn_bytes[i] ^= out_block[i + 1];
            return;
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
            header_first.* ^= (mask0 & hdr_mask);
            var i: usize = 0;
            while (i < pn_bytes.len) : (i += 1) pn_bytes[i] ^= block[i + 1];
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
    @memcpy(out[0..], iv);
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
    var i: usize = 0;
    while (i < 12) : (i += 1) out[i] ^= pn_be[i];
}

// --- ChaCha20 block (minimal) for header protection ---
inline fn rotl32(x: u32, n: u5) u32 {
    return std.math.rotl(u32, x, n);
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
    comptime var i_key: usize = 0;
    inline while (i_key < 8) : (i_key += 1) {
        const j = i_key * 4;
        state[4 + i_key] = @as(u32, key32[j]) | (@as(u32, key32[j + 1]) << 8) | (@as(u32, key32[j + 2]) << 16) | (@as(u32, key32[j + 3]) << 24);
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

fn aesEcbEncrypt128(out: *[16]u8, key16: [16]u8, block16: [16]u8) !void {
    if (!@hasDecl(core, "aes")) return error.NotImplemented;
    const Aes128 = core.aes.Aes128;
    var ctx = Aes128.initEnc(key16);
    ctx.encrypt(out, &block16);
}

/// Protect an Initial-like packet payload and apply header protection using the provided keys.
/// - header_first: pointer to first header byte (mutated by HP)
/// - pn_bytes: packet number bytes (1..4), mutated by HP
/// - header_prefix: bytes before PN (e.g., long header fields up to Length varint end)
/// - plaintext -> ciphertext+tag written to out_cipher (len = plaintext.len+16)
/// AAD = header_prefix || pn_bytes (pre-HP). HP sample is 16 bytes starting 4 bytes after PN, i.e., out_cipher[4..20].
pub fn protectInitial(
    suite: AeadSuite,
    aead_key: []const u8,
    aead_iv: []const u8,
    hp_key: []const u8,
    packet_number: u64,
    header_first: *u8,
    pn_bytes: []u8,
    header_prefix: []const u8,
    plaintext: []const u8,
    out_cipher: []u8,
) !usize {
    // Build AAD: header_prefix || pn_bytes (pre-HP)
    var aad_buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer aad_buf.deinit();
    try aad_buf.appendSlice(header_prefix);
    try aad_buf.appendSlice(pn_bytes);
    const aad = aad_buf.items;

    const ct_len = try aeadEncrypt(suite, aead_key, aead_iv, packet_number, aad, plaintext, out_cipher);

    // HP sample: for AES, start at (4 - pn_len); for ChaCha, start at 0.
    if (ct_len < 16) return error.AuthenticationFailed;
    var sample16: [16]u8 = undefined;
    const pn_len: usize = pn_bytes.len;
    const offset: usize = switch (suite) {
        .aes_128_gcm => (4 - pn_len),
        .chacha20_poly1305 => 0,
    };
    if (offset + 16 > out_cipher.len) return error.AuthenticationFailed;
    @memcpy(sample16[0..], out_cipher[offset .. offset + 16]);
    try headerProtect(suite, hp_key, &sample16, header_first, pn_bytes);

    return ct_len;
}

/// Undo header protection and decrypt Initial-like packet payload.
pub fn unprotectInitial(
    suite: AeadSuite,
    aead_key: []const u8,
    aead_iv: []const u8,
    hp_key: []const u8,
    packet_number: u64,
    header_first: *u8,
    pn_bytes: []u8,
    header_prefix: []const u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
) !usize {
    if (ciphertext_and_tag.len < 16) return error.AuthenticationFailed;
    var sample16: [16]u8 = undefined;
    const pn_len: usize = pn_bytes.len;
    const offset: usize = switch (suite) {
        .aes_128_gcm => (4 - pn_len),
        .chacha20_poly1305 => 0,
    };
    if (offset + 16 > ciphertext_and_tag.len) return error.AuthenticationFailed;
    @memcpy(sample16[0..], ciphertext_and_tag[offset .. offset + 16]);
    try headerUnprotect(suite, hp_key, &sample16, header_first, pn_bytes);

    // AAD recomputed with unprotected header_first and pn_bytes
    var aad_buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer aad_buf.deinit();
    try aad_buf.appendSlice(header_prefix);
    try aad_buf.appendSlice(pn_bytes);
    const aad = aad_buf.items;

    return try aeadDecrypt(suite, aead_key, aead_iv, packet_number, aad, ciphertext_and_tag, out_plaintext);
}
