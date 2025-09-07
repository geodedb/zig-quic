// MIT License
// QUIC Initial packet AEAD and Header Protection helpers (RFC 9001/9369)
const std = @import("std");
const core = std.crypto.core;
const builtin = @import("builtin");
const ks = @import("quic_tls");

/// Expand a truncated packet number using the expected packet number.
/// Based on RFC 9000 Appendix A.3
fn expandPacketNumber(truncated: u64, pn_len: u3, expected: u64) u64 {
    const pn_nbits: u6 = @as(u6, pn_len) * 8;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;

    // For the first packet, if we have no expectation, just return the truncated value
    // This handles the case where the client starts with a random packet number
    if (expected == 0 and truncated < pn_win) {
        return truncated;
    }

    var candidate: u64 = (expected & ~pn_mask) | truncated;

    // Determine if we need to adjust the candidate
    // Check if candidate is too far in the past
    if (expected >= pn_hwin) {
        if (candidate <= expected - pn_hwin and candidate < (1 << 62)) {
            candidate += pn_win;
        }
    }
    // Check if candidate is too far in the future
    if (candidate > expected + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }

    return candidate;
}

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
            if (has_chacha) {
                const ChaCha = std.crypto.aead.chacha20poly1305.ChaCha20Poly1305;
                var nonce: [12]u8 = undefined;
                xorNonce(&nonce, iv, packet_number);
                var tag: [ChaCha.tag_length]u8 = undefined;
                ChaCha.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key[0..32].*);
                @memcpy(out[plaintext.len .. plaintext.len + tag.len], tag[0..]);
                return plaintext.len + tag.len;
            } else {
                // Fallback: RFC 8439 AEAD_CHACHA20_POLY1305 (IETF 96-bit nonce)
                var nonce: [12]u8 = undefined;
                xorNonce(&nonce, iv, packet_number);
                // Derive one-time Poly1305 key: chacha20 block with counter=0
                var otk_block: [64]u8 = undefined;
                chacha20Block(&otk_block, key[0..32].*, nonce, 0);
                var otk: [32]u8 = undefined;
                @memcpy(otk[0..], otk_block[0..32]);
                // Encrypt plaintext with counter=1
                chacha20Xor(out[0..plaintext.len], plaintext, key[0..32].*, nonce, 1);
                // Compute Poly1305 tag over AAD || pad16 || CT || pad16 || len(aad) || len(ct)
                const tag = try poly1305TagRfc8439(aad, out[0..plaintext.len], &otk);
                @memcpy(out[plaintext.len .. plaintext.len + 16], tag[0..]);
                return plaintext.len + 16;
            }
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
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            if (has_chacha) {
                const ChaCha = std.crypto.aead.chacha20poly1305.ChaCha20Poly1305;
                if (!ChaCha.decrypt(out_plaintext[0..ct.len], ct, tag_arr, aad, nonce, key[0..32].*))
                    return error.AuthenticationFailed;
                return ct.len;
            } else {
                // Fallback: verify tag then decrypt with counter=1
                var otk_block: [64]u8 = undefined;
                chacha20Block(&otk_block, key[0..32].*, nonce, 0);
                var otk: [32]u8 = undefined;
                @memcpy(otk[0..], otk_block[0..32]);
                const tag = try poly1305TagRfc8439(aad, ct, &otk);
                if (!std.mem.eql(u8, &tag_arr, &tag)) return error.AuthenticationFailed;
                chacha20Xor(out_plaintext[0..ct.len], ct, key[0..32].*, nonce, 1);
                return ct.len;
            }
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

// --- Retry Integrity Tag helpers (RFC 9001 §5.8, RFC 9369 §3.3.3) ---
const retry_secret_v1: [32]u8 = .{
    0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20,
    0x00, 0x21, 0x50, 0x6b, 0xcc, 0x02, 0x81, 0x4c,
    0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce,
    0x87, 0x6e, 0xca, 0x87, 0x6e, 0x6f, 0xca, 0x8e,
};
const retry_secret_v2: [32]u8 = .{
    0xc4, 0xdd, 0x24, 0x84, 0xd6, 0x81, 0xae, 0xfa,
    0x4f, 0xf4, 0xd6, 0x9c, 0x2c, 0x20, 0x29, 0x99,
    0x84, 0xa7, 0x65, 0xa5, 0xd3, 0xc3, 0x19, 0x82,
    0xf3, 0x8f, 0xc7, 0x41, 0x62, 0x15, 0x5e, 0x9f,
};

fn deriveRetryKeyIv(version_v2: bool) struct { key: [16]u8, iv: [12]u8 } {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    if (version_v2) {
        ks.expandLabel(retry_secret_v2, "quicv2 key", &[_]u8{}, &key) catch unreachable;
        ks.expandLabel(retry_secret_v2, "quicv2 iv", &[_]u8{}, &iv) catch unreachable;
    } else {
        ks.expandLabel(retry_secret_v1, "quic key", &[_]u8{}, &key) catch unreachable;
        ks.expandLabel(retry_secret_v1, "quic iv", &[_]u8{}, &iv) catch unreachable;
    }
    return .{ .key = key, .iv = iv };
}

/// Compute the Retry Integrity Tag over the provided pseudo-packet AAD using AES-128-GCM with fixed key/nonce.
fn aesGcmTagFixedNonce(key16: [16]u8, nonce12: [12]u8, aad: []const u8) [16]u8 {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    // Empty plaintext; ciphertext buffer can be zero-length
    const ct: []u8 = ct_empty[0..0];
    Aes128Gcm.encrypt(ct, &tag, ct_empty[0..0], aad, nonce12, key16);
    return tag;
}

var ct_empty: [1]u8 = .{0};

/// Public helper: compute Retry Integrity Tag for QUIC v1/v2.
pub fn computeRetryIntegrityTag(version_v2: bool, odcid: []const u8, retry_without_tag: []const u8) [16]u8 {
    const kiv = deriveRetryKeyIv(version_v2);
    // Build AAD = ODCID Len (1) || ODCID || retry_without_tag
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.heap.page_allocator);
    buf.append(std.heap.page_allocator, @as(u8, @intCast(odcid.len))) catch unreachable;
    buf.appendSlice(std.heap.page_allocator, odcid) catch unreachable;
    buf.appendSlice(std.heap.page_allocator, retry_without_tag) catch unreachable;
    return aesGcmTagFixedNonce(kiv.key, kiv.iv, buf.items);
}

/// Protect an Initial-like packet payload and apply header protection using the provided keys.
/// - header_first: pointer to first header byte (mutated by HP)
/// - pn_bytes: packet number bytes (1..4), mutated by HP
/// - header_prefix: bytes before PN (e.g., long header fields up to Length varint end)
/// - plaintext -> ciphertext+tag written to out_cipher (len = plaintext.len+16)
/// AAD = header_first || header_prefix || pn_bytes (pre-HP). HP sample is 16 bytes starting 4 bytes after PN, i.e., out_cipher[4..20].
pub fn protectInitial(
    suite: AeadSuite,
    aead_key: []const u8,
    aead_iv: []const u8,
    hp_key: []const u8,
    packet_number: u64,
    header_first: *u8,
    pn_bytes: []u8,
    header_prefix: []const u8, // bytes after first header byte up to PN
    plaintext: []const u8,
    out_cipher: []u8,
) !usize {
    // Build AAD: header_first || header_prefix || pn_bytes (pre-HP)
    var aad_stack: [1024]u8 = undefined;
    const aad_len = 1 + header_prefix.len + pn_bytes.len;
    if (aad_len > aad_stack.len) return error.MessageTooLong;
    aad_stack[0] = header_first.*;
    @memcpy(aad_stack[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_stack[1 + header_prefix.len .. aad_len], pn_bytes);
    const aad = aad_stack[0..aad_len];

    // Debug dumps
    if (builtin.is_test) {
        dumpBytes("ENC aead_key", aead_key);
        dumpBytes("ENC aead_iv", aead_iv);
        dumpBytes("ENC aad", aad);
        var ndbg: [12]u8 = undefined;
        xorNonce(&ndbg, aead_iv, packet_number);
        dumpBytes("ENC nonce", &ndbg);
        dumpBytes("ENC pn_bytes", pn_bytes);
    }

    const ct_len = try aeadEncrypt(suite, aead_key, aead_iv, packet_number, aad, plaintext, out_cipher);

    // Build HP sample per RFC 9001:
    // - AES: 16 bytes starting 4 bytes after start of PN -> relative to ciphertext (which starts after PN), offset = 4 - pn_len
    // - ChaCha: 16 bytes starting at start of PN -> compose from PN bytes + first (16 - pn_len) bytes of ciphertext
    if (ct_len < 16) return error.AuthenticationFailed;
    var sample16: [16]u8 = undefined;
    const pn_len: usize = pn_bytes.len;
    switch (suite) {
        .aes_128_gcm => {
            const offset: usize = (4 - pn_len);
            if (offset + 16 > out_cipher.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..], out_cipher[offset .. offset + 16]);
        },
        .chacha20_poly1305 => {
            if (pn_len > 4) return error.InvalidPacketNumberLength;
            if ((16 - pn_len) > out_cipher.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..pn_len], pn_bytes);
            @memcpy(sample16[pn_len..], out_cipher[0 .. 16 - pn_len]);
        },
    }
    if (builtin.is_test) dumpBytes("ENC hp_sample", sample16[0..]);

    try headerProtect(suite, hp_key, &sample16, header_first, pn_bytes);

    return ct_len;
}

/// Undo header protection and decrypt Initial-like packet payload.
/// expected_pn is used to expand the truncated packet number.
pub fn unprotectInitial(
    suite: AeadSuite,
    aead_key: []const u8,
    aead_iv: []const u8,
    hp_key: []const u8,
    header_first: *u8,
    pn_bytes: []u8,
    header_prefix: []const u8, // bytes after first header byte up to PN
    hp_sample16: *const [16]u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
    expected_pn: u64, // Expected packet number for expansion
) !usize {
    if (ciphertext_and_tag.len < 16) return error.AuthenticationFailed;

    if (builtin.is_test or true) { // Always debug for now
        dumpBytes("DEC hp_sample", hp_sample16.*[0..]);
        dumpBytes("DEC hp_key", hp_key);
    }

    // Remove header protection using provided sample
    try headerUnprotect(suite, hp_key, hp_sample16, header_first, pn_bytes);

    // AAD recomputed with unprotected header_first and pn_bytes
    var aad_stack: [1024]u8 = undefined;
    const aad_len = 1 + header_prefix.len + pn_bytes.len;
    if (aad_len > aad_stack.len) return error.MessageTooLong;
    aad_stack[0] = header_first.*;
    @memcpy(aad_stack[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_stack[1 + header_prefix.len .. aad_len], pn_bytes);
    const aad = aad_stack[0..aad_len];

    // Derive packet_number from unmasked pn_bytes (big-endian truncated).
    var pn_val_truncated: u64 = 0;
    var i: usize = 0;
    while (i < pn_bytes.len) : (i += 1) pn_val_truncated = (pn_val_truncated << 8) | pn_bytes[i];

    // Expand the truncated packet number using the expected value
    const pn_val = expandPacketNumber(pn_val_truncated, @intCast(pn_bytes.len), expected_pn);

    if (expected_pn == 0) {
        std.debug.print("First packet: truncated={x:0>4} ({}) -> expanded={}\n", .{ pn_val_truncated, pn_val_truncated, pn_val });
    }

    if (builtin.is_test or true) { // Always debug for now
        dumpBytes("DEC aead_key", aead_key);
        dumpBytes("DEC aead_iv", aead_iv);
        dumpBytes("DEC aad", aad);
        var ndbg: [12]u8 = undefined;
        xorNonce(&ndbg, aead_iv, pn_val);
        dumpBytes("DEC nonce", &ndbg);
        dumpBytes("DEC pn_bytes", pn_bytes);
    }

    return aeadDecrypt(suite, aead_key, aead_iv, pn_val, aad, ciphertext_and_tag, out_plaintext) catch |err| {
        std.debug.print("AEAD decrypt failed: {} (pn={})\n", .{ err, pn_val });
        return err;
    };
}

/// Variant of unprotectInitial that derives the HP sample internally from pn_bytes and ciphertext
/// to avoid caller misuse (incorrect sample construction can lead to auth failure). For AES-128-GCM
/// the sample is the 16 bytes starting (4 - pn_len) bytes into the ciphertext (which begins right
/// after the truncated PN). For ChaCha20-Poly1305 the sample is PN bytes (1..4) followed by the first
/// (16 - pn_len) bytes of ciphertext (RFC 9001 §5.4.4). The AAD construction and PN expansion logic
/// mirror unprotectInitial.
pub fn unprotectInitialAutoSample(
    suite: AeadSuite,
    aead_key: []const u8,
    aead_iv: []const u8,
    hp_key: []const u8,
    header_first: *u8,
    pn_bytes: []u8,
    header_prefix: []const u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
    expected_pn: u64,
) !usize {
    if (ciphertext_and_tag.len < 16) return error.AuthenticationFailed;
    const pn_len = pn_bytes.len;
    if (pn_len == 0 or pn_len > 4) return error.InvalidPacketNumberLength;

    // Reconstruct HP sample per suite
    var sample16: [16]u8 = undefined;
    switch (suite) {
        .aes_128_gcm => {
            const offset = 4 - pn_len; // (4 - pn_len) into ciphertext
            if (offset + 16 > ciphertext_and_tag.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..], ciphertext_and_tag[offset .. offset + 16]);
        },
        .chacha20_poly1305 => {
            if ((16 - pn_len) > ciphertext_and_tag.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..pn_len], pn_bytes);
            @memcpy(sample16[pn_len..], ciphertext_and_tag[0 .. 16 - pn_len]);
        },
    }

    // Remove header protection in-place (mutates header_first & pn_bytes) using derived sample
    if (builtin.is_test or true) {
        std.debug.print("Before headerUnprotect: pn_bytes=", .{});
        for (pn_bytes) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});
    }
    try headerUnprotect(suite, hp_key, &sample16, header_first, pn_bytes);
    if (builtin.is_test or true) {
        std.debug.print("After headerUnprotect: pn_bytes=", .{});
        for (pn_bytes) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});
    }

    // Build AAD after unmasking: first byte + header_prefix + pn_bytes
    var aad_stack: [1024]u8 = undefined;
    const aad_len = 1 + header_prefix.len + pn_len;
    if (aad_len > aad_stack.len) return error.MessageTooLong;
    aad_stack[0] = header_first.*;
    @memcpy(aad_stack[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_stack[1 + header_prefix.len .. aad_len], pn_bytes);
    const aad = aad_stack[0..aad_len];

    // Expand truncated PN for nonce derivation
    var pn_trunc: u64 = 0;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) pn_trunc = (pn_trunc << 8) | pn_bytes[i];
    const full_pn = expandPacketNumber(pn_trunc, @intCast(pn_len), expected_pn);

    if (builtin.is_test or true) { // Always debug for now
        std.debug.print("expandPacketNumber: truncated={} pn_len={} expected={} -> full={}\n", .{ pn_trunc, pn_len, expected_pn, full_pn });
    }

    return aeadDecrypt(suite, aead_key, aead_iv, full_pn, aad, ciphertext_and_tag, out_plaintext) catch |err| {
        std.debug.print("AEAD decrypt failed (auto-sample): {} (pn={})\n", .{ err, full_pn });
        return err;
    };
}

/// Unmask long header first byte and up to 4 PN bytes using the given hp_key and sample.
/// Returns the actual packet number length (1..4) after unmasking the header.
pub fn unmaskLongHeaderAndPn(
    suite: AeadSuite,
    hp_key: []const u8,
    sample16: *const [16]u8,
    header_first: *u8,
    pn_buf: *[4]u8, // contains 4 masked bytes from packet at PN start
) !u3 {
    var out_block: [16]u8 = undefined;
    switch (suite) {
        .aes_128_gcm => {
            if (hp_key.len != 16) return error.InvalidKey;
            try aesEcbEncrypt128(&out_block, hp_key[0..16].*, sample16.*);
        },
        .chacha20_poly1305 => {
            if (hp_key.len != 32) return error.InvalidKey;
            var nonce: [12]u8 = undefined;
            @memcpy(nonce[0..], sample16.*[4..16]);
            var block: [64]u8 = undefined;
            chacha20Block(&block, hp_key[0..32].*, nonce, 0);
            @memcpy(out_block[0..16], block[0..16]);
        },
    }
    const is_long = (header_first.* & 0x80) != 0;
    const hdr_mask: u8 = if (is_long) 0x0f else 0x1f;
    header_first.* ^= (out_block[0] & hdr_mask);
    const pn_len: u3 = @as(u3, @intCast((header_first.* & 0x03))) + 1;
    // Constant-time-ish: always xor 4 bytes to avoid data-dependent timing; callers will slice by pn_len.
    var i: usize = 0;
    while (i < 4) : (i += 1) pn_buf.*[i] ^= out_block[i + 1];
    return pn_len;
}

// XOR ChaCha20 keystream (starting from given counter) with input into out
fn chacha20Xor(out: []u8, input: []const u8, key32: [32]u8, nonce12: [12]u8, counter: u32) void {
    var ctr = counter;
    var off: usize = 0;
    var block: [64]u8 = undefined;
    while (off < input.len) {
        chacha20Block(&block, key32, nonce12, ctr);
        ctr +%= 1;
        const n = @min(input.len - off, block.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            out[off + i] = input[off + i] ^ block[i];
        }
        off += n;
    }
}

inline fn pad16Len(len: usize) usize {
    return (16 - (len % 16)) % 16;
}

fn le64(x: u64) [8]u8 {
    return .{
        @as(u8, @truncate(x)),
        @as(u8, @truncate(x >> 8)),
        @as(u8, @truncate(x >> 16)),
        @as(u8, @truncate(x >> 24)),
        @as(u8, @truncate(x >> 32)),
        @as(u8, @truncate(x >> 40)),
        @as(u8, @truncate(x >> 48)),
        @as(u8, @truncate(x >> 56)),
    };
}

fn poly1305TagRfc8439(aad: []const u8, ciphertext: []const u8, otk32: *const [32]u8) ![16]u8 {
    // Prefer std Poly1305 if available
    const have_poly = @hasDecl(std.crypto.onetimeauth, "Poly1305");
    if (have_poly) {
        const Poly1305 = std.crypto.onetimeauth.Poly1305;
        var mac = Poly1305.init(otk32);
        // AAD
        mac.update(aad);
        var zeros16: [16]u8 = .{0} ** 16;
        var pad_len = pad16Len(aad.len);
        if (pad_len != 0) mac.update(zeros16[0..pad_len]);
        // Ciphertext
        mac.update(ciphertext);
        pad_len = pad16Len(ciphertext.len);
        if (pad_len != 0) mac.update(zeros16[0..pad_len]);
        // Lengths (64-bit little endian each)
        const a_len_le = le64(@intCast(aad.len));
        const c_len_le = le64(@intCast(ciphertext.len));
        mac.update(&a_len_le);
        mac.update(&c_len_le);
        var tag: [16]u8 = undefined;
        mac.final(&tag);
        return tag;
    } else {
        // Minimal in-repo Poly1305 (slow fallback) — not implemented yet.
        return error.NotImplemented;
    }
}

fn dumpBytes(label: []const u8, bytes: []const u8) void {
    // Temporarily always dump for debugging
    // if (!builtin.is_test) return;
    var list = std.ArrayList(u8){};
    defer list.deinit(std.heap.page_allocator);
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        _ = list.writer(std.heap.page_allocator).print("{x:0>2}", .{bytes[i]}) catch break;
        if (i + 1 < bytes.len) _ = list.append(std.heap.page_allocator, ' ') catch break;
    }
    std.debug.print("{s}: {s}\n", .{ label, list.items });
}

/// Decode QUIC short header key phase bit and pn length from first byte.
/// Returns (key_phase: bool, pn_len: u3)
pub fn decodeShortHeaderKeyPhaseAndPnLen(first: u8) struct { key_phase: bool, pn_len: u3 } {
    // Short header format: 0b0100_?0?? where bit 2 is Key Phase, bits 0..1 are PN length-1
    const key_phase = ((first >> 2) & 0x01) == 1;
    const pn_len: u3 = @as(u3, @intCast(first & 0x03)) + 1;
    return .{ .key_phase = key_phase, .pn_len = pn_len };
}

/// Derive next 1-RTT AeadKeys from current application traffic secret (client or server).
pub fn deriveNextAppKeys(current_app_secret: [ks.H.digest_length]u8, version_v2: bool) struct { next_secret: [ks.H.digest_length]u8, keys: struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } } {
    const next = ks.updateTrafficSecret(current_app_secret);
    const mat = if (version_v2) ks.deriveKeyIvHpV2(next) else ks.deriveKeyIvHp(next);
    return .{ .next_secret = next, .keys = .{ .key = mat.key, .iv = mat.iv, .hp = mat.hp } };
}
