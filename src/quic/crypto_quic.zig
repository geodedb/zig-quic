// MIT License
// QUIC Initial packet AEAD and Header Protection helpers (RFC 9001/9369)
const std = @import("std");
const builtin = @import("builtin");
const ks = @import("quic_tls");
const logger = @import("quic_logger");

// Use standard library crypto
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;

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
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
            ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key[0..32].*);
            @memcpy(out[plaintext.len .. plaintext.len + tag.len], tag[0..]);
            return plaintext.len + tag.len;
        },
        .aes_128_gcm => {
            if (key.len != 16 or iv.len != 12) return error.InvalidKeyIv;
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

    // Debug logging for AEAD decryption
    logger.debug("aeadDecrypt: suite={}, pn={}, ct_len={}, tag_len=16", .{ suite, packet_number, ct.len });
    dumpBytes("AEAD decrypt key", key);
    dumpBytes("AEAD decrypt iv", iv);
    var nonce_debug: [12]u8 = undefined;
    xorNonce(&nonce_debug, iv, packet_number);
    dumpBytes("AEAD decrypt nonce", &nonce_debug);
    dumpBytes("AEAD decrypt aad", aad);
    if (ct.len <= 32) {
        dumpBytes("AEAD decrypt ciphertext", ct);
    } else {
        dumpBytes("AEAD decrypt ciphertext (first 32)", ct[0..32]);
    }
    dumpBytes("AEAD decrypt tag", &tag_arr);

    switch (suite) {
        .chacha20_poly1305 => {
            if (key.len != 32 or iv.len != 12) return error.InvalidKeyIv;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            ChaCha20Poly1305.decrypt(out_plaintext[0..ct.len], ct, tag_arr, aad, nonce, key[0..32].*) catch {
                logger.debug("ChaCha20Poly1305.decrypt failed for pn={}", .{packet_number});
                return error.AuthenticationFailed;
            };
            return ct.len;
        },
        .aes_128_gcm => {
            if (key.len != 16 or iv.len != 12) return error.InvalidKeyIv;
            var nonce: [12]u8 = undefined;
            xorNonce(&nonce, iv, packet_number);
            Aes128Gcm.decrypt(out_plaintext[0..ct.len], ct, tag_arr, aad, nonce, key[0..16].*) catch {
                logger.debug("Aes128Gcm.decrypt failed for pn={}", .{packet_number});
                return error.AuthenticationFailed;
            };
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
            const Aes128 = std.crypto.core.aes.Aes128;
            var ctx = Aes128.initEnc(hp_key[0..16].*);
            var out_block: [16]u8 = undefined;
            ctx.encrypt(&out_block, sample16);
            const mask0 = out_block[0];
            const is_long = (header_first.* & 0x80) != 0;
            const hdr_mask: u8 = if (is_long) 0x0f else 0x1f;
            const old_first = header_first.*;
            header_first.* ^= (mask0 & hdr_mask);
            logger.debug("headerProtect: first byte 0x{X:0>2} ^ (mask0 0x{X:0>2} & hdr_mask 0x{X:0>2}) = 0x{X:0>2}", .{ old_first, mask0, hdr_mask, header_first.* });
            var i: usize = 0;
            while (i < pn_bytes.len) : (i += 1) pn_bytes[i] ^= out_block[i + 1];
            return;
        },
        .chacha20_poly1305 => {
            if (hp_key.len != 32) return error.InvalidKey;
            // Per RFC 9001 §5.4.4 use bytes 4..15 of sample as 96-bit nonce
            var nonce: [12]u8 = undefined;
            @memcpy(nonce[0..], sample16.*[4..16]);
            // Generate mask using ChaCha20 with counter=0
            var block: [64]u8 = undefined;
            ChaCha20IETF.xor(&block, &([_]u8{0} ** 64), 0, hp_key[0..32].*, nonce);
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
    // Per RFC 9001: The 62-bit packet number is padded with zeros on the left
    // and XORed with the IV to produce the nonce. Since we use 64-bit pn,
    // we just XOR it at the end of the 12-byte nonce (last 8 bytes).
    // The packet number is encoded in network byte order (big-endian).
    var pn_bytes: [8]u8 = undefined;
    pn_bytes[0] = @as(u8, @truncate(pn >> 56));
    pn_bytes[1] = @as(u8, @truncate(pn >> 48));
    pn_bytes[2] = @as(u8, @truncate(pn >> 40));
    pn_bytes[3] = @as(u8, @truncate(pn >> 32));
    pn_bytes[4] = @as(u8, @truncate(pn >> 24));
    pn_bytes[5] = @as(u8, @truncate(pn >> 16));
    pn_bytes[6] = @as(u8, @truncate(pn >> 8));
    pn_bytes[7] = @as(u8, @truncate(pn));
    // XOR the packet number bytes with the last 8 bytes of the IV
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        out[4 + i] ^= pn_bytes[i];
    }
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

/// Generic protection function for Initial and Handshake packets.
/// - header_first: pointer to first header byte (mutated by HP)
/// - pn_bytes: packet number bytes (1..4), mutated by HP
/// - header_prefix: bytes before PN (e.g., long header fields up to Length varint end)
/// - plaintext -> ciphertext+tag written to out_cipher (len = plaintext.len+16)
/// AAD = header_first || header_prefix || pn_bytes (pre-HP). HP sample is 16 bytes starting 4 bytes after PN, i.e., out_cipher[4..20].
pub fn protectPacket(
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
            // RFC 9001: sample starts 4 bytes after the start of packet number field
            // If PN is N bytes, sample starts at (4-N) bytes into ciphertext
            const sample_offset: usize = if (pn_len >= 4) 0 else (4 - pn_len);
            if (sample_offset + 16 > out_cipher.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..], out_cipher[sample_offset .. sample_offset + 16]);
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

/// Backward compatibility wrapper for protectInitial
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
    return protectPacket(suite, aead_key, aead_iv, hp_key, packet_number, header_first, pn_bytes, header_prefix, plaintext, out_cipher);
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

    if (builtin.is_test) {
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
        logger.debug("First packet: truncated={x:0>4} ({}) -> expanded={}", .{ pn_val_truncated, pn_val_truncated, pn_val });
    }

    if (builtin.is_test) {
        dumpBytes("DEC aead_key", aead_key);
        dumpBytes("DEC aead_iv", aead_iv);
        dumpBytes("DEC aad", aad);
        var ndbg: [12]u8 = undefined;
        xorNonce(&ndbg, aead_iv, pn_val);
        dumpBytes("DEC nonce", &ndbg);
        dumpBytes("DEC pn_bytes", pn_bytes);
    }

    return aeadDecrypt(suite, aead_key, aead_iv, pn_val, aad, ciphertext_and_tag, out_plaintext) catch |err| {
        logger.debug("AEAD decrypt failed: {} (pn={})", .{ err, pn_val });
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
            // RFC 9001: sample starts 4 bytes after the start of packet number field
            // If PN is N bytes, sample starts at (4-N) bytes into ciphertext
            const sample_offset = if (pn_len >= 4) 0 else (4 - pn_len);
            if (sample_offset + 16 > ciphertext_and_tag.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..], ciphertext_and_tag[sample_offset .. sample_offset + 16]);
        },
        .chacha20_poly1305 => {
            // For ChaCha20, sample is PN bytes (masked) followed by first (16 - pn_len) bytes of ciphertext
            if ((16 - pn_len) > ciphertext_and_tag.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..pn_len], pn_bytes);
            @memcpy(sample16[pn_len..], ciphertext_and_tag[0 .. 16 - pn_len]);
        },
    }

    // Remove header protection in-place (mutates header_first & pn_bytes) using derived sample
    if (builtin.is_test) {
        logger.debug("Before headerUnprotect: pn_bytes set", .{});
    }
    try headerUnprotect(suite, hp_key, &sample16, header_first, pn_bytes);
    if (builtin.is_test) {
        logger.debug("After headerUnprotect: pn_bytes set", .{});
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

    if (builtin.is_test) {
        logger.debug("expandPacketNumber: truncated={} pn_len={} expected={} -> full={}", .{ pn_trunc, pn_len, expected_pn, full_pn });
    }

    return aeadDecrypt(suite, aead_key, aead_iv, full_pn, aad, ciphertext_and_tag, out_plaintext) catch |err| {
        logger.debug("AEAD decrypt failed (auto-sample): {} (pn={})", .{ err, full_pn });
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
            const Aes128 = std.crypto.core.aes.Aes128;
            var ctx = Aes128.initEnc(hp_key[0..16].*);
            ctx.encrypt(&out_block, sample16);
        },
        .chacha20_poly1305 => {
            if (hp_key.len != 32) return error.InvalidKey;
            var nonce: [12]u8 = undefined;
            @memcpy(nonce[0..], sample16.*[4..16]);
            // Generate mask using ChaCha20 with counter=0
            var block: [64]u8 = undefined;
            ChaCha20IETF.xor(&block, &([_]u8{0} ** 64), 0, hp_key[0..32].*, nonce);
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
    logger.debug("{s}: {s}", .{ label, list.items });
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
