// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC Initial packet AEAD and Header Protection helpers (RFC 9001/9369).
//!
//! Covers key derivation and masking rules from RFC 9001 §§5.3–5.4 and Retry
//! integrity handling from RFC 9001 §5.8 / RFC 9369 §3.3.3. Debug statements are
//! retained to validate nonce construction when tracing interop failures.
const std = @import("std");
const builtin = @import("builtin");
const ks = @import("quic_tls");
const logger = @import("quic_logger");

// Use Zig std.crypto for AEAD operations (matching vendored ztls approach)
const crypto_impl = @import("crypto_zig.zig");

// Keep Zig std.crypto for Retry Integrity Tag
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;

/// Expand a truncated packet number using the largest received packet number.
/// Based on RFC 9000 Appendix A.3
/// @param truncated: The truncated packet number from the packet header
/// @param pn_len: Length of the truncated packet number in bytes (1-4)
/// @param largest_pn: The largest packet number successfully received and processed (0 if none)
pub fn expandPacketNumber(truncated: u64, pn_len: u3, largest_pn: u64) u64 {
    const pn_nbits: u6 = @as(u6, pn_len) * 8;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;

    // Compute expected_pn as per RFC 9000 Appendix A.3
    // This is the next packet number we expect to receive
    const expected_pn: u64 = largest_pn +% 1;

    // Standard RFC 9000 A.3 algorithm - no special cases
    var candidate: u64 = (expected_pn & ~pn_mask) | truncated;

    // Determine if we need to adjust the candidate
    // Check if candidate is too far in the past
    if (expected_pn >= pn_hwin) {
        if (candidate <= expected_pn - pn_hwin and candidate < (1 << 62)) {
            candidate += pn_win;
        }
    }
    // Check if candidate is too far in the future
    if (candidate > expected_pn + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }

    return candidate;
}

/// Supported AEAD suites for QUIC-TLS binding (re-exported from Zig crypto module).
pub const AeadSuite = crypto_impl.AeadSuite;

/// Result from unprotectInitialAutoSample containing packet number and actual PN length.
pub const UnprotectResult = struct {
    packet_number: u64,
    pn_len: u3, // Actual PN length (1-4) determined from unmasked header
};

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
    // Use Zig std.crypto for AEAD operations (matching vendored ztls)
    return crypto_impl.aeadEncrypt(suite, key, iv, packet_number, aad, plaintext, out);
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
    // Use Zig std.crypto for AEAD operations (matching vendored ztls)
    return crypto_impl.aeadDecrypt(suite, key, iv, packet_number, aad, ciphertext_and_tag, out_plaintext);
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
    // Delegate to Zig crypto implementation (matching vendored ztls)
    return crypto_impl.headerProtect(suite, hp_key, sample16, header_first, pn_bytes);
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
        ks.expandLabel(&retry_secret_v2, "quicv2 key", &[_]u8{}, &key) catch unreachable;
        ks.expandLabel(&retry_secret_v2, "quicv2 iv", &[_]u8{}, &iv) catch unreachable;
    } else {
        ks.expandLabel(&retry_secret_v1, "quic key", &[_]u8{}, &key) catch unreachable;
        ks.expandLabel(&retry_secret_v1, "quic iv", &[_]u8{}, &iv) catch unreachable;
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
    // Log plaintext input at the very start
    logger.debugPrint("protectPacket INPUT: plaintext.len={} out_cipher.len={}\n", .{ plaintext.len, out_cipher.len });
    if (plaintext.len > 0) {
        logger.debugPrint("protectPacket INPUT: plaintext first 30 bytes: ", .{});
        for (plaintext[0..@min(plaintext.len, 30)]) |b| logger.debugPrint("{x:0>2} ", .{b});
        logger.debugPrint("\n", .{});
    }

    // Build AAD: header_first || header_prefix || pn_bytes (pre-HP)
    var aad_stack: [1024]u8 = undefined;
    const aad_len = 1 + header_prefix.len + pn_bytes.len;
    if (aad_len > aad_stack.len) return error.MessageTooLong;
    aad_stack[0] = header_first.*;
    @memcpy(aad_stack[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_stack[1 + header_prefix.len .. aad_len], pn_bytes);
    const aad = aad_stack[0..aad_len];

    // Debug logging for encryption
    logger.debugPrint("protectPacket: pn={} pn_len={} header_prefix_len={} aad_len={}\n", .{ packet_number, pn_bytes.len, header_prefix.len, aad_len });
    logger.debugPrint("protectPacket: header_first=0x{X:0>2}\n", .{header_first.*});
    logger.debugPrint("protectPacket: AAD (first 20 bytes): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{
        aad[0],                           if (aad_len > 1) aad[1] else 0,   if (aad_len > 2) aad[2] else 0,   if (aad_len > 3) aad[3] else 0,
        if (aad_len > 4) aad[4] else 0,   if (aad_len > 5) aad[5] else 0,   if (aad_len > 6) aad[6] else 0,   if (aad_len > 7) aad[7] else 0,
        if (aad_len > 8) aad[8] else 0,   if (aad_len > 9) aad[9] else 0,   if (aad_len > 10) aad[10] else 0, if (aad_len > 11) aad[11] else 0,
        if (aad_len > 12) aad[12] else 0, if (aad_len > 13) aad[13] else 0, if (aad_len > 14) aad[14] else 0, if (aad_len > 15) aad[15] else 0,
        if (aad_len > 16) aad[16] else 0, if (aad_len > 17) aad[17] else 0, if (aad_len > 18) aad[18] else 0, if (aad_len > 19) aad[19] else 0,
    });

    // Compute and log nonce
    var nonce_dbg: [12]u8 = undefined;
    xorNonce(&nonce_dbg, aead_iv, packet_number);
    logger.debugPrint("protectPacket: Nonce: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{
        nonce_dbg[0], nonce_dbg[1], nonce_dbg[2], nonce_dbg[3], nonce_dbg[4],  nonce_dbg[5],
        nonce_dbg[6], nonce_dbg[7], nonce_dbg[8], nonce_dbg[9], nonce_dbg[10], nonce_dbg[11],
    });

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
    // Debug: Only print for very small plaintexts
    if (plaintext.len < 100) {
        logger.debugPrint("protectPacket WARNING: small plaintext.len={}, ct_len={}\n", .{ plaintext.len, ct_len });
    }

    // Build HP sample per RFC 9001:
    // - AES: 16 bytes starting 4 bytes after start of PN -> relative to ciphertext (which starts after PN), offset = 4 - pn_len
    // - ChaCha: 16 bytes starting at start of PN -> compose from PN bytes + first (16 - pn_len) bytes of ciphertext
    if (ct_len < 16) {
        return error.AuthenticationFailed;
    }
    var sample16: [16]u8 = undefined;
    const pn_len: usize = pn_bytes.len;
    switch (suite) {
        .aes_128_gcm, .aes_256_gcm => {
            // RFC 9001 §5.4.3: Sample starts 4 bytes after the start of packet number field
            // The out_cipher buffer contains only encrypted payload (no PN bytes)
            // For 2-byte PN: sample at packet bytes 4-19 = ciphertext bytes 2-17 = offset (4-2)
            // General formula: offset into ciphertext = 4 - pn_len
            const sample_offset: usize = if (pn_len >= 4) 0 else (4 - pn_len);
            if (sample_offset + 16 > out_cipher.len) {
                // This error means the plaintext is too short for header protection
                // Need at least (4 - pn_len) + 16 bytes of ciphertext
                return error.AuthenticationFailed;
            }
            @memcpy(sample16[0..], out_cipher[sample_offset .. sample_offset + 16]);
        },
        .chacha20_poly1305 => {
            if (pn_len > 4) return error.InvalidPacketNumberLength;
            if ((16 - pn_len) > out_cipher.len) {
                return error.AuthenticationFailed;
            }
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
/// largest_pn is the largest packet number successfully received (0 if none).
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
    largest_pn: u64, // Largest packet number successfully received (0 if none)
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

    logger.debugPrint("Packet number extraction: pn_bytes={any}, pn_val_truncated={}, largest_pn={}\n", .{ pn_bytes, pn_val_truncated, largest_pn });

    // Expand the truncated packet number per RFC 9000 Appendix A.3
    const pn_val = expandPacketNumber(pn_val_truncated, @intCast(pn_bytes.len), largest_pn);

    logger.debugPrint("Expanded packet number: {} (from truncated {} with largest_pn {})\n", .{ pn_val, pn_val_truncated, largest_pn });

    if (largest_pn == 0) {
        logger.debugPrint("First packet: truncated={x:0>4} ({}) -> expanded={}\n", .{ pn_val_truncated, pn_val_truncated, pn_val });
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
        logger.debugPrint("AEAD decrypt failed: {} (pn={})\n", .{ err, pn_val });
        return err;
    };
}

/// Decrypt a QUIC packet when header protection has ALREADY been removed.
/// Used by short header decryption path which unmasks header+PN before calling this.
/// Skips the headerUnprotect step that unprotectInitial performs.
pub fn unprotectInitialNoUnmask(
    suite: AeadSuite,
    aead_key: []const u8,
    aead_iv: []const u8,
    header_first: *const u8, // Already unmasked
    pn_bytes: []const u8, // Already unmasked
    header_prefix: []const u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
    largest_pn: u64,
) !usize {
    if (ciphertext_and_tag.len < 16) return error.AuthenticationFailed;

    // AAD constructed with already-unprotected header_first and pn_bytes
    var aad_stack: [1024]u8 = undefined;
    const aad_len = 1 + header_prefix.len + pn_bytes.len;
    if (aad_len > aad_stack.len) return error.MessageTooLong;
    aad_stack[0] = header_first.*;
    @memcpy(aad_stack[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_stack[1 + header_prefix.len .. aad_len], pn_bytes);
    const aad = aad_stack[0..aad_len];

    // Derive packet_number from unmasked pn_bytes (big-endian truncated)
    var pn_val_truncated: u64 = 0;
    var i: usize = 0;
    while (i < pn_bytes.len) : (i += 1) pn_val_truncated = (pn_val_truncated << 8) | pn_bytes[i];

    // logger.debugPrint("Packet number extraction (no-unmask): pn_bytes={any}, pn_val_truncated={}, largest_pn={}\n", .{ pn_bytes, pn_val_truncated, largest_pn });

    // Expand the truncated packet number per RFC 9000 Appendix A.3
    const pn_val = expandPacketNumber(pn_val_truncated, @intCast(pn_bytes.len), largest_pn);

    // logger.debugPrint("Expanded packet number (no-unmask): {} (from truncated {} with largest_pn {})\n", .{ pn_val, pn_val_truncated, largest_pn });

    // if (largest_pn == 0) {
    //     logger.debugPrint("First 1-RTT packet: truncated={x:0>4} ({}) -> expanded={}\n", .{ pn_val_truncated, pn_val_truncated, pn_val });
    // }

    return aeadDecrypt(suite, aead_key, aead_iv, pn_val, aad, ciphertext_and_tag, out_plaintext) catch |err| {
        // Only log for specific packet numbers that seem real
        if (pn_val > 0 and pn_val < 1000) {
            logger.debugPrint("AEAD decrypt failed: pn={} err={}\n", .{ pn_val, err });
        }
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
    largest_pn: u64,
) !UnprotectResult {
    if (ciphertext_and_tag.len < 16) return error.AuthenticationFailed;
    const pn_len = pn_bytes.len;
    if (pn_len == 0 or pn_len > 4) return error.InvalidPacketNumberLength;

    // IMPORTANT: The ciphertext_and_tag buffer starts at the packet number field.
    // The first pn_len bytes are the masked packet number bytes.
    // pn_bytes is already initialized by the caller with the masked PN bytes.
    // DO NOT overwrite pn_bytes here - it's already set correctly by the caller.

    // Reconstruct HP sample per suite
    // ciphertext_and_tag parameter starts at PN field beginning (includes PN bytes + encrypted payload + tag)
    var sample16: [16]u8 = undefined;

    // Commented out verbose debug output
    // const debug_len = @min(32, ciphertext_and_tag.len);
    // var hex_buf: [96]u8 = undefined; // 32 bytes * 3 chars per byte (2 hex + 1 space)
    // var hex_stream = std.io.fixedBufferStream(&hex_buf);
    // const hex_writer = hex_stream.writer();
    // for (ciphertext_and_tag[0..debug_len]) |b| {
    //     _ = hex_writer.print("{X:0>2} ", .{b}) catch break;
    // }
    // const hex_str = hex_stream.getWritten();
    // logger.debugPrint("Header protection removal - first {} bytes of ciphertext_and_tag: {s}\n", .{ debug_len, hex_str });
    // logger.debugPrint("  pn_len={}, ciphertext_and_tag.len={}, largest_pn={}\n", .{ pn_len, ciphertext_and_tag.len, largest_pn });

    // // Debug: Show the masked packet number bytes
    // var pn_hex_buf: [12]u8 = undefined; // 4 bytes max * 3 chars
    // var pn_hex_stream = std.io.fixedBufferStream(&pn_hex_buf);
    // const pn_hex_writer = pn_hex_stream.writer();
    // for (pn_bytes[0..pn_len]) |b| {
    //     _ = pn_hex_writer.print("{X:0>2} ", .{b}) catch break;
    // }
    // const pn_hex_str = pn_hex_stream.getWritten();
    // logger.debugPrint("  Masked PN bytes before unmasking: {s}\n", .{pn_hex_str});

    switch (suite) {
        .aes_128_gcm, .aes_256_gcm => {
            // RFC 9001 §5.4.2: Sample starts 4 bytes after PN field start, always 16 bytes.
            // Buffer layout: [PN bytes (pn_len)] [encrypted payload...] [16-byte tag]
            // Sample position: Always at offset 4 from the start of the Packet Number field
            const sample_offset: usize = 4;
            if (sample_offset + 16 > ciphertext_and_tag.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..], ciphertext_and_tag[sample_offset .. sample_offset + 16]);
        },
        .chacha20_poly1305 => {
            // For ChaCha20, sample is PN bytes (masked) followed by first (16 - pn_len) bytes of ciphertext
            // Buffer layout: [PN bytes (pn_len)] [encrypted payload...] [16-byte tag]
            if (pn_len + (16 - pn_len) > ciphertext_and_tag.len) return error.AuthenticationFailed;
            @memcpy(sample16[0..pn_len], pn_bytes);
            @memcpy(sample16[pn_len..], ciphertext_and_tag[pn_len .. pn_len + (16 - pn_len)]);
        },
    }

    // Remove header protection in-place (mutates header_first & pn_bytes) using derived sample
    try headerUnprotect(suite, hp_key, &sample16, header_first, pn_bytes);

    // Extract actual PN length from unmasked header byte
    // RFC 9000 §17.1: Packet Number Length is encoded in bits 0-1 of the first byte
    // For both long and short headers: pn_len = (first_byte & 0x03) + 1
    const actual_pn_len: usize = @intCast((header_first.* & 0x03) + 1);

    // Phase 33: Caller now always passes full 4-byte buffer, so no validation needed
    // The actual PN length is determined from the unmasked header byte

    // Build AAD after unmasking: first byte + header_prefix + pn_bytes (using actual length)
    var aad_stack: [1024]u8 = undefined;
    const aad_len = 1 + header_prefix.len + actual_pn_len;
    if (aad_len > aad_stack.len) return error.MessageTooLong;
    aad_stack[0] = header_first.*;
    @memcpy(aad_stack[1 .. 1 + header_prefix.len], header_prefix);
    @memcpy(aad_stack[1 + header_prefix.len .. aad_len], pn_bytes[0..actual_pn_len]);
    const aad = aad_stack[0..aad_len];

    // Expand truncated PN for nonce derivation (use actual PN length)
    var pn_trunc: u64 = 0;
    var i: usize = 0;
    while (i < actual_pn_len) : (i += 1) pn_trunc = (pn_trunc << 8) | pn_bytes[i];

    logger.debugPrint("[unprotectInitial] PN bytes after unmasking: ", .{});
    var j: usize = 0;
    while (j < actual_pn_len) : (j += 1) {
        logger.debugPrint("{X:0>2} ", .{pn_bytes[j]});
    }
    logger.debugPrint("\n", .{});
    logger.debugPrint("[unprotectInitial] truncated={} actual_pn_len={} largest_pn={}\n", .{ pn_trunc, actual_pn_len, largest_pn });

    // ciphertext_and_tag buffer layout: [PN bytes (actual_pn_len)] [encrypted payload + tag]
    // Pass only the encrypted payload + tag portion to AEAD decrypt (skip the PN bytes)
    const actual_ciphertext = ciphertext_and_tag[actual_pn_len..];
    const base_pn = expandPacketNumber(pn_trunc, @intCast(actual_pn_len), largest_pn);
    const pn_nbits: u6 = @as(u6, @intCast(actual_pn_len)) * 8;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;

    // RFC 9000 A.3 packet number reconstruction can be ambiguous when no packets
    // have been successfully authenticated yet (largest_pn == 0). Some peers can
    // start with large Initial packet numbers, so probe nearby reconstruction
    // candidates in that first-packet case.
    var pn_candidates: [4]u64 = undefined;
    var candidate_count: usize = 0;
    pn_candidates[candidate_count] = base_pn;
    candidate_count += 1;
    if (largest_pn == 0 and actual_pn_len < 4) {
        var k: u64 = 1;
        while (candidate_count < pn_candidates.len and k < 4) : (k += 1) {
            const delta = k * pn_win;
            if (delta > (std.math.maxInt(u64) - base_pn)) break;
            const next = base_pn + delta;
            if (next >= (1 << 62)) break;
            pn_candidates[candidate_count] = next;
            candidate_count += 1;
        }
    }

    var chosen_pn: ?u64 = null;
    var last_err: anyerror = error.AuthenticationFailed;
    var ci: usize = 0;
    while (ci < candidate_count) : (ci += 1) {
        const full_pn = pn_candidates[ci];
        if (full_pn >= 80 or largest_pn >= 80) {
            var nonce_preview: [12]u8 = undefined;
            xorNonce(&nonce_preview, aead_iv, full_pn);
            logger.debugPrint("[PHASE57-NONCE] pn={} nonce=", .{full_pn});
            var nidx: usize = 0;
            while (nidx < nonce_preview.len) : (nidx += 1) {
                logger.debugPrint("{X:0>2}", .{nonce_preview[nidx]});
            }
            logger.debugPrint(" aad_len={} header_first=0x{X:0>2}\n", .{ aad.len, header_first.* });
            const aad_preview_len = @min(aad.len, 64);
            logger.debugPrint("[PHASE57-AAD] pn={} aad_prefix=", .{full_pn});
            var aidx: usize = 0;
            while (aidx < aad_preview_len) : (aidx += 1) {
                logger.debugPrint("{X:0>2}", .{aad[aidx]});
            }
            if (aad_preview_len < aad.len) {
                logger.debugPrint("...", .{});
            }
            logger.debugPrint("\n", .{});
        }

        _ = aeadDecrypt(suite, aead_key, aead_iv, full_pn, aad, actual_ciphertext, out_plaintext) catch |err| {
            last_err = err;
            // Only print for non-zero packet numbers (likely real failures, not probing)
            if (full_pn > 0 and full_pn < 1000) {
                logger.debugPrint("AEAD decrypt failed: pn={} err={}\n", .{ full_pn, err });
            }
            continue;
        };

        chosen_pn = full_pn;
        break;
    }

    const full_pn = chosen_pn orelse return last_err;
    logger.debugPrint("[unprotectInitial] expanded to full_pn={}\n", .{full_pn});

    // Return the expanded packet number and actual PN length
    return UnprotectResult{
        .packet_number = full_pn,
        .pn_len = @intCast(actual_pn_len),
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
    // logger.debugPrint("HP key: ", .{});
    // for (hp_key) |b| logger.debugPrint("{X:0>2}\n", .{b});
    // logger.debugPrint("", .{});

    var out_block: [16]u8 = undefined;
    switch (suite) {
        .aes_128_gcm, .aes_256_gcm => {
            // Both AES-128-GCM and AES-256-GCM use AES-128-ECB for header protection (RFC 9001 §5.4.3)
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

    logger.debugPrint("HP mask (first 5 bytes): ", .{});
    for (out_block[0..5]) |b| logger.debugPrint("{X:0>2}\n", .{b});
    logger.debugPrint("", .{});

    const is_long = (header_first.* & 0x80) != 0;
    const hdr_mask: u8 = if (is_long) 0x0f else 0x1f;
    logger.debugPrint("is_long={}, hdr_mask={X:0>2}, header_first_before={X:0>2}\n", .{ is_long, hdr_mask, header_first.* });

    header_first.* ^= (out_block[0] & hdr_mask);
    logger.debugPrint("header_first_after={X:0>2}\n", .{header_first.*});

    const pn_len: u3 = @as(u3, @intCast((header_first.* & 0x03))) + 1;
    logger.debugPrint("Decoded pn_len from header: {}\n", .{pn_len});

    logger.debugPrint("pn_buf before unmasking: {any}\n", .{pn_buf.*});
    // Constant-time-ish: always xor 4 bytes to avoid data-dependent timing; callers will slice by pn_len.
    var i: usize = 0;
    while (i < 4) : (i += 1) pn_buf.*[i] ^= out_block[i + 1];
    logger.debugPrint("pn_buf after unmasking: {any}, using pn_len={}\n", .{ pn_buf.*, pn_len });
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
    logger.debugPrint("{s}: {s}\n", .{ label, list.items });
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
