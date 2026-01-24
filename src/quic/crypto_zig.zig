// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! AEAD cipher operations using Zig standard library crypto
//!
//! This module provides AEAD encryption/decryption using pure Zig std.crypto
//! implementations, matching the vendored ztls approach. No external dependencies.
//!
//! Supports:
//! - AES-128-GCM
//! - AES-256-GCM
//! - ChaCha20-Poly1305
//!
//! All operations follow RFC 5116 AEAD interface with 96-bit nonces and 128-bit tags.

const std = @import("std");
const crypto = std.crypto;

const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = crypto.stream.chacha.ChaCha20IETF;

/// Supported AEAD cipher suites for QUIC packet protection (RFC 9001 §5.3).
pub const AeadSuite = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    /// Get the key length in bytes for this cipher suite.
    pub fn keyLen(self: AeadSuite) usize {
        return switch (self) {
            .aes_128_gcm => 16, // 128-bit key
            .aes_256_gcm => 32, // 256-bit key
            .chacha20_poly1305 => 32, // 256-bit key
        };
    }

    /// Get the tag length in bytes for this cipher suite.
    /// All supported AEAD ciphers use 128-bit (16-byte) tags per RFC 5116.
    pub fn tagLen(_: AeadSuite) usize {
        return 16;
    }

    /// Get the nonce/IV length in bytes for this cipher suite.
    /// All supported AEAD ciphers use 96-bit (12-byte) nonces per RFC 5116.
    pub fn nonceLen(_: AeadSuite) usize {
        return 12;
    }
};

/// Encrypt plaintext with AEAD using the specified cipher suite.
///
/// The nonce is constructed by XORing the IV with the packet number (RFC 9001 §5.3):
/// `nonce = iv XOR packet_number` (packet_number left-padded with zeros to IV length)
///
/// Parameters:
/// - suite: The AEAD cipher suite to use
/// - key: The encryption key (length must match suite.keyLen())
/// - iv: The initialization vector (12 bytes)
/// - packet_number: QUIC packet number used for nonce derivation
/// - aad: Additional authenticated data (packet header)
/// - plaintext: Data to encrypt
/// - out_ciphertext_and_tag: Output buffer (must have capacity plaintext.len + 16)
///
/// Returns: Length of ciphertext + tag written to output buffer
pub fn aeadEncrypt(
    suite: AeadSuite,
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    plaintext: []const u8,
    out_ciphertext_and_tag: []u8,
) !usize {
    // Construct nonce: iv XOR packet_number (RFC 9001 §5.3)
    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, iv[0..12]);

    // XOR packet number into the last 8 bytes of nonce (big-endian)
    var pn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_bytes, packet_number, .big);
    for (pn_bytes, 0..) |b, i| {
        nonce[4 + i] ^= b;
    }

    const ct_len = plaintext.len;
    const tag_len = suite.tagLen();

    if (out_ciphertext_and_tag.len < ct_len + tag_len) {
        return error.OutputBufferTooSmall;
    }

    switch (suite) {
        .aes_128_gcm => {
            if (key.len != 16) return error.InvalidKeyLength;
            Aes128Gcm.encrypt(
                out_ciphertext_and_tag[0..ct_len],
                out_ciphertext_and_tag[ct_len..][0..16],
                plaintext,
                aad,
                nonce,
                key[0..16].*,
            );
            return ct_len + 16;
        },
        .aes_256_gcm => {
            if (key.len != 32) return error.InvalidKeyLength;
            Aes256Gcm.encrypt(
                out_ciphertext_and_tag[0..ct_len],
                out_ciphertext_and_tag[ct_len..][0..16],
                plaintext,
                aad,
                nonce,
                key[0..32].*,
            );
            return ct_len + 16;
        },
        .chacha20_poly1305 => {
            if (key.len != 32) return error.InvalidKeyLength;
            ChaCha20Poly1305.encrypt(
                out_ciphertext_and_tag[0..ct_len],
                out_ciphertext_and_tag[ct_len..][0..16],
                plaintext,
                aad,
                nonce,
                key[0..32].*,
            );
            return ct_len + 16;
        },
    }
}

/// Decrypt ciphertext with AEAD using the specified cipher suite.
///
/// The nonce is constructed by XORing the IV with the packet number (RFC 9001 §5.3):
/// `nonce = iv XOR packet_number` (packet_number left-padded with zeros to IV length)
///
/// Parameters:
/// - suite: The AEAD cipher suite to use
/// - key: The decryption key (length must match suite.keyLen())
/// - iv: The initialization vector (12 bytes)
/// - packet_number: QUIC packet number used for nonce derivation
/// - aad: Additional authenticated data (packet header)
/// - ciphertext_and_tag: Encrypted data + authentication tag
/// - out_plaintext: Output buffer for decrypted data
///
/// Returns: Length of plaintext written to output buffer
/// Errors: AuthenticationFailed if tag verification fails
pub fn aeadDecrypt(
    suite: AeadSuite,
    key: []const u8,
    iv: []const u8,
    packet_number: u64,
    aad: []const u8,
    ciphertext_and_tag: []const u8,
    out_plaintext: []u8,
) !usize {
    const tag_len = suite.tagLen();
    if (ciphertext_and_tag.len < tag_len) {
        return error.CiphertextTooShort;
    }

    const ct_len = ciphertext_and_tag.len - tag_len;
    if (out_plaintext.len < ct_len) {
        return error.OutputBufferTooSmall;
    }

    // Construct nonce: iv XOR packet_number (RFC 9001 §5.3)
    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, iv[0..12]);

    // XOR packet number into the last 8 bytes of nonce (big-endian)
    var pn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_bytes, packet_number, .big);
    for (pn_bytes, 0..) |b, i| {
        nonce[4 + i] ^= b;
    }

    const ciphertext = ciphertext_and_tag[0..ct_len];
    const tag = ciphertext_and_tag[ct_len..][0..16];

    switch (suite) {
        .aes_128_gcm => {
            if (key.len != 16) return error.InvalidKeyLength;
            Aes128Gcm.decrypt(
                out_plaintext[0..ct_len],
                ciphertext,
                tag.*,
                aad,
                nonce,
                key[0..16].*,
            ) catch {
                return error.AuthenticationFailed;
            };
            return ct_len;
        },
        .aes_256_gcm => {
            if (key.len != 32) return error.InvalidKeyLength;
            Aes256Gcm.decrypt(
                out_plaintext[0..ct_len],
                ciphertext,
                tag.*,
                aad,
                nonce,
                key[0..32].*,
            ) catch {
                return error.AuthenticationFailed;
            };
            return ct_len;
        },
        .chacha20_poly1305 => {
            if (key.len != 32) return error.InvalidKeyLength;
            ChaCha20Poly1305.decrypt(
                out_plaintext[0..ct_len],
                ciphertext,
                tag.*,
                aad,
                nonce,
                key[0..32].*,
            ) catch {
                return error.AuthenticationFailed;
            };
            return ct_len;
        },
    }
}

/// Apply header protection mask to packet header (RFC 9001 §5.4).
///
/// For AES-based ciphers, uses AES-ECB with the first 16 bytes of the sample.
/// For ChaCha20-Poly1305, uses ChaCha20 with the sample as counter and nonce.
///
/// Parameters:
/// - suite: The cipher suite (determines HP algorithm)
/// - hp_key: Header protection key
/// - sample: 16-byte sample from packet payload
/// - header_first: First byte of packet header (modified in place)
/// - pn_bytes: Packet number bytes (modified in place)
pub fn headerProtect(
    suite: AeadSuite,
    hp_key: []const u8,
    sample: *const [16]u8,
    header_first: *u8,
    pn_bytes: []u8,
) !void {
    switch (suite) {
        .aes_128_gcm => {
            if (hp_key.len != 16) return error.InvalidKeyLength;
            // AES-128-ECB: encrypt the 16-byte sample
            const Aes128 = crypto.core.aes.Aes128;
            const aes = Aes128.initEnc(hp_key[0..16].*);
            var mask: [16]u8 = undefined;
            aes.encrypt(&mask, sample);

            // Apply mask to header (RFC 9001 §5.4.1)
            const long_header = (header_first.* & 0x80) != 0;
            if (long_header) {
                header_first.* ^= mask[0] & 0x0f; // Mask lower 4 bits for long header
            } else {
                header_first.* ^= mask[0] & 0x1f; // Mask lower 5 bits for short header
            }

            // Apply mask to packet number bytes
            for (pn_bytes, 0..) |*b, i| {
                b.* ^= mask[1 + i];
            }
        },
        .aes_256_gcm => {
            if (hp_key.len != 32) return error.InvalidKeyLength;
            // AES-256-ECB: encrypt the 16-byte sample
            const Aes256 = crypto.core.aes.Aes256;
            const aes = Aes256.initEnc(hp_key[0..32].*);
            var mask: [16]u8 = undefined;
            aes.encrypt(&mask, sample);

            // Apply mask to header
            const long_header = (header_first.* & 0x80) != 0;
            if (long_header) {
                header_first.* ^= mask[0] & 0x0f;
            } else {
                header_first.* ^= mask[0] & 0x1f;
            }

            // Apply mask to packet number bytes
            for (pn_bytes, 0..) |*b, i| {
                b.* ^= mask[1 + i];
            }
        },
        .chacha20_poly1305 => {
            if (hp_key.len != 32) return error.InvalidKeyLength;
            // ChaCha20 HP (RFC 9001 §5.4.4)
            // Use sample as counter(4) + nonce(12): counter=bytes[0..4], nonce=bytes[4..16]
            const counter: u32 = std.mem.readInt(u32, sample[0..4], .little);
            var nonce: [12]u8 = undefined;
            @memcpy(&nonce, sample[4..16]);

            // Generate mask by encrypting zeros
            var mask: [5]u8 = [_]u8{0} ** 5;
            ChaCha20IETF.xor(&mask, &mask, counter, hp_key[0..32].*, nonce);

            // Apply mask to header
            const long_header = (header_first.* & 0x80) != 0;
            if (long_header) {
                header_first.* ^= mask[0] & 0x0f;
            } else {
                header_first.* ^= mask[0] & 0x1f;
            }

            // Apply mask to packet number bytes
            for (pn_bytes, 0..) |*b, i| {
                b.* ^= mask[1 + i];
            }
        },
    }
}

/// Remove header protection from packet header (RFC 9001 §5.4).
///
/// This is the inverse of headerProtect().
pub fn headerUnprotect(
    suite: AeadSuite,
    hp_key: []const u8,
    sample: *const [16]u8,
    header_first: *u8,
    pn_bytes: []u8,
) !void {
    // Header unprotection is the same as protection (XOR is self-inverse)
    return headerProtect(suite, hp_key, sample, header_first, pn_bytes);
}
