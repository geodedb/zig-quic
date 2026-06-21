// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const crypto = @import("quic_crypto"); // crypto_quic.zig re-exports crypto_zig fns
const backend = @import("crypto_backend");
const parallel = @import("parallel");

test "AES-256-GCM round-trips via the seam in both modes" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x01} ** 12;
    const aad = "quic-header";
    const pt = "the quick brown fox";
    var ct: [pt.len + 16]u8 = undefined;
    const ct_len = try crypto.aeadEncrypt(.aes_256_gcm, &key, &iv, 0xABCD, aad, pt, &ct);
    var dec: [pt.len]u8 = undefined;
    const pt_len = try crypto.aeadDecrypt(.aes_256_gcm, &key, &iv, 0xABCD, aad, ct[0..ct_len], &dec);
    try std.testing.expectEqualSlices(u8, pt, dec[0..pt_len]);
}

test "AES-128-GCM round-trips via the seam in both modes" {
    const key = [_]u8{0x42} ** 16;
    const iv = [_]u8{0x01} ** 12;
    const aad = "quic-header";
    const pt = "the quick brown fox";
    var ct: [pt.len + 16]u8 = undefined;
    const ct_len = try crypto.aeadEncrypt(.aes_128_gcm, &key, &iv, 0xABCD, aad, pt, &ct);
    var dec: [pt.len]u8 = undefined;
    const pt_len = try crypto.aeadDecrypt(.aes_128_gcm, &key, &iv, 0xABCD, aad, ct[0..ct_len], &dec);
    try std.testing.expectEqualSlices(u8, pt, dec[0..pt_len]);
}

test "ChaCha20-Poly1305 is rejected under fips, allowed otherwise" {
    const key = [_]u8{0x11} ** 32;
    const iv = [_]u8{0x22} ** 12;
    const pt = "hi";
    var ct: [pt.len + 16]u8 = undefined;
    const res = crypto.aeadEncrypt(.chacha20_poly1305, &key, &iv, 0, "", pt, &ct);
    if (backend.fips_enabled) {
        try std.testing.expectError(error.Unsupported, res);
    } else {
        _ = try res; // std build: ChaCha20-Poly1305 still works
    }
}

test "parallel AES header mask matches single-shot AES mask (both modes)" {
    const hp_key = [_]u8{0x77} ** 32;
    const sample = [_]u8{0x33} ** 16;
    const mask = parallel.generateHeaderMaskForTest(.aes_256_gcm, &hp_key, sample);
    // AES-256-ECB of the sample, first 5 bytes.
    const aes = std.crypto.core.aes.Aes256.initEnc(hp_key);
    var block: [16]u8 = undefined;
    aes.encrypt(&block, &sample);
    try std.testing.expectEqualSlices(u8, block[0..5], &mask);
}

test "ChaCha header mask: computed when fips off, gated by AEAD seam when fips on" {
    const hp_key = [_]u8{0x55} ** 32;
    const sample = [_]u8{0x66} ** 16;
    if (backend.fips_enabled) {
        // The parallel ChaCha HP arm is `comptime unreachable` under fips,
        // so it is never called with a ChaCha suite. Pin the actual gate:
        // the AEAD seam rejects ChaCha BEFORE any header mask is computed,
        // which is exactly why generateHeaderMask is never reached for it.
        const key = [_]u8{0x11} ** 32;
        const iv = [_]u8{0x22} ** 12;
        var ct: [2 + 16]u8 = undefined;
        try std.testing.expectError(
            error.Unsupported,
            crypto.aeadEncrypt(.chacha20_poly1305, &key, &iv, 0, "", "hi", &ct),
        );
    } else {
        // Non-fips: the ChaCha arm computes a real, non-zero mask.
        const mask = parallel.generateHeaderMaskForTest(.chacha20_poly1305, &hp_key, sample);
        try std.testing.expect(!std.mem.eql(u8, &mask, &[_]u8{0} ** 5));
    }
}
