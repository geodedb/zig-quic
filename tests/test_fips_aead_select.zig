// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const crypto = @import("quic_crypto"); // crypto_quic.zig re-exports crypto_zig fns
const backend = @import("crypto_backend");

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
