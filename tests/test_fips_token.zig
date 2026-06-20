// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Pins the address-validation token HMAC across the crypto_backend seam swap.
// The token module computes HMAC-SHA256 via crypto_backend.Mac in both
// -Dfips modes; this test asserts the round-trip / tamper / wrong-secret
// behavior is byte-identical regardless of backend.
const std = @import("std");
const token = @import("quic_token");

test "token encode/verify round-trips through the crypto_backend seam" {
    const a = std.testing.allocator;
    const secret = "fips-token-secret-0123456789abcd";
    const ip = [_]u8{ 192, 0, 2, 7 };
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    const tok = try token.encode(a, &ip, &dcid, secret, 60_000);
    defer a.free(tok);

    // Current time in ms since epoch (token is valid for 60s).
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    const now_ms: u64 = @intCast(@divTrunc(@as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec), std.time.ns_per_ms));

    // Valid token: dcid round-trips through the seam HMAC.
    var dcid_buf: [20]u8 = undefined;
    const got = token.verifyAndExtractDcid(tok, &ip, secret, now_ms, &dcid_buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &dcid, got);

    // Wrong secret must reject.
    try std.testing.expect(!token.verify(tok, &ip, "wrong-secret-zzzzzzzzzzzzzzzzzzz", now_ms));

    // Tamper one HMAC byte -> reject.
    var bad = try a.dupe(u8, tok);
    defer a.free(bad);
    bad[bad.len - 1] ^= 0x01;
    try std.testing.expect(!token.verify(bad, &ip, secret, now_ms));
}
