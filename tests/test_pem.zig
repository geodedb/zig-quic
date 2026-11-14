// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (v0.1.51 follow-up): PEM parsing leaked the DER output
// buffer when the base64 did not decode, and freed the base64 scratch copy
// of private keys without zeroing it.

const std = @import("std");
const testing = std.testing;
const pem = @import("quic_api").pem;

const bad_body = "\nMHcCAQEE!!!!not-base64!!!!\n";

test "malformed base64 in a certificate is an error, with nothing leaked" {
    const data = "-----BEGIN CERTIFICATE-----" ++ bad_body ++ "-----END CERTIFICATE-----\n";
    try testing.expect(std.meta.isError(pem.parseCertificate(testing.allocator, data)));
}

test "malformed base64 in an EC key is an error, with nothing leaked" {
    const data = "-----BEGIN EC PRIVATE KEY-----" ++ bad_body ++ "-----END EC PRIVATE KEY-----\n";
    try testing.expect(std.meta.isError(pem.parseECPrivateKey(testing.allocator, data)));
}

test "malformed base64 in RSA and PKCS#8 keys is an error, with nothing leaked" {
    const rsa = "-----BEGIN RSA PRIVATE KEY-----" ++ bad_body ++ "-----END RSA PRIVATE KEY-----\n";
    const p8 = "-----BEGIN PRIVATE KEY-----" ++ bad_body ++ "-----END PRIVATE KEY-----\n";
    try testing.expect(std.meta.isError(pem.parseRSAPrivateKey(testing.allocator, rsa)));
    try testing.expect(std.meta.isError(pem.parseRSAPrivateKey(testing.allocator, p8)));
    try testing.expect(std.meta.isError(pem.parsePrivateKey(testing.allocator, p8)));
}

test "key parsing leaves no key material in memory it frees, valid or malformed" {
    // Back the parser with a buffer the test owns and scan it afterwards.
    // (In Debug and ReleaseSafe std.mem.Allocator.free overwrites freed
    // memory itself, so this catches a missing wipe in ReleaseFast and
    // ReleaseSmall, where it does not.)
    var region: [64 * 1024]u8 = @splat(0);
    var fba = std.heap.FixedBufferAllocator.init(&region);
    const a = fba.allocator();
    // base64 of "ABCDEFGHIJKLMNOPQRSTUVWX", repeated so the scratch copy is long.
    const line = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY";
    const good = "-----BEGIN EC PRIVATE KEY-----\n" ++ ((line ++ "\n") ** 8) ++ "-----END EC PRIVATE KEY-----\n";
    const bad = "-----BEGIN EC PRIVATE KEY-----\n" ++ ((line ++ "\n") ** 8) ++ "!!!!\n-----END EC PRIVATE KEY-----\n";

    try testing.expect(std.meta.isError(pem.parseECPrivateKey(a, bad)));
    try testing.expect(std.meta.isError(pem.parsePrivateKey(a, "-----BEGIN PRIVATE KEY-----\n" ++ line ++ "!!!!\n-----END PRIVATE KEY-----\n")));
    const key = try pem.parseECPrivateKey(a, good);
    try testing.expectEqualStrings("ABCDEFGHIJKLMNOPQRSTUVWX", key[0..24]);

    // Outside the returned key, neither the base64 text nor the decoded
    // key bytes may remain anywhere in the memory the parser used.
    const key_lo = @intFromPtr(key.ptr) - @intFromPtr(&region);
    const key_hi = key_lo + key.len;
    for ([_][]const u8{ line, "ABCDEFGHIJKLMNOPQRSTUVWX" }) |needle| {
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, &region, from, needle)) |at| : (from = at + 1) {
            const inside_key = at >= key_lo and at + needle.len <= key_hi;
            if (!inside_key) {
                std.debug.print("key material {s} left at offset {d}\n", .{ needle, at });
                return error.TestUnexpectedResult;
            }
        }
    }
}
