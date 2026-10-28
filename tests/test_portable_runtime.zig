// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros
const std = @import("std");
const compat = @import("compat");
const shim = @import("std_shim");
const sharding = @import("sharding");

test "portable runtime clocks preserve the Unix epoch and millisecond units" {
    const before = std.Io.Clock.real.now(std.testing.io).nanoseconds;
    const ns = compat.nanoTimestamp();
    const ms = compat.milliTimestamp();
    const after = std.Io.Clock.real.now(std.testing.io).nanoseconds;
    try std.testing.expect(ns >= before);
    try std.testing.expect(ns <= after);
    try std.testing.expect(ms >= @divTrunc(before, std.time.ns_per_ms));
    try std.testing.expect(ms <= @divTrunc(after, std.time.ns_per_ms));
}

test "portable runtime sleep advances the monotonic clock" {
    const before = compat.monotonicNanoTimestamp();
    const duration = 5 * std.time.ns_per_ms;
    compat.threadSleep(duration);
    const after = compat.monotonicNanoTimestamp();
    try std.testing.expect(before > 0);
    try std.testing.expect(after - before >= duration);
}

test "portable runtime entropy fills independent nonzero buffers" {
    var a: [32]u8 = @splat(0);
    var b: [32]u8 = @splat(0);
    var c: [32]u8 = @splat(0);
    const zero: [32]u8 = @splat(0);
    try compat.secureRandomBytes(&a);
    try compat.secureRandomBytes(&b);
    try shim.Csprng.bytes(&c);
    try std.testing.expect(!std.mem.eql(u8, &a, &zero));
    try std.testing.expect(!std.mem.eql(u8, &b, &zero));
    try std.testing.expect(!std.mem.eql(u8, &c, &zero));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
    try compat.secureRandomBytes(a[0..0]);
    try shim.Csprng.bytes(c[0..0]);
}

test "portable runtime key generation signs and verifies with OS entropy" {
    var key = try shim.Sig.generate(.ed25519);
    defer key.deinit();
    const message = "portable QUIC runtime";
    var signature: [64]u8 = undefined;
    const n = try shim.Sig.sign(.ed25519, &key, message, &signature);
    try shim.Sig.verify(.ed25519, &key, message, signature[0..n]);
    try std.testing.expectError(error.VerifyFailed, shim.Sig.verify(.ed25519, &key, "tampered", signature[0..n]));
}

test "portable runtime sharder seeds come from OS entropy" {
    const first = try sharding.Sharder.init(8);
    const second = try sharding.Sharder.init(8);
    try std.testing.expect(first.seed != 0);
    try std.testing.expect(first.seed != second.seed);
    try std.testing.expect(first.chooseLoop("connection") < 8);
    try std.testing.expectError(error.InvalidShardCount, sharding.Sharder.init(0));
}
