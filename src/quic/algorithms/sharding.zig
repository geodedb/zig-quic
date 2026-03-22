// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection-to-shard mapping using seeded hash for DoS resistance.

const std = @import("std");

pub const ShardError = error{InvalidShardCount};

fn seededHash(bytes: []const u8, seed: u64) u64 {
    return std.hash.Wyhash.hash(seed, bytes);
}

pub const Sharder = struct {
    seed: u64,
    shard_count: u32,

    pub fn init(shard_count: u32) ShardError!Sharder {
        if (shard_count == 0) return ShardError.InvalidShardCount;
        var buf: [8]u8 = undefined;
        std.crypto.random.bytes(&buf);
        return .{ .seed = std.mem.readInt(u64, &buf, .little), .shard_count = shard_count };
    }

    pub fn initWithSeed(shard_count: u32, seed: u64) ShardError!Sharder {
        if (shard_count == 0) return ShardError.InvalidShardCount;
        return .{ .seed = seed, .shard_count = shard_count };
    }

    pub fn chooseLoop(self: *const Sharder, key: []const u8) u32 {
        const h = seededHash(key, self.seed);
        return @as(u32, @intCast(h % @as(u64, self.shard_count)));
    }
};

/// Choose loop index in [0, shard_count) using a 5-tuple or CID.
/// WARNING: Uses fixed seed=0; prefer Sharder.init() for DoS resistance.
pub fn chooseLoop(key: []const u8, shard_count: u32) ShardError!u32 {
    if (shard_count == 0) return ShardError.InvalidShardCount;
    const h = seededHash(key, 0);
    return @as(u32, @intCast(h % @as(u64, shard_count)));
}

test "shard: stable mapping" {
    const idx1 = try chooseLoop("1.2.3.4:5555|10.0.0.1:443|udp", 8);
    const idx2 = try chooseLoop("1.2.3.4:5555|10.0.0.1:443|udp", 8);
    try std.testing.expectEqual(idx1, idx2);
}

test "shard: edge — distribution over 64 flows" {
    var used: [8]bool = .{false} ** 8;
    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        var buf: [16]u8 = undefined;
        const len = std.fmt.bufPrint(&buf, "key{d}", .{i}) catch unreachable;
        const idx = try chooseLoop(buf[0..len.len], 8);
        used[idx] = true;
    }
    var distinct: usize = 0;
    for (used) |b| {
        if (b) distinct += 1;
    }
    try std.testing.expect(distinct >= 6); // rough spread
}

test "shard: invalid — zero shard count" {
    const err = chooseLoop("x", 0);
    try std.testing.expectError(ShardError.InvalidShardCount, err);
}

test "shard: Sharder — same key maps to same shard" {
    const sharder = try Sharder.initWithSeed(8, 42);
    const idx1 = sharder.chooseLoop("conn-abc");
    const idx2 = sharder.chooseLoop("conn-abc");
    try std.testing.expectEqual(idx1, idx2);
}

test "shard: Sharder — different seeds produce different mappings" {
    const sharder_a = try Sharder.initWithSeed(256, 1);
    const sharder_b = try Sharder.initWithSeed(256, 2);
    // With 256 shards and different seeds, at least one of several keys should differ
    var differ: usize = 0;
    const keys = [_][]const u8{ "alpha", "beta", "gamma", "delta", "epsilon" };
    for (keys) |key| {
        if (sharder_a.chooseLoop(key) != sharder_b.chooseLoop(key)) differ += 1;
    }
    try std.testing.expect(differ >= 1);
}

test "shard: Sharder — zero shard count returns error" {
    const err = Sharder.initWithSeed(0, 42);
    try std.testing.expectError(ShardError.InvalidShardCount, err);
}
