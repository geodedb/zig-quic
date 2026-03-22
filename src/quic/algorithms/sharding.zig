const std = @import("std");

pub const ShardError = error{InvalidShardCount};

fn fnv1a64(bytes: []const u8) u64 {
    var hash: u64 = 14695981039346656037; // FNV offset basis
    for (bytes) |b| {
        hash = hash ^ @as(u64, b);
        hash = hash *% 1099511628211; // Use wrapping multiplication
    }
    return hash;
}

/// Choose loop index in [0, shard_count) using a 5-tuple or CID.
pub fn chooseLoop(key: []const u8, shard_count: u32) ShardError!u32 {
    if (shard_count == 0) return ShardError.InvalidShardCount;
    const h = fnv1a64(key);
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
