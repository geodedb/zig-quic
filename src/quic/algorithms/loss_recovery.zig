// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Packet loss detection using reordering and time thresholds (RFC 9002 S6).

const std = @import("std");

pub const SentPacket = struct {
    pn: u64,
    sent_at_us: u64,
    size: usize = 0,
    acked: bool,
    declared_lost: bool = false,
};

pub fn detectLost(
    pkts: []SentPacket,
    latest_acked_pn: u64,
    now_us: u64,
    srtt_us: u64,
    reordering_threshold: u32, // e.g., 3
    out_lost: []u64,
) usize {
    const time_threshold = srtt_us + srtt_us / 8; // ~1.125 * RTT
    var n: usize = 0;
    for (pkts) |*p| {
        if (p.acked or p.pn >= latest_acked_pn) continue;
        if (p.declared_lost) continue;
        const exceeds_reorder = (latest_acked_pn - p.pn) >= @as(u64, reordering_threshold);
        const exceeds_time = if (now_us >= p.sent_at_us) (now_us - p.sent_at_us) >= time_threshold else false;
        if (exceeds_reorder or exceeds_time) {
            if (n < out_lost.len) {
                out_lost[n] = p.pn;
                n += 1;
                p.declared_lost = true;
            }
        }
    }
    return n;
}

test "loss: threshold by reordering or time" {
    var pkts = [_]SentPacket{
        .{ .pn = 10, .sent_at_us = 1000, .size = 1200, .acked = false },
        .{ .pn = 11, .sent_at_us = 1010, .size = 1200, .acked = true },
        .{ .pn = 12, .sent_at_us = 1020, .size = 1200, .acked = true },
    };
    var out: [4]u64 = undefined;
    const n = detectLost(pkts[0..], 12, 3000, 1000, 3, out[0..]);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 10), out[0]);
}

test "loss: edge — not enough time nor reordering" {
    var pkts = [_]SentPacket{
        .{ .pn = 5, .sent_at_us = 2000, .size = 1200, .acked = false },
        .{ .pn = 6, .sent_at_us = 2010, .size = 1200, .acked = true },
    };
    var out: [2]u64 = undefined;
    const n = detectLost(pkts[0..], 6, 2100, 1000, 5, out[0..]);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "loss: invalid — empty out buffer just truncates (non-panicking)" {
    var pkts = [_]SentPacket{
        .{ .pn = 1, .sent_at_us = 0, .size = 1200, .acked = false },
    };
    var out: [0]u64 = .{};
    const n = detectLost(pkts[0..], 10, 2000, 1000, 1, out[0..]);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "loss: clock skew — now_us < sent_at_us does not panic" {
    var pkts = [_]SentPacket{
        .{ .pn = 1, .sent_at_us = 5000, .size = 1200, .acked = false },
    };
    var out: [2]u64 = undefined;
    // now_us (1000) < sent_at_us (5000): must not underflow/panic
    const n = detectLost(pkts[0..], 10, 1000, 1000, 3, out[0..]);
    // Reordering threshold alone triggers loss (10 - 1 = 9 >= 3)
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 1), out[0]);
}

test "loss: declared_lost — already-lost packets not re-reported" {
    var pkts = [_]SentPacket{
        .{ .pn = 1, .sent_at_us = 1000, .size = 1200, .acked = false },
        .{ .pn = 2, .sent_at_us = 1010, .size = 1200, .acked = false },
    };
    var out: [4]u64 = undefined;

    // First detection: both packets should be detected as lost
    const n1 = detectLost(pkts[0..], 10, 5000, 1000, 3, out[0..]);
    try std.testing.expectEqual(@as(usize, 2), n1);

    // Second detection: both should now be declared_lost and skipped
    const n2 = detectLost(pkts[0..], 10, 6000, 1000, 3, out[0..]);
    try std.testing.expectEqual(@as(usize, 0), n2);
}
