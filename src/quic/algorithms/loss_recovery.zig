const std = @import("std");

pub const SentPacket = struct {
    pn: u64,
    sent_at_us: u64,
    acked: bool,
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
    for (pkts) |p| {
        if (p.acked or p.pn >= latest_acked_pn) continue;
        const exceeds_reorder = (latest_acked_pn - p.pn) >= @as(u64, reordering_threshold);
        const exceeds_time = (now_us - p.sent_at_us) >= time_threshold;
        if (exceeds_reorder or exceeds_time) {
            if (n < out_lost.len) {
                out_lost[n] = p.pn;
                n += 1;
            }
        }
    }
    return n;
}

test "loss: threshold by reordering or time" {
    var pkts = [_]SentPacket{
        .{ .pn = 10, .sent_at_us = 1000, .acked = false },
        .{ .pn = 11, .sent_at_us = 1010, .acked = true },
        .{ .pn = 12, .sent_at_us = 1020, .acked = true },
    };
    var out: [4]u64 = undefined;
    const n = detectLost(pkts[0..], 12, 3000, 1000, 3, out[0..]);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 10), out[0]);
}

test "loss: edge — not enough time nor reordering" {
    var pkts = [_]SentPacket{
        .{ .pn = 5, .sent_at_us = 2000, .acked = false },
        .{ .pn = 6, .sent_at_us = 2010, .acked = true },
    };
    var out: [2]u64 = undefined;
    const n = detectLost(pkts[0..], 6, 2100, 1000, 5, out[0..]);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "loss: invalid — empty out buffer just truncates (non-panicking)" {
    var pkts = [_]SentPacket{
        .{ .pn = 1, .sent_at_us = 0, .acked = false },
    };
    var out: [0]u64 = .{};
    const n = detectLost(pkts[0..], 10, 2000, 1000, 1, out[0..]);
    try std.testing.expectEqual(@as(usize, 0), n);
}
