const std = @import("std");
const frame = @import("../src/quic/frame.zig");

test "ack multi-range encode/decode with ECN counts" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const a = frame.Frame{
        .ack = .{
            .largest = 100,
            .ack_delay = 0,
            .first_range = 2, // acknowledges [98..100]
            .ranges = &[_]frame.AckRange{ .{ .gap = 0, .len = 0 }, .{ .gap = 1, .len = 1 } },
            // gaps/lengths: then a single [97..97], skip one, then [95..96]
            .ecn = .{ .ect0 = 10, .ect1 = 5, .ce = 1 },
        },
    };
    const n = try a.write(fbs.writer(alloc));
    // First byte should be ACK_ECN (0x03)
    try std.testing.expect(buf[0] == @intFromEnum(frame.FrameType.ACK_ECN));
    const pr = try frame.parse(buf[0..n]);
    try std.testing.expect(std.mem.eql(u8, @tagName(pr.frame), "ack"));
    const ack = pr.frame.ack;
    try std.testing.expectEqual(@as(u64, 100), ack.largest);
    try std.testing.expectEqual(@as(u64, 2), ack.first_range);
    try std.testing.expectEqual(@as(usize, 2), ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[0].len);
    try std.testing.expectEqual(@as(u64, 1), ack.ranges[1].gap);
    try std.testing.expectEqual(@as(u64, 1), ack.ranges[1].len);
    try std.testing.expect(ack.ecn != null);
    try std.testing.expectEqual(@as(u64, 10), ack.ecn.?.ect0);
    try std.testing.expectEqual(@as(u64, 5), ack.ecn.?.ect1);
    try std.testing.expectEqual(@as(u64, 1), ack.ecn.?.ce);
}
