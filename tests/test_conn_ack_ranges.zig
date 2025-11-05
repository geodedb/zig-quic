const std = @import("std");
const quic = @import("../quic.zig");

pub fn main() !void {}

// RFC 9000 §19.3 example-style ACK encoding: largest=9, additional ranges
// acknowledge 7-6 then 3-1 with appropriate gaps.
test "conn ack ranges follow RFC 9000 multi-block example" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Client, 0, peer);
    defer conn.deinit();

    conn.trackRecvPnApp(1);
    conn.trackRecvPnApp(2);
    conn.trackRecvPnApp(3);
    conn.trackRecvPnApp(6);
    conn.trackRecvPnApp(7);
    conn.trackRecvPnApp(9);

    const ack = conn.buildAckApp();
    try std.testing.expectEqual(@as(u64, 9), ack.largest);
    try std.testing.expectEqual(@as(u64, 0), ack.first_range);
    try std.testing.expectEqual(@as(usize, 2), ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 1), ack.ranges[0].len);
    try std.testing.expectEqual(@as(u64, 1), ack.ranges[1].gap);
    try std.testing.expectEqual(@as(u64, 2), ack.ranges[1].len);
}

// When a new largest packet number extends beyond the 256-packet tracking
// window, older acknowledgements fall outside RFC 9000 §19.3's encoded ranges.
test "conn ack window drops stale packets beyond span" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var conn: quic.Connection = undefined;
    const peer = quic.Connection.SockAddr.ipv4(127, 0, 0, 1, 4433);
    conn.init(&alloc, .Client, 0, peer);
    defer conn.deinit();

    conn.trackRecvPnApp(0);
    conn.trackRecvPnApp(1);
    conn.trackRecvPnApp(2);
    conn.trackRecvPnApp(299);
    conn.trackRecvPnApp(300);

    const ack = conn.buildAckApp();
    try std.testing.expectEqual(@as(u64, 300), ack.largest);
    try std.testing.expectEqual(@as(u64, 1), ack.first_range);
    try std.testing.expectEqual(@as(usize, 0), ack.ranges.len);
}
