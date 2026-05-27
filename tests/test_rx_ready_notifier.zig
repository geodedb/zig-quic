const std = @import("std");

const quic_conn = @import("quic_conn");

test "connection STREAM receive invokes and clears RX-ready notifier" {
    var allocator = std.testing.allocator;
    var conn: quic_conn.Connection = undefined;
    conn.init(&allocator, .Server, -1, quic_conn.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    var calls = std.atomic.Value(u32).init(0);
    const Notify = struct {
        fn cb(ctx: *anyopaque, c: *quic_conn.Connection) void {
            _ = c;
            const counter: *std.atomic.Value(u32) = @ptrCast(@alignCast(ctx));
            _ = counter.fetchAdd(1, .acq_rel);
        }
    };

    conn.setRxReadyNotifier(@ptrCast(&calls), Notify.cb);
    try conn.pushStreamFrame(0, 0, "ping", false);
    try std.testing.expectEqual(@as(u32, 1), calls.load(.acquire));
    try std.testing.expect(conn.rx_data_generation.load(.acquire) > 0);

    conn.clearRxReadyNotifier();
    try conn.pushStreamFrame(0, 4, "pong", false);
    try std.testing.expectEqual(@as(u32, 1), calls.load(.acquire));
}
