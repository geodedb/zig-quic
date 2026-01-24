const std = @import("std");
const frame = @import("quic_frame");
const varint = @import("quic_varint");
const testing = std.testing;

test "streaming encode/decode PING" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const f = frame.Frame{ .ping = {} };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .ping);
}

test "streaming encode/decode STREAM" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const data = "hello world";
    const f = frame.Frame{ .stream = .{ .stream_id = 123, .offset = 0, .fin = true, .data = data } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);
    defer {
        // Clean up allocated data
        if (decoded == .stream) testing.allocator.free(decoded.stream.data);
    }

    try testing.expect(decoded == .stream);
    try testing.expectEqual(@as(u64, 123), decoded.stream.stream_id);
    try testing.expectEqual(@as(?u64, 0), decoded.stream.offset);
    try testing.expect(decoded.stream.fin);
    try testing.expectEqualStrings(data, decoded.stream.data);
}

test "streaming encode/decode ACK" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    var ranges = [_]frame.AckRange{.{ .gap = 1, .len = 2 }};
    const f = frame.Frame{ .ack = .{
        .largest = 100,
        .ack_delay = 5,
        .first_range = 10,
        .ranges = &ranges,
        .ecn = null,
    } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);
    defer {
        if (decoded == .ack) testing.allocator.free(decoded.ack.ranges);
    }

    try testing.expect(decoded == .ack);
    try testing.expectEqual(@as(u64, 100), decoded.ack.largest);
    try testing.expectEqual(@as(u64, 5), decoded.ack.ack_delay);
    try testing.expectEqual(@as(u64, 10), decoded.ack.first_range);
    try testing.expectEqual(@as(usize, 1), decoded.ack.ranges.len);
    try testing.expectEqual(@as(u64, 1), decoded.ack.ranges[0].gap);
    try testing.expectEqual(@as(u64, 2), decoded.ack.ranges[0].len);
}

test "streaming encode/decode CONNECTION_CLOSE" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const reason = "goodbye";
    const f = frame.Frame{ .connection_close = .{ .error_code = 1, .frame_type = 0, .reason = reason } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);
    defer {
        if (decoded == .connection_close) testing.allocator.free(decoded.connection_close.reason);
    }

    try testing.expect(decoded == .connection_close);
    try testing.expectEqual(@as(u64, 1), decoded.connection_close.error_code);
    try testing.expectEqualStrings(reason, decoded.connection_close.reason);
}
