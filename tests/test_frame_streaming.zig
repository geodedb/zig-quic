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

test "streaming encode/decode HANDSHAKE_DONE" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const f = frame.Frame{ .handshake_done = {} };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .handshake_done);
}

test "streaming encode/decode MAX_DATA" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const f = frame.Frame{ .max_data = .{ .max = 1048576 } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .max_data);
    try testing.expectEqual(@as(u64, 1048576), decoded.max_data.max);
}

test "streaming encode/decode MAX_STREAM_DATA" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const f = frame.Frame{ .max_stream_data = .{ .stream_id = 42, .max = 65536 } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .max_stream_data);
    try testing.expectEqual(@as(u64, 42), decoded.max_stream_data.stream_id);
    try testing.expectEqual(@as(u64, 65536), decoded.max_stream_data.max);
}

test "streaming encode/decode PATH_CHALLENGE" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const challenge_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const f = frame.Frame{ .path_challenge = challenge_data };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .path_challenge);
    try testing.expectEqualSlices(u8, &challenge_data, &decoded.path_challenge);
}

test "streaming encode/decode PATH_RESPONSE" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const response_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    const f = frame.Frame{ .path_response = response_data };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .path_response);
    try testing.expectEqualSlices(u8, &response_data, &decoded.path_response);
}

test "streaming encode/decode RESET_STREAM" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const f = frame.Frame{ .reset_stream = .{ .stream_id = 7, .error_code = 0x0a, .final_size = 4096 } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .reset_stream);
    try testing.expectEqual(@as(u64, 7), decoded.reset_stream.stream_id);
    try testing.expectEqual(@as(u64, 0x0a), decoded.reset_stream.error_code);
    try testing.expectEqual(@as(u64, 4096), decoded.reset_stream.final_size);
}

test "streaming encode/decode STOP_SENDING" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    const w = buf.writer(testing.allocator);

    const f = frame.Frame{ .stop_sending = .{ .stream_id = 15, .error_code = 0x0b } };
    try frame.encode(f, w);

    var fbs = std.io.fixedBufferStream(buf.items);
    const r = fbs.reader();
    const decoded = try frame.decode(r, testing.allocator);

    try testing.expect(decoded == .stop_sending);
    try testing.expectEqual(@as(u64, 15), decoded.stop_sending.stream_id);
    try testing.expectEqual(@as(u64, 0x0b), decoded.stop_sending.error_code);
}
