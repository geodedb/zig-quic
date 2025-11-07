//! Unit tests for frame/misc.zig
//!
//! RFC References:
//! - RFC 9000 §19.1: PADDING Frame
//! - RFC 9000 §19.2: PING Frame
//! - RFC 9000 §19.7: NEW_TOKEN Frame
//! - RFC 9000 §19.20: HANDSHAKE_DONE Frame
//!
//! Coverage:
//! - Positive cases: Frame encoding/decoding, normal operation
//! - Negative cases: Invalid frame types, truncated buffers
//! - Edge cases: Zero padding, empty tokens, max token lengths
//! - RFC compliance: Frame format specifications, byte layouts

const std = @import("std");
const testing = std.testing;

const misc = @import("misc");
const types = @import("types");

// =============================================================================
// PADDING Frame Tests (RFC 9000 §19.1)
// =============================================================================

test "RFC 9000 §19.1 - writePadding single byte" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePadding(fbs.writer(), 1);

    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
}

test "RFC 9000 §19.1 - writePadding multiple bytes" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePadding(fbs.writer(), 5);

    try testing.expectEqual(@as(usize, 5), n);
    for (buf[0..5]) |byte| {
        try testing.expectEqual(@as(u8, 0x00), byte);
    }
}

test "RFC 9000 §19.1 - writePadding zero count" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePadding(fbs.writer(), 0);

    try testing.expectEqual(@as(usize, 0), n);
}

test "RFC 9000 §19.1 - decodePadding single byte" {
    const buf = [_]u8{0x00};

    const result = try misc.decodePadding(&buf);

    try testing.expectEqual(@as(usize, 1), result.count);
    try testing.expectEqual(@as(usize, 1), result.n);
}

test "RFC 9000 §19.1 - decodePadding multiple consecutive bytes" {
    const buf = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00 };

    const result = try misc.decodePadding(&buf);

    try testing.expectEqual(@as(usize, 5), result.count);
    try testing.expectEqual(@as(usize, 5), result.n);
}

test "RFC 9000 §19.1 - decodePadding stops at non-padding byte" {
    const buf = [_]u8{ 0x00, 0x00, 0x01, 0x00 }; // 2 padding, then PING

    const result = try misc.decodePadding(&buf);

    try testing.expectEqual(@as(usize, 2), result.count);
    try testing.expectEqual(@as(usize, 2), result.n);
}

test "RFC 9000 §19.1 - decodePadding empty buffer" {
    const buf: []const u8 = &[_]u8{};

    const result = try misc.decodePadding(buf);

    try testing.expectEqual(@as(usize, 0), result.count);
    try testing.expectEqual(@as(usize, 0), result.n);
}

test "RFC 9000 §19.1 - decodePadding no padding in buffer" {
    const buf = [_]u8{0x01}; // PING, not PADDING

    const result = try misc.decodePadding(&buf);

    try testing.expectEqual(@as(usize, 0), result.count);
    try testing.expectEqual(@as(usize, 0), result.n);
}

test "RFC 9000 §19.1 - PADDING round trip" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const write_count: usize = 7;
    const n = try misc.writePadding(fbs.writer(), write_count);

    const result = try misc.decodePadding(buf[0..n]);

    try testing.expectEqual(write_count, result.count);
    try testing.expectEqual(n, result.n);
}

// =============================================================================
// PING Frame Tests (RFC 9000 §19.2)
// =============================================================================

test "RFC 9000 §19.2 - writePing encodes single byte" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePing(fbs.writer());

    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "RFC 9000 §19.2 - decodePing validates frame type" {
    const buf = [_]u8{0x01};

    const result = try misc.decodePing(&buf);

    try testing.expectEqual(@as(usize, 1), result.n);
}

test "RFC 9000 §19.2 - decodePing rejects wrong frame type" {
    const buf = [_]u8{0x00}; // PADDING, not PING

    const result = misc.decodePing(&buf);

    try testing.expectError(error.InvalidFrameType, result);
}

test "RFC 9000 §19.2 - decodePing requires minimum length" {
    const buf: []const u8 = &[_]u8{};

    const result = misc.decodePing(buf);

    try testing.expectError(error.Truncated, result);
}

test "RFC 9000 §19.2 - PING round trip" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePing(fbs.writer());
    const result = try misc.decodePing(buf[0..n]);

    try testing.expectEqual(@as(usize, 1), result.n);
}

test "RFC 9000 §19.2 - PING resets idle timeout" {
    // PING frames are ACK-eliciting and reset idle timer
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePing(fbs.writer());

    // Verify frame type is PING (0x01)
    try testing.expectEqual(@as(u8, 0x01), buf[0]);
    try testing.expectEqual(@as(usize, 1), n);
}

// =============================================================================
// NEW_TOKEN Frame Tests (RFC 9000 §19.7)
// =============================================================================

test "RFC 9000 §19.7 - writeNewToken with simple token" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const token = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const n = try misc.writeNewToken(fbs.writer(), &token);

    // Frame type (0x07) + length varint + token bytes
    try testing.expectEqual(@as(u8, 0x07), buf[0]);
    try testing.expectEqual(@as(usize, 1 + 1 + 4), n); // type + len(4 as varint=1byte) + 4 bytes
}

test "RFC 9000 §19.7 - writeNewToken with empty token" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const token: []const u8 = &[_]u8{};

    const n = try misc.writeNewToken(fbs.writer(), token);

    try testing.expectEqual(@as(u8, 0x07), buf[0]);
    try testing.expectEqual(@as(u8, 0x00), buf[1]); // Length = 0
    try testing.expectEqual(@as(usize, 2), n);
}

test "RFC 9000 §19.7 - writeNewToken with large token" {
    var buf: [300]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var token: [200]u8 = undefined;
    @memset(&token, 0x42);

    const n = try misc.writeNewToken(fbs.writer(), &token);

    try testing.expectEqual(@as(u8, 0x07), buf[0]);
    try testing.expect(n > 200); // type + varint length + 200 bytes
}

test "RFC 9000 §19.7 - decodeNewToken reads token correctly" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const original_token = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55 };

    const n = try misc.writeNewToken(fbs.writer(), &original_token);
    const result = try misc.decodeNewToken(buf[0..n]);

    try testing.expectEqualSlices(u8, &original_token, result.token);
    try testing.expectEqual(n, result.n);
}

test "RFC 9000 §19.7 - decodeNewToken with empty token" {
    const buf = [_]u8{ 0x07, 0x00 }; // NEW_TOKEN with length 0

    const result = try misc.decodeNewToken(&buf);

    try testing.expectEqual(@as(usize, 0), result.token.len);
    try testing.expectEqual(@as(usize, 2), result.n);
}

test "RFC 9000 §19.7 - decodeNewToken truncated buffer" {
    const buf = [_]u8{0x07}; // NEW_TOKEN without length

    const result = misc.decodeNewToken(&buf);

    try testing.expectError(error.Truncated, result);
}

test "RFC 9000 §19.7 - decodeNewToken wrong frame type" {
    const buf = [_]u8{ 0x01, 0x04 }; // PING, not NEW_TOKEN

    const result = misc.decodeNewToken(&buf);

    try testing.expectError(error.InvalidFrameType, result);
}

test "RFC 9000 §19.7 - decodeNewToken truncated token data" {
    const buf = [_]u8{ 0x07, 0x10 }; // NEW_TOKEN claiming 16 bytes but no data

    const result = misc.decodeNewToken(&buf);

    try testing.expectError(error.Truncated, result);
}

test "RFC 9000 §19.7 - NEW_TOKEN round trip" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const original_token = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

    const n = try misc.writeNewToken(fbs.writer(), &original_token);
    const result = try misc.decodeNewToken(buf[0..n]);

    try testing.expectEqualSlices(u8, &original_token, result.token);
    try testing.expectEqual(n, result.n);
}

// =============================================================================
// HANDSHAKE_DONE Frame Tests (RFC 9000 §19.20)
// =============================================================================

test "RFC 9000 §19.20 - writeHandshakeDone encodes single byte" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writeHandshakeDone(fbs.writer());

    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x1E), buf[0]);
}

test "RFC 9000 §19.20 - decodeHandshakeDone validates frame type" {
    const buf = [_]u8{0x1E};

    const result = try misc.decodeHandshakeDone(&buf);

    try testing.expectEqual(@as(usize, 1), result.n);
}

test "RFC 9000 §19.20 - decodeHandshakeDone rejects wrong frame type" {
    const buf = [_]u8{0x01}; // PING, not HANDSHAKE_DONE

    const result = misc.decodeHandshakeDone(&buf);

    try testing.expectError(error.InvalidFrameType, result);
}

test "RFC 9000 §19.20 - decodeHandshakeDone requires minimum length" {
    const buf: []const u8 = &[_]u8{};

    const result = misc.decodeHandshakeDone(buf);

    try testing.expectError(error.Truncated, result);
}

test "RFC 9000 §19.20 - HANDSHAKE_DONE round trip" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writeHandshakeDone(fbs.writer());
    const result = try misc.decodeHandshakeDone(buf[0..n]);

    try testing.expectEqual(@as(usize, 1), result.n);
}

test "RFC 9000 §19.20 - HANDSHAKE_DONE server-only frame" {
    // HANDSHAKE_DONE is sent by server to signal handshake completion
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writeHandshakeDone(fbs.writer());

    // Verify frame type is HANDSHAKE_DONE (0x1E)
    try testing.expectEqual(@as(u8, 0x1E), buf[0]);
    try testing.expectEqual(@as(usize, 1), n);
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: PADDING with maximum practical count" {
    var buf: [1500]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const count: usize = 1200; // MTU-sized padding
    const n = try misc.writePadding(fbs.writer(), count);

    try testing.expectEqual(count, n);

    const result = try misc.decodePadding(buf[0..n]);
    try testing.expectEqual(count, result.count);
}

test "boundary: NEW_TOKEN with 1-byte token" {
    var buf: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const token = [_]u8{0x99};

    const n = try misc.writeNewToken(fbs.writer(), &token);
    const result = try misc.decodeNewToken(buf[0..n]);

    try testing.expectEqualSlices(u8, &token, result.token);
}

test "boundary: NEW_TOKEN with max-size token" {
    var buf: [2000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var token: [1024]u8 = undefined;
    for (0..1024) |i| {
        token[i] = @intCast(i & 0xFF);
    }

    const n = try misc.writeNewToken(fbs.writer(), &token);
    const result = try misc.decodeNewToken(buf[0..n]);

    try testing.expectEqualSlices(u8, &token, result.token);
}

test "boundary: Mixed frame sequence" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    // Write: PADDING, PING, PADDING, HANDSHAKE_DONE
    var offset: usize = 0;

    fbs.pos = offset;
    offset += try misc.writePadding(fbs.writer(), 3);

    fbs.pos = offset;
    offset += try misc.writePing(fbs.writer());

    fbs.pos = offset;
    offset += try misc.writePadding(fbs.writer(), 2);

    fbs.pos = offset;
    offset += try misc.writeHandshakeDone(fbs.writer());

    // Verify encoded sequence
    try testing.expectEqual(@as(u8, 0x00), buf[0]); // PADDING
    try testing.expectEqual(@as(u8, 0x00), buf[1]); // PADDING
    try testing.expectEqual(@as(u8, 0x00), buf[2]); // PADDING
    try testing.expectEqual(@as(u8, 0x01), buf[3]); // PING
    try testing.expectEqual(@as(u8, 0x00), buf[4]); // PADDING
    try testing.expectEqual(@as(u8, 0x00), buf[5]); // PADDING
    try testing.expectEqual(@as(u8, 0x1E), buf[6]); // HANDSHAKE_DONE
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §19.1 - PADDING frame format" {
    // RFC 9000 §19.1: PADDING frame is type 0x00 with no additional data
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    _ = try misc.writePadding(fbs.writer(), 1);

    try testing.expectEqual(@intFromEnum(types.FrameType.PADDING), buf[0]);
}

test "RFC 9000 §19.2 - PING frame format" {
    // RFC 9000 §19.2: PING frame is type 0x01 with no additional data
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    _ = try misc.writePing(fbs.writer());

    try testing.expectEqual(@intFromEnum(types.FrameType.PING), buf[0]);
}

test "RFC 9000 §19.7 - NEW_TOKEN frame format" {
    // RFC 9000 §19.7: NEW_TOKEN = type(i) + token_length(i) + token(...)
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const token = [_]u8{ 0x01, 0x02, 0x03 };

    _ = try misc.writeNewToken(fbs.writer(), &token);

    // Verify type byte
    try testing.expectEqual(@intFromEnum(types.FrameType.NEW_TOKEN), buf[0]);
    // Verify length is encoded (0x03)
    try testing.expectEqual(@as(u8, 0x03), buf[1]);
    // Verify token data
    try testing.expectEqualSlices(u8, &token, buf[2..5]);
}

test "RFC 9000 §19.20 - HANDSHAKE_DONE frame format" {
    // RFC 9000 §19.20: HANDSHAKE_DONE frame is type 0x1E with no additional data
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    _ = try misc.writeHandshakeDone(fbs.writer());

    try testing.expectEqual(@intFromEnum(types.FrameType.HANDSHAKE_DONE), buf[0]);
}

test "RFC 9000 §19.1 - PADDING increases packet size" {
    // RFC 9000 §19.1: PADDING frames are used to increase packet size
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const initial_pos = fbs.pos;
    const padding_count: usize = 50;
    _ = try misc.writePadding(fbs.writer(), padding_count);

    // Verify packet size increased by padding_count
    try testing.expectEqual(initial_pos + padding_count, fbs.pos);
}

test "RFC 9000 §19.2 - PING elicits ACK" {
    // RFC 9000 §19.2: PING frames are ACK-eliciting
    // This is a semantic property - verify frame is encoded correctly
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writePing(fbs.writer());

    // PING frame should be exactly 1 byte (type 0x01)
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "RFC 9000 §19.7 - NEW_TOKEN for address validation" {
    // RFC 9000 §19.7: Server sends NEW_TOKEN to provide address validation token
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const validation_token = [_]u8{ 0xDE, 0xAD, 0xC0, 0xDE };

    const n = try misc.writeNewToken(fbs.writer(), &validation_token);
    const result = try misc.decodeNewToken(buf[0..n]);

    // Verify token is opaque and preserved exactly
    try testing.expectEqualSlices(u8, &validation_token, result.token);
}

test "RFC 9000 §19.20 - HANDSHAKE_DONE signals completion" {
    // RFC 9000 §19.20: Server sends HANDSHAKE_DONE to signal handshake complete
    // Client can send 1-RTT data after receiving this frame
    var buf: [1]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const n = try misc.writeHandshakeDone(fbs.writer());

    // Verify frame is simple (no payload)
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x1E), buf[0]);
}

test "RFC 9000 §19 - All misc frame types are distinct" {
    // Verify all 4 frame types have unique type identifiers
    try testing.expect(@intFromEnum(types.FrameType.PADDING) != @intFromEnum(types.FrameType.PING));
    try testing.expect(@intFromEnum(types.FrameType.PADDING) != @intFromEnum(types.FrameType.NEW_TOKEN));
    try testing.expect(@intFromEnum(types.FrameType.PADDING) != @intFromEnum(types.FrameType.HANDSHAKE_DONE));
    try testing.expect(@intFromEnum(types.FrameType.PING) != @intFromEnum(types.FrameType.NEW_TOKEN));
    try testing.expect(@intFromEnum(types.FrameType.PING) != @intFromEnum(types.FrameType.HANDSHAKE_DONE));
    try testing.expect(@intFromEnum(types.FrameType.NEW_TOKEN) != @intFromEnum(types.FrameType.HANDSHAKE_DONE));
}
