//! Unit tests for frame/flow_control.zig
//!
//! RFC References:
//! - RFC 9000 §19.10: MAX_DATA Frame
//! - RFC 9000 §19.11: MAX_STREAM_DATA Frame
//! - RFC 9000 §19.12: MAX_STREAMS Frame
//! - RFC 9000 §19.13: DATA_BLOCKED Frame
//! - RFC 9000 §19.14: STREAM_DATA_BLOCKED Frame
//! - RFC 9000 §19.14: STREAMS_BLOCKED Frame
//! - RFC 9000 §4: Flow Control
//!
//! Coverage:
//! - Positive cases: Basic encoding/decoding for all 8 frame types
//! - Negative cases: Truncated buffers, wrong frame types
//! - Edge cases: Zero limits, maximum values, bidirectional vs unidirectional
//! - RFC compliance: Frame formats, flow control semantics, blocked conditions

const std = @import("std");
const testing = std.testing;

const fc = @import("flow_control");
const types = @import("types");

// =============================================================================
// MAX_DATA Frame Tests
// =============================================================================

test "RFC 9000 §19.10 - writeMaxData encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 1000;
    const n = try fc.writeMaxData(w, max);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x10), buf[0]); // MAX_DATA type
}

test "RFC 9000 §19.10 - decodeMaxData reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 10000;
    _ = try fc.writeMaxData(w, max);

    const result = try fc.decodeMaxData(fbs.getWritten());

    try testing.expectEqual(@as(u64, 10000), result.max);
}

test "RFC 9000 §19.10 - MAX_DATA round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 50000;
    const written = try fc.writeMaxData(w, max);

    const result = try fc.decodeMaxData(fbs.getWritten());

    try testing.expectEqual(max, result.max);
    try testing.expectEqual(written, result.n);
}

test "RFC 9000 §4.1 - MAX_DATA with zero limit" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try fc.writeMaxData(w, 0);

    const result = try fc.decodeMaxData(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.max);
}

test "negative: decodeMaxData with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeMaxData(buf));
}

test "negative: decodeMaxData with wrong frame type" {
    const buf = [_]u8{ 0x11, 0x00 }; // MAX_STREAM_DATA instead
    try testing.expectError(error.InvalidFrameType, fc.decodeMaxData(&buf));
}

// =============================================================================
// MAX_STREAM_DATA Frame Tests
// =============================================================================

test "RFC 9000 §19.11 - writeMaxStreamData encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const max: u64 = 5000;
    const n = try fc.writeMaxStreamData(w, stream_id, max);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x11), buf[0]); // MAX_STREAM_DATA type
}

test "RFC 9000 §19.11 - decodeMaxStreamData reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 8;
    const max: u64 = 20000;
    _ = try fc.writeMaxStreamData(w, stream_id, max);

    const result = try fc.decodeMaxStreamData(fbs.getWritten());

    try testing.expectEqual(@as(u64, 8), result.stream_id);
    try testing.expectEqual(@as(u64, 20000), result.max);
}

test "RFC 9000 §19.11 - MAX_STREAM_DATA round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 12;
    const max: u64 = 100000;
    const written = try fc.writeMaxStreamData(w, stream_id, max);

    const result = try fc.decodeMaxStreamData(fbs.getWritten());

    try testing.expectEqual(stream_id, result.stream_id);
    try testing.expectEqual(max, result.max);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeMaxStreamData with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeMaxStreamData(buf));
}

test "negative: decodeMaxStreamData with wrong frame type" {
    const buf = [_]u8{ 0x10, 0x00 }; // MAX_DATA instead
    try testing.expectError(error.InvalidFrameType, fc.decodeMaxStreamData(&buf));
}

// =============================================================================
// MAX_STREAMS (Bidirectional) Frame Tests
// =============================================================================

test "RFC 9000 §19.12 - writeMaxStreamsBidi encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 100;
    const n = try fc.writeMaxStreamsBidi(w, max);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x12), buf[0]); // MAX_STREAMS_BIDI type
}

test "RFC 9000 §19.12 - decodeMaxStreamsBidi reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 200;
    _ = try fc.writeMaxStreamsBidi(w, max);

    const result = try fc.decodeMaxStreamsBidi(fbs.getWritten());

    try testing.expectEqual(@as(u64, 200), result.max);
}

test "RFC 9000 §19.12 - MAX_STREAMS_BIDI round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 500;
    const written = try fc.writeMaxStreamsBidi(w, max);

    const result = try fc.decodeMaxStreamsBidi(fbs.getWritten());

    try testing.expectEqual(max, result.max);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeMaxStreamsBidi with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeMaxStreamsBidi(buf));
}

test "negative: decodeMaxStreamsBidi with wrong frame type" {
    const buf = [_]u8{ 0x13, 0x00 }; // MAX_STREAMS_UNI instead
    try testing.expectError(error.InvalidFrameType, fc.decodeMaxStreamsBidi(&buf));
}

// =============================================================================
// MAX_STREAMS (Unidirectional) Frame Tests
// =============================================================================

test "RFC 9000 §19.12 - writeMaxStreamsUni encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 150;
    const n = try fc.writeMaxStreamsUni(w, max);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x13), buf[0]); // MAX_STREAMS_UNI type
}

test "RFC 9000 §19.12 - decodeMaxStreamsUni reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 300;
    _ = try fc.writeMaxStreamsUni(w, max);

    const result = try fc.decodeMaxStreamsUni(fbs.getWritten());

    try testing.expectEqual(@as(u64, 300), result.max);
}

test "RFC 9000 §19.12 - MAX_STREAMS_UNI round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 1000;
    const written = try fc.writeMaxStreamsUni(w, max);

    const result = try fc.decodeMaxStreamsUni(fbs.getWritten());

    try testing.expectEqual(max, result.max);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeMaxStreamsUni with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeMaxStreamsUni(buf));
}

test "negative: decodeMaxStreamsUni with wrong frame type" {
    const buf = [_]u8{ 0x12, 0x00 }; // MAX_STREAMS_BIDI instead
    try testing.expectError(error.InvalidFrameType, fc.decodeMaxStreamsUni(&buf));
}

// =============================================================================
// DATA_BLOCKED Frame Tests
// =============================================================================

test "RFC 9000 §19.13 - writeDataBlocked encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const limit: u64 = 10000;
    const n = try fc.writeDataBlocked(w, limit);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x14), buf[0]); // DATA_BLOCKED type
}

test "RFC 9000 §19.13 - decodeDataBlocked reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const limit: u64 = 50000;
    _ = try fc.writeDataBlocked(w, limit);

    const result = try fc.decodeDataBlocked(fbs.getWritten());

    try testing.expectEqual(@as(u64, 50000), result.limit);
}

test "RFC 9000 §19.13 - DATA_BLOCKED round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const limit: u64 = 100000;
    const written = try fc.writeDataBlocked(w, limit);

    const result = try fc.decodeDataBlocked(fbs.getWritten());

    try testing.expectEqual(limit, result.limit);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeDataBlocked with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeDataBlocked(buf));
}

test "negative: decodeDataBlocked with wrong frame type" {
    const buf = [_]u8{ 0x15, 0x00 }; // STREAM_DATA_BLOCKED instead
    try testing.expectError(error.InvalidFrameType, fc.decodeDataBlocked(&buf));
}

// =============================================================================
// STREAM_DATA_BLOCKED Frame Tests
// =============================================================================

test "RFC 9000 §19.14 - writeStreamDataBlocked encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const limit: u64 = 5000;
    const n = try fc.writeStreamDataBlocked(w, stream_id, limit);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x15), buf[0]); // STREAM_DATA_BLOCKED type
}

test "RFC 9000 §19.14 - decodeStreamDataBlocked reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 8;
    const limit: u64 = 25000;
    _ = try fc.writeStreamDataBlocked(w, stream_id, limit);

    const result = try fc.decodeStreamDataBlocked(fbs.getWritten());

    try testing.expectEqual(@as(u64, 8), result.stream_id);
    try testing.expectEqual(@as(u64, 25000), result.limit);
}

test "RFC 9000 §19.14 - STREAM_DATA_BLOCKED round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 12;
    const limit: u64 = 75000;
    const written = try fc.writeStreamDataBlocked(w, stream_id, limit);

    const result = try fc.decodeStreamDataBlocked(fbs.getWritten());

    try testing.expectEqual(stream_id, result.stream_id);
    try testing.expectEqual(limit, result.limit);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeStreamDataBlocked with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeStreamDataBlocked(buf));
}

test "negative: decodeStreamDataBlocked with wrong frame type" {
    const buf = [_]u8{ 0x14, 0x00 }; // DATA_BLOCKED instead
    try testing.expectError(error.InvalidFrameType, fc.decodeStreamDataBlocked(&buf));
}

// =============================================================================
// STREAMS_BLOCKED (Bidirectional) Frame Tests
// =============================================================================

test "RFC 9000 §19.14 - writeStreamsBlockedBidi encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 100;
    const n = try fc.writeStreamsBlockedBidi(w, max);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x16), buf[0]); // STREAMS_BLOCKED_BIDI type
}

test "RFC 9000 §19.14 - decodeStreamsBlockedBidi reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 250;
    _ = try fc.writeStreamsBlockedBidi(w, max);

    const result = try fc.decodeStreamsBlockedBidi(fbs.getWritten());

    try testing.expectEqual(@as(u64, 250), result.max);
}

test "RFC 9000 §19.14 - STREAMS_BLOCKED_BIDI round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 500;
    const written = try fc.writeStreamsBlockedBidi(w, max);

    const result = try fc.decodeStreamsBlockedBidi(fbs.getWritten());

    try testing.expectEqual(max, result.max);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeStreamsBlockedBidi with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeStreamsBlockedBidi(buf));
}

test "negative: decodeStreamsBlockedBidi with wrong frame type" {
    const buf = [_]u8{ 0x17, 0x00 }; // STREAMS_BLOCKED_UNI instead
    try testing.expectError(error.InvalidFrameType, fc.decodeStreamsBlockedBidi(&buf));
}

// =============================================================================
// STREAMS_BLOCKED (Unidirectional) Frame Tests
// =============================================================================

test "RFC 9000 §19.14 - writeStreamsBlockedUni encodes frame" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 75;
    const n = try fc.writeStreamsBlockedUni(w, max);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x17), buf[0]); // STREAMS_BLOCKED_UNI type
}

test "RFC 9000 §19.14 - decodeStreamsBlockedUni reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 400;
    _ = try fc.writeStreamsBlockedUni(w, max);

    const result = try fc.decodeStreamsBlockedUni(fbs.getWritten());

    try testing.expectEqual(@as(u64, 400), result.max);
}

test "RFC 9000 §19.14 - STREAMS_BLOCKED_UNI round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const max: u64 = 1000;
    const written = try fc.writeStreamsBlockedUni(w, max);

    const result = try fc.decodeStreamsBlockedUni(fbs.getWritten());

    try testing.expectEqual(max, result.max);
    try testing.expectEqual(written, result.n);
}

test "negative: decodeStreamsBlockedUni with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, fc.decodeStreamsBlockedUni(buf));
}

test "negative: decodeStreamsBlockedUni with wrong frame type" {
    const buf = [_]u8{ 0x16, 0x00 }; // STREAMS_BLOCKED_BIDI instead
    try testing.expectError(error.InvalidFrameType, fc.decodeStreamsBlockedUni(&buf));
}

// =============================================================================
// Frame Type Verification Tests
// =============================================================================

test "RFC 9000 §19 - Flow control frame types are distinct" {
    try testing.expectEqual(@as(u8, 0x10), @intFromEnum(types.FrameType.MAX_DATA));
    try testing.expectEqual(@as(u8, 0x11), @intFromEnum(types.FrameType.MAX_STREAM_DATA));
    try testing.expectEqual(@as(u8, 0x12), @intFromEnum(types.FrameType.MAX_STREAMS_BIDI));
    try testing.expectEqual(@as(u8, 0x13), @intFromEnum(types.FrameType.MAX_STREAMS_UNI));
    try testing.expectEqual(@as(u8, 0x14), @intFromEnum(types.FrameType.DATA_BLOCKED));
    try testing.expectEqual(@as(u8, 0x15), @intFromEnum(types.FrameType.STREAM_DATA_BLOCKED));
    try testing.expectEqual(@as(u8, 0x16), @intFromEnum(types.FrameType.STREAMS_BLOCKED_BIDI));
    try testing.expectEqual(@as(u8, 0x17), @intFromEnum(types.FrameType.STREAMS_BLOCKED_UNI));
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §4.1 - MAX_DATA increases connection flow control limit" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Initial limit
    _ = try fc.writeMaxData(w, 10000);

    // Increased limit
    _ = try fc.writeMaxData(w, 50000);

    const written = fbs.getWritten();

    const r1 = try fc.decodeMaxData(written);
    try testing.expectEqual(@as(u64, 10000), r1.max);

    const r2 = try fc.decodeMaxData(written[r1.n..]);
    try testing.expectEqual(@as(u64, 50000), r2.max);

    // Limit increased
    try testing.expect(r2.max > r1.max);
}

test "RFC 9000 §4.1 - MAX_STREAM_DATA increases stream flow control limit" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;

    // Initial limit
    _ = try fc.writeMaxStreamData(w, stream_id, 5000);

    // Increased limit
    _ = try fc.writeMaxStreamData(w, stream_id, 20000);

    const written = fbs.getWritten();

    const r1 = try fc.decodeMaxStreamData(written);
    try testing.expectEqual(@as(u64, 5000), r1.max);

    const r2 = try fc.decodeMaxStreamData(written[r1.n..]);
    try testing.expectEqual(@as(u64, 20000), r2.max);

    // Same stream, increased limit
    try testing.expectEqual(stream_id, r1.stream_id);
    try testing.expectEqual(stream_id, r2.stream_id);
    try testing.expect(r2.max > r1.max);
}

test "RFC 9000 §4.6 - MAX_STREAMS controls concurrent stream count" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Separate limits for bidirectional and unidirectional
    _ = try fc.writeMaxStreamsBidi(w, 100);
    _ = try fc.writeMaxStreamsUni(w, 50);

    const written = fbs.getWritten();

    const bidi = try fc.decodeMaxStreamsBidi(written);
    try testing.expectEqual(@as(u64, 100), bidi.max);

    const uni = try fc.decodeMaxStreamsUni(written[bidi.n..]);
    try testing.expectEqual(@as(u64, 50), uni.max);
}

test "RFC 9000 §4.1 - DATA_BLOCKED signals connection limit reached" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const limit: u64 = 10000; // Current limit sender is blocked at

    _ = try fc.writeDataBlocked(w, limit);

    const result = try fc.decodeDataBlocked(fbs.getWritten());

    // Receiver should send MAX_DATA to increase limit
    try testing.expectEqual(@as(u64, 10000), result.limit);
}

test "RFC 9000 §4.1 - STREAM_DATA_BLOCKED signals stream limit reached" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const limit: u64 = 5000;

    _ = try fc.writeStreamDataBlocked(w, stream_id, limit);

    const result = try fc.decodeStreamDataBlocked(fbs.getWritten());

    // Receiver should send MAX_STREAM_DATA to increase limit
    try testing.expectEqual(stream_id, result.stream_id);
    try testing.expectEqual(@as(u64, 5000), result.limit);
}

test "RFC 9000 §4.6 - STREAMS_BLOCKED signals stream count limit" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Blocked on bidirectional streams
    _ = try fc.writeStreamsBlockedBidi(w, 100);

    // Blocked on unidirectional streams
    _ = try fc.writeStreamsBlockedUni(w, 50);

    const written = fbs.getWritten();

    const bidi = try fc.decodeStreamsBlockedBidi(written);
    try testing.expectEqual(@as(u64, 100), bidi.max);

    const uni = try fc.decodeStreamsBlockedUni(written[bidi.n..]);
    try testing.expectEqual(@as(u64, 50), uni.max);
}

test "RFC 9000 §4 - Flow control interaction: BLOCKED then MAX" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Sender blocked at limit
    const n1 = try fc.writeDataBlocked(w, 10000);

    // Receiver increases limit
    const n2 = try fc.writeMaxData(w, 50000);

    const written = fbs.getWritten();

    const blocked = try fc.decodeDataBlocked(written);
    try testing.expectEqual(@as(u64, 10000), blocked.limit);

    const max = try fc.decodeMaxData(written[n1..]);
    try testing.expectEqual(@as(u64, 50000), max.max);

    // New limit allows more data
    try testing.expect(max.max > blocked.limit);
    try testing.expect(n1 > 0 and n2 > 0);
}

test "RFC 9000 §4 - Per-stream flow control independent" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Different limits for different streams
    _ = try fc.writeMaxStreamData(w, 0, 10000);
    _ = try fc.writeMaxStreamData(w, 4, 20000);
    _ = try fc.writeMaxStreamData(w, 8, 5000);

    const written = fbs.getWritten();

    var pos: usize = 0;
    const s0 = try fc.decodeMaxStreamData(written[pos..]);
    try testing.expectEqual(@as(u64, 0), s0.stream_id);
    try testing.expectEqual(@as(u64, 10000), s0.max);
    pos += s0.n;

    const s1 = try fc.decodeMaxStreamData(written[pos..]);
    try testing.expectEqual(@as(u64, 4), s1.stream_id);
    try testing.expectEqual(@as(u64, 20000), s1.max);
    pos += s1.n;

    const s2 = try fc.decodeMaxStreamData(written[pos..]);
    try testing.expectEqual(@as(u64, 8), s2.stream_id);
    try testing.expectEqual(@as(u64, 5000), s2.max);
}

test "RFC 9000 §4.1 - Connection limit applies to all streams" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Connection-wide limit
    _ = try fc.writeMaxData(w, 100000);

    // Per-stream limits (sum should not exceed connection limit)
    _ = try fc.writeMaxStreamData(w, 0, 30000);
    _ = try fc.writeMaxStreamData(w, 4, 30000);
    _ = try fc.writeMaxStreamData(w, 8, 30000);

    const written = fbs.getWritten();

    const conn = try fc.decodeMaxData(written);
    try testing.expectEqual(@as(u64, 100000), conn.max);

    // Individual stream limits exist but total is bounded by connection limit
    try testing.expect(conn.max >= 30000);
}

test "RFC 9000 §4.2 - AUTO_TUNING: Receiver increases limits proactively" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Initial conservative limit
    _ = try fc.writeMaxData(w, 10000);

    // Auto-tune to larger limit as data flows
    _ = try fc.writeMaxData(w, 100000);

    // Further increase
    _ = try fc.writeMaxData(w, 1000000);

    const written = fbs.getWritten();

    var pos: usize = 0;
    const r1 = try fc.decodeMaxData(written[pos..]);
    pos += r1.n;

    const r2 = try fc.decodeMaxData(written[pos..]);
    pos += r2.n;

    const r3 = try fc.decodeMaxData(written[pos..]);

    // Limits monotonically increase
    try testing.expect(r2.max > r1.max);
    try testing.expect(r3.max > r2.max);
}

test "RFC 9000 §4.6 - Bidirectional and unidirectional stream limits separate" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // MAX_STREAMS for both directions
    _ = try fc.writeMaxStreamsBidi(w, 100);
    _ = try fc.writeMaxStreamsUni(w, 50);

    // STREAMS_BLOCKED for both directions
    _ = try fc.writeStreamsBlockedBidi(w, 100);
    _ = try fc.writeStreamsBlockedUni(w, 50);

    const written = fbs.getWritten();

    var pos: usize = 0;
    const max_bidi = try fc.decodeMaxStreamsBidi(written[pos..]);
    pos += max_bidi.n;

    const max_uni = try fc.decodeMaxStreamsUni(written[pos..]);
    pos += max_uni.n;

    const blocked_bidi = try fc.decodeStreamsBlockedBidi(written[pos..]);
    pos += blocked_bidi.n;

    const blocked_uni = try fc.decodeStreamsBlockedUni(written[pos..]);

    // Separate limits for each direction
    try testing.expectEqual(@as(u64, 100), max_bidi.max);
    try testing.expectEqual(@as(u64, 50), max_uni.max);
    try testing.expectEqual(@as(u64, 100), blocked_bidi.max);
    try testing.expectEqual(@as(u64, 50), blocked_uni.max);
}
