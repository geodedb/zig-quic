//! Unit tests for frame/stream.zig
//!
//! RFC References:
//! - RFC 9000 §19.8: STREAM Frame
//! - RFC 9000 §2: Stream Multiplexing
//! - RFC 9000 §3: Stream States
//!
//! Coverage:
//! - Positive cases: Basic encoding/decoding, flag combinations, stream IDs, offsets
//! - Negative cases: Truncated buffers, wrong frame type, invalid fields
//! - Edge cases: FIN flag, empty data, maximum values, all flag combinations
//! - RFC compliance: Frame format, stream semantics, flow control integration

const std = @import("std");
const testing = std.testing;

const stream = @import("stream");
const types = @import("types");

// =============================================================================
// Basic STREAM Frame Tests
// =============================================================================

test "RFC 9000 §19.8 - writeStream encodes frame with stream ID and data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const offset: ?u64 = null;
    const fin = false;
    const data = "Hello";
    const n = try stream.writeStream(w, stream_id, offset, fin, data);

    // Frame type (0x08-0x0f) + stream ID + length + data
    try testing.expect(n > data.len);
    try testing.expect((buf[0] & 0xf8) == 0x08); // STREAM frame type
}

test "RFC 9000 §19.8 - decodeStream reads frame correctly" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 8;
    const offset: ?u64 = 100;
    const fin = false;
    const data = "Test data";
    _ = try stream.writeStream(w, stream_id, offset, fin, data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, 8), result.stream_id);
    try testing.expectEqual(@as(?u64, 100), result.offset);
    try testing.expectEqual(false, result.fin);
    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9000 §19.8 - STREAM frame round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 12;
    const offset: ?u64 = 42;
    const fin = true;
    const data = "Round trip test";
    const written = try stream.writeStream(w, stream_id, offset, fin, data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(stream_id, result.stream_id);
    try testing.expectEqual(offset, result.offset);
    try testing.expectEqual(fin, result.fin);
    try testing.expectEqualStrings(data, result.data);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// Stream ID Variation Tests
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame with stream ID 0" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 0;
    _ = try stream.writeStream(w, stream_id, null, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.stream_id);
}

test "RFC 9000 §19.8 - STREAM frame with small stream ID" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 127; // 1-byte varint
    _ = try stream.writeStream(w, stream_id, null, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, 127), result.stream_id);
}

test "RFC 9000 §19.8 - STREAM frame with large stream ID" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 100000; // Multi-byte varint
    _ = try stream.writeStream(w, stream_id, null, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, 100000), result.stream_id);
}

test "RFC 9000 §19.8 - STREAM frame with maximum stream ID" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = (1 << 62) - 1; // Max varint
    _ = try stream.writeStream(w, stream_id, null, false, "X");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(u64, (1 << 62) - 1), result.stream_id);
}

// =============================================================================
// Offset Variation Tests
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame with null offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: ?u64 = null;
    _ = try stream.writeStream(w, 4, offset, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(?u64, null), result.offset);

    // OFF flag should NOT be set
    const written = fbs.getWritten();
    try testing.expect((written[0] & stream.OFF) == 0);
}

test "RFC 9000 §19.8 - STREAM frame with zero offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: ?u64 = 0;
    _ = try stream.writeStream(w, 4, offset, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(?u64, 0), result.offset);

    // OFF flag should be set
    const written = fbs.getWritten();
    try testing.expect((written[0] & stream.OFF) != 0);
}

test "RFC 9000 §19.8 - STREAM frame with small offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: ?u64 = 1024;
    _ = try stream.writeStream(w, 4, offset, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(?u64, 1024), result.offset);
}

test "RFC 9000 §19.8 - STREAM frame with large offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: ?u64 = 1 << 30; // 1 GB offset
    _ = try stream.writeStream(w, 4, offset, false, "Data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(?u64, 1 << 30), result.offset);
}

// =============================================================================
// FIN Flag Tests
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame with FIN flag set" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, null, true, "Final data");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(true, result.fin);

    // FIN bit should be set
    const written = fbs.getWritten();
    try testing.expect((written[0] & stream.FIN) != 0);
}

test "RFC 9000 §19.8 - STREAM frame with FIN flag clear" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, null, false, "Not final");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(false, result.fin);

    // FIN bit should NOT be set
    const written = fbs.getWritten();
    try testing.expect((written[0] & stream.FIN) == 0);
}

test "RFC 9000 §19.8 - STREAM frame with FIN and empty data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data: []const u8 = "";
    _ = try stream.writeStream(w, 4, null, true, data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(true, result.fin);
    try testing.expectEqual(@as(usize, 0), result.data.len);
}

// =============================================================================
// Flag Combination Tests
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame flags: no offset, no FIN" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, null, false, "Data");

    const written = fbs.getWritten();
    const type_byte = written[0];

    // Base type (0x08) + LEN flag (0x02)
    try testing.expect((type_byte & stream.OFF) == 0);
    try testing.expect((type_byte & stream.LEN) != 0); // LEN always set
    try testing.expect((type_byte & stream.FIN) == 0);
}

test "RFC 9000 §19.8 - STREAM frame flags: offset, no FIN" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, 100, false, "Data");

    const written = fbs.getWritten();
    const type_byte = written[0];

    try testing.expect((type_byte & stream.OFF) != 0);
    try testing.expect((type_byte & stream.LEN) != 0);
    try testing.expect((type_byte & stream.FIN) == 0);
}

test "RFC 9000 §19.8 - STREAM frame flags: no offset, FIN" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, null, true, "Data");

    const written = fbs.getWritten();
    const type_byte = written[0];

    try testing.expect((type_byte & stream.OFF) == 0);
    try testing.expect((type_byte & stream.LEN) != 0);
    try testing.expect((type_byte & stream.FIN) != 0);
}

test "RFC 9000 §19.8 - STREAM frame flags: offset, FIN" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, 200, true, "Data");

    const written = fbs.getWritten();
    const type_byte = written[0];

    try testing.expect((type_byte & stream.OFF) != 0);
    try testing.expect((type_byte & stream.LEN) != 0);
    try testing.expect((type_byte & stream.FIN) != 0);
}

test "RFC 9000 §19.8 - STREAM frame type byte range 0x08-0x0f" {
    // STREAM frames have base type 0x08 with 3 flag bits
    // Possible values: 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f

    var buf: [256]u8 = undefined;

    // Test all combinations
    const test_cases = [_]struct { offset: ?u64, fin: bool }{
        .{ .offset = null, .fin = false }, // 0x08 | LEN
        .{ .offset = null, .fin = true },  // 0x08 | LEN | FIN
        .{ .offset = 0, .fin = false },    // 0x08 | OFF | LEN
        .{ .offset = 0, .fin = true },     // 0x08 | OFF | LEN | FIN
    };

    for (test_cases) |tc| {
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();
        _ = try stream.writeStream(w, 4, tc.offset, tc.fin, "X");

        const type_byte = buf[0];
        try testing.expect(type_byte >= 0x08 and type_byte <= 0x0f);
    }
}

// =============================================================================
// Data Length Variation Tests
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame with empty data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data: []const u8 = "";
    _ = try stream.writeStream(w, 4, null, false, data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(usize, 0), result.data.len);
}

test "RFC 9000 §19.8 - STREAM frame with single byte data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "X";
    _ = try stream.writeStream(w, 4, null, false, data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9000 §19.8 - STREAM frame with large data" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    var large_data: [1024]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }

    _ = try stream.writeStream(w, 4, 0, false, &large_data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqualSlices(u8, &large_data, result.data);
}

// =============================================================================
// Multiple Streams Tests
// =============================================================================

test "RFC 9000 §19.8 - Multiple STREAM frames for different streams" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Stream 0
    const n1 = try stream.writeStream(w, 0, null, false, "Stream0");

    // Stream 4
    const n2 = try stream.writeStream(w, 4, null, false, "Stream4");

    const written = fbs.getWritten();

    const r1 = try stream.decodeStream(written);
    try testing.expectEqual(@as(u64, 0), r1.stream_id);
    try testing.expectEqual(n1, r1.n);

    const r2 = try stream.decodeStream(written[r1.n..]);
    try testing.expectEqual(@as(u64, 4), r2.stream_id);
    try testing.expectEqual(n2, r2.n);
}

test "RFC 9000 §19.8 - Multiple STREAM frames same stream different offsets" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // First chunk at offset 0
    _ = try stream.writeStream(w, 4, 0, false, "AAA");

    // Second chunk at offset 3
    _ = try stream.writeStream(w, 4, 3, false, "BBB");

    // Third chunk at offset 6
    _ = try stream.writeStream(w, 4, 6, true, "CCC");

    const written = fbs.getWritten();

    var pos: usize = 0;
    const r1 = try stream.decodeStream(written[pos..]);
    try testing.expectEqual(@as(u64, 4), r1.stream_id);
    try testing.expectEqual(@as(?u64, 0), r1.offset);
    try testing.expectEqual(false, r1.fin);
    pos += r1.n;

    const r2 = try stream.decodeStream(written[pos..]);
    try testing.expectEqual(@as(u64, 4), r2.stream_id);
    try testing.expectEqual(@as(?u64, 3), r2.offset);
    try testing.expectEqual(false, r2.fin);
    pos += r2.n;

    const r3 = try stream.decodeStream(written[pos..]);
    try testing.expectEqual(@as(u64, 4), r3.stream_id);
    try testing.expectEqual(@as(?u64, 6), r3.offset);
    try testing.expectEqual(true, r3.fin);
}

// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: decodeStream with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, stream.decodeStream(buf));
}

test "negative: decodeStream with wrong frame type" {
    const buf = [_]u8{ 0x06, 0x00 }; // CRYPTO frame, not STREAM
    try testing.expectError(error.InvalidFrameType, stream.decodeStream(&buf));
}

test "negative: decodeStream truncated at stream ID" {
    const buf = [_]u8{0x0a}; // Type only, missing stream ID
    try testing.expectError(error.Truncated, stream.decodeStream(&buf));
}

test "negative: decodeStream truncated at offset" {
    // Type (0x0c = OFF | LEN) + stream ID (0) + missing offset
    const buf = [_]u8{ 0x0e, 0x00 }; // OFF flag set but no offset
    try testing.expectError(error.Truncated, stream.decodeStream(&buf));
}

test "negative: decodeStream truncated at length" {
    // Type (0x0a = LEN) + stream ID (0) + missing length
    const buf = [_]u8{ 0x0a, 0x00 };
    try testing.expectError(error.Truncated, stream.decodeStream(&buf));
}

test "negative: decodeStream truncated data" {
    // Type + stream ID + length (10) + only 2 bytes data
    const buf = [_]u8{ 0x0a, 0x00, 0x0a, 0xaa, 0xbb };
    try testing.expectError(error.Truncated, stream.decodeStream(&buf));
}

test "negative: decodeStream length exceeds buffer" {
    // Type + stream ID + length (100) + short data
    const buf = [_]u8{ 0x0a, 0x00, 0x64, 0x01, 0x02 };
    try testing.expectError(error.Truncated, stream.decodeStream(&buf));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: STREAM frame bytes consumed matches written" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const written = try stream.writeStream(w, 8, 123, true, "Test");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(written, result.n);
}

test "boundary: STREAM frame with all flags set" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // OFF + LEN + FIN
    _ = try stream.writeStream(w, 4, 100, true, "Data");

    const written = fbs.getWritten();
    const type_byte = written[0];

    try testing.expectEqual(@as(u8, 0x0f), type_byte); // 0x08 | 0x04 | 0x02 | 0x01
}

test "boundary: STREAM frame offset + length require multi-byte varints" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Large offset and large data
    const offset: u64 = 100000;
    var large_data: [256]u8 = undefined;
    @memset(&large_data, 0x42);

    _ = try stream.writeStream(w, 4, offset, false, &large_data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(?u64, 100000), result.offset);
    try testing.expectEqual(@as(usize, 256), result.data.len);
}

test "boundary: STREAM frame data slice is correct subset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "ABCDEFGH";
    _ = try stream.writeStream(w, 4, 0, false, data);

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
    // Verify it's a slice of the original buffer
    try testing.expect(@intFromPtr(result.data.ptr) >= @intFromPtr(&buf[0]));
    try testing.expect(@intFromPtr(result.data.ptr) < @intFromPtr(&buf[0]) + buf.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §19.8 - STREAM frame type is 0x08-0x0f" {
    try testing.expectEqual(@as(u8, 0x08), @intFromEnum(types.FrameType.STREAM));

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 4, null, false, "X");

    const type_byte = buf[0];
    try testing.expect((type_byte & 0xf8) == 0x08);
}

test "RFC 9000 §19.8 - STREAM frame format: Type + StreamID + [Offset] + [Length] + Data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try stream.writeStream(w, 12, 100, false, "Test");

    const written = fbs.getWritten();

    // Type byte
    try testing.expect((written[0] & 0xf8) == 0x08);

    // Decode to verify structure
    const result = try stream.decodeStream(written);
    try testing.expectEqual(@as(u64, 12), result.stream_id);
    try testing.expectEqual(@as(?u64, 100), result.offset);
    try testing.expectEqualStrings("Test", result.data);
}

test "RFC 9000 §19.8 - OFF bit indicates offset presence" {
    var buf: [256]u8 = undefined;

    // Without offset
    var fbs1 = std.io.fixedBufferStream(&buf);
    _ = try stream.writeStream(fbs1.writer(), 4, null, false, "X");
    try testing.expect((buf[0] & stream.OFF) == 0);

    // With offset
    var fbs2 = std.io.fixedBufferStream(&buf);
    _ = try stream.writeStream(fbs2.writer(), 4, 0, false, "X");
    try testing.expect((buf[0] & stream.OFF) != 0);
}

test "RFC 9000 §19.8 - LEN bit indicates length field presence" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // writeStream always sets LEN flag
    _ = try stream.writeStream(w, 4, null, false, "X");

    try testing.expect((buf[0] & stream.LEN) != 0);
}

test "RFC 9000 §19.8 - FIN bit indicates end of stream" {
    var buf: [256]u8 = undefined;

    // Without FIN
    var fbs1 = std.io.fixedBufferStream(&buf);
    _ = try stream.writeStream(fbs1.writer(), 4, null, false, "X");
    try testing.expect((buf[0] & stream.FIN) == 0);

    // With FIN
    var fbs2 = std.io.fixedBufferStream(&buf);
    _ = try stream.writeStream(fbs2.writer(), 4, null, true, "X");
    try testing.expect((buf[0] & stream.FIN) != 0);
}

test "RFC 9000 §2 - Stream IDs identify independent data flows" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Different streams can have same offset independently
    _ = try stream.writeStream(w, 0, 0, false, "Stream0");
    _ = try stream.writeStream(w, 4, 0, false, "Stream4");
    _ = try stream.writeStream(w, 8, 0, false, "Stream8");

    const written = fbs.getWritten();

    var pos: usize = 0;
    var count: usize = 0;
    while (pos < written.len) {
        const r = try stream.decodeStream(written[pos..]);
        try testing.expectEqual(@as(?u64, 0), r.offset); // All at offset 0
        pos += r.n;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
}

test "RFC 9000 §3 - Stream offset enables reliable ordered delivery" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Send stream data with gaps (out of order)
    _ = try stream.writeStream(w, 4, 10, false, "Second");
    _ = try stream.writeStream(w, 4, 0, false, "First");
    _ = try stream.writeStream(w, 4, 5, false, "Middle");

    const written = fbs.getWritten();

    // Decode all frames
    var frames: [3]struct { offset: ?u64, data: []const u8 } = undefined;
    var pos: usize = 0;
    for (&frames) |*f| {
        const result = try stream.decodeStream(written[pos..]);
        f.* = .{ .offset = result.offset, .data = result.data };
        pos += result.n;
    }

    // Application should reassemble by offset order
    try testing.expectEqual(@as(?u64, 10), frames[0].offset);
    try testing.expectEqual(@as(?u64, 0), frames[1].offset);
    try testing.expectEqual(@as(?u64, 5), frames[2].offset);
}

test "RFC 9000 §19.8 - FIN signals clean stream termination" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Stream data followed by FIN
    _ = try stream.writeStream(w, 4, 0, false, "Part1");
    _ = try stream.writeStream(w, 4, 5, false, "Part2");
    _ = try stream.writeStream(w, 4, 10, true, "Part3"); // FIN on last frame

    const written = fbs.getWritten();

    var pos: usize = 0;
    var final_frame = false;

    while (pos < written.len) {
        const r = try stream.decodeStream(written[pos..]);
        if (r.fin) {
            final_frame = true;
        }
        pos += r.n;
    }

    try testing.expect(final_frame); // Stream properly terminated
}

test "RFC 9000 §4 - STREAM frames interact with flow control" {
    // STREAM frames respect MAX_STREAM_DATA limits
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const stream_id: u64 = 4;
    const offset: u64 = 1000;
    const data = "Data within flow control window";

    _ = try stream.writeStream(w, stream_id, offset, false, data);

    const result = try stream.decodeStream(fbs.getWritten());

    // Receiver checks: offset + data.len <= local MAX_STREAM_DATA
    const end_offset = result.offset.? + result.data.len;
    try testing.expectEqual(@as(u64, 1000 + data.len), end_offset);
}

test "RFC 9000 §2 - Client-initiated streams have even IDs" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Client-initiated bidirectional: 0, 4, 8, ...
    _ = try stream.writeStream(w, 0, null, false, "X");
    _ = try stream.writeStream(w, 4, null, false, "X");
    _ = try stream.writeStream(w, 8, null, false, "X");

    const written = fbs.getWritten();

    var pos: usize = 0;
    var count: usize = 0;
    while (pos < written.len) {
        const r = try stream.decodeStream(written[pos..]);
        try testing.expect(r.stream_id % 2 == 0); // All even
        pos += r.n;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
}

test "RFC 9000 §19.8 - STREAM frame supports zero-length data with FIN" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Empty STREAM frame with FIN (closes stream without more data)
    _ = try stream.writeStream(w, 4, 100, true, "");

    const result = try stream.decodeStream(fbs.getWritten());

    try testing.expectEqual(@as(usize, 0), result.data.len);
    try testing.expectEqual(true, result.fin);
}
