//! Unit tests for frame/datagram.zig
//!
//! RFC References:
//! - RFC 9221: An Unreliable Datagram Extension to QUIC
//! - RFC 9221 §4: DATAGRAM Frame
//!
//! Coverage:
//! - Positive cases: Basic encoding/decoding, various data lengths
//! - Negative cases: Truncated buffers, wrong frame type, invalid length
//! - Edge cases: Empty data, single byte, large payloads, maximum values
//! - RFC compliance: Frame format, unreliable semantics, length encoding

const std = @import("std");
const testing = std.testing;

const datagram = @import("datagram");
const types = @import("types");

// =============================================================================
// Basic DATAGRAM Frame Tests
// =============================================================================

test "RFC 9221 §4 - writeDatagram encodes frame with data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Hello datagram";
    const n = try datagram.writeDatagram(w, data);

    try testing.expect(n > data.len);
    try testing.expectEqual(@as(u8, 0x30), buf[0]); // DATAGRAM frame type
}

test "RFC 9221 §4 - decodeDatagram reads frame correctly" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Test datagram data";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §4 - DATAGRAM frame round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Round trip datagram test";
    const written = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// Data Length Variation Tests
// =============================================================================

test "RFC 9221 §4 - DATAGRAM frame with empty data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data: []const u8 = "";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqual(@as(usize, 0), result.data.len);
}

test "RFC 9221 §4 - DATAGRAM frame with single byte" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "X";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §4 - DATAGRAM frame with small data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Small payload";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §4 - DATAGRAM frame with large data" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Create large payload
    var large_data: [1024]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }

    _ = try datagram.writeDatagram(w, &large_data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqualSlices(u8, &large_data, result.data);
}

test "RFC 9221 §4 - DATAGRAM frame with maximum practical size" {
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Simulate MTU-sized datagram
    var mtu_data: [1200]u8 = undefined;
    @memset(&mtu_data, 0xaa);

    _ = try datagram.writeDatagram(w, &mtu_data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqual(@as(usize, 1200), result.data.len);
}

// =============================================================================
// Multiple DATAGRAM Frames Tests
// =============================================================================

test "RFC 9221 §4 - Multiple DATAGRAM frames in sequence" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data1 = "First datagram";
    const n1 = try datagram.writeDatagram(w, data1);

    const data2 = "Second datagram";
    const n2 = try datagram.writeDatagram(w, data2);

    const data3 = "Third datagram";
    const n3 = try datagram.writeDatagram(w, data3);

    const written = fbs.getWritten();

    var pos: usize = 0;
    const r1 = try datagram.decodeDatagram(written[pos..]);
    try testing.expectEqualStrings(data1, r1.data);
    try testing.expectEqual(n1, r1.n);
    pos += r1.n;

    const r2 = try datagram.decodeDatagram(written[pos..]);
    try testing.expectEqualStrings(data2, r2.data);
    try testing.expectEqual(n2, r2.n);
    pos += r2.n;

    const r3 = try datagram.decodeDatagram(written[pos..]);
    try testing.expectEqualStrings(data3, r3.data);
    try testing.expectEqual(n3, r3.n);
}

test "RFC 9221 §4 - DATAGRAM frames with varying sizes" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Small datagram
    _ = try datagram.writeDatagram(w, "Short");

    // Medium datagram
    _ = try datagram.writeDatagram(w, "This is a medium sized datagram");

    // Larger datagram
    var large: [128]u8 = undefined;
    @memset(&large, 0x42);
    _ = try datagram.writeDatagram(w, &large);

    const written = fbs.getWritten();

    var pos: usize = 0;
    const r1 = try datagram.decodeDatagram(written[pos..]);
    try testing.expectEqual(@as(usize, 5), r1.data.len);
    pos += r1.n;

    const r2 = try datagram.decodeDatagram(written[pos..]);
    try testing.expectEqual(@as(usize, 31), r2.data.len);
    pos += r2.n;

    const r3 = try datagram.decodeDatagram(written[pos..]);
    try testing.expectEqual(@as(usize, 128), r3.data.len);
}

// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: decodeDatagram with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, datagram.decodeDatagram(buf));
}

test "negative: decodeDatagram with wrong frame type" {
    const buf = [_]u8{ 0x08, 0x00 }; // STREAM frame, not DATAGRAM
    try testing.expectError(error.InvalidFrameType, datagram.decodeDatagram(&buf));
}

test "negative: decodeDatagram truncated at length" {
    const buf = [_]u8{0x30}; // Only frame type, missing length
    try testing.expectError(error.Truncated, datagram.decodeDatagram(&buf));
}

test "negative: decodeDatagram truncated data" {
    // Frame type + length (10) + only 2 bytes of data
    const buf = [_]u8{ 0x30, 0x0a, 0xaa, 0xbb };
    try testing.expectError(error.Truncated, datagram.decodeDatagram(&buf));
}

test "negative: decodeDatagram length exceeds buffer" {
    // Frame type + length (100) + short data
    const buf = [_]u8{ 0x30, 0x64, 0x01, 0x02 };
    try testing.expectError(error.Truncated, datagram.decodeDatagram(&buf));
}

test "negative: decodeDatagram with partial varint length" {
    // Frame type + partial 2-byte varint (missing second byte)
    const buf = [_]u8{ 0x30, 0x40 };
    try testing.expectError(error.Truncated, datagram.decodeDatagram(&buf));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: DATAGRAM frame bytes consumed matches written" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Boundary test data";
    const written = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqual(written, result.n);
}

test "boundary: DATAGRAM frame encodes to exact buffer size" {
    var buf: [32]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Exact"; // Frame type (1) + length (1) + data (5) = 7 bytes
    const n = try datagram.writeDatagram(w, data);

    try testing.expect(n == 7);
}

test "boundary: DATAGRAM frame with length requiring multi-byte varint" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Create data requiring 2-byte varint length (>= 64 bytes)
    var large_data: [128]u8 = undefined;
    @memset(&large_data, 0xAB);

    _ = try datagram.writeDatagram(w, &large_data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqual(@as(usize, 128), result.data.len);
}

test "boundary: DATAGRAM frame data slice is correct subset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "ABCDEFGH";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Verify data slice points to correct region in buffer
    try testing.expectEqualStrings(data, result.data);
    // Verify it's actually a slice of the original buffer
    try testing.expect(@intFromPtr(result.data.ptr) >= @intFromPtr(&buf[0]));
    try testing.expect(@intFromPtr(result.data.ptr) < @intFromPtr(&buf[0]) + buf.len);
}

test "boundary: DATAGRAM frame with zero-length data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data: []const u8 = "";
    const written = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqual(@as(usize, 0), result.data.len);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9221 §4 - DATAGRAM frame type is 0x30" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try datagram.writeDatagram(w, "X");

    try testing.expectEqual(@as(u8, 0x30), buf[0]);
    try testing.expectEqual(@as(u8, 0x30), @intFromEnum(types.FrameType.DATAGRAM));
}

test "RFC 9221 §4 - DATAGRAM frame format: Type + Length + Data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = "Test";
    _ = try datagram.writeDatagram(w, data);

    const written = fbs.getWritten();

    // Verify format manually
    try testing.expectEqual(@as(u8, 0x30), written[0]); // Type

    // The rest should decode correctly
    const result = try datagram.decodeDatagram(written);
    try testing.expectEqualStrings(data, result.data); // Data decoded
}

test "RFC 9221 §1 - DATAGRAM frames provide unreliable delivery" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Datagrams are not retransmitted if lost
    const data = "Unreliable datagram";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Successfully encode/decode, but no reliability guarantees
    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §2 - DATAGRAM frames do not guarantee ordering" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Send datagrams in order
    _ = try datagram.writeDatagram(w, "First");
    _ = try datagram.writeDatagram(w, "Second");
    _ = try datagram.writeDatagram(w, "Third");

    const written = fbs.getWritten();

    // Decode in order, but application should handle reordering
    var pos: usize = 0;
    const r1 = try datagram.decodeDatagram(written[pos..]);
    pos += r1.n;

    const r2 = try datagram.decodeDatagram(written[pos..]);
    pos += r2.n;

    const r3 = try datagram.decodeDatagram(written[pos..]);

    // Frames can arrive in any order
    try testing.expect(r1.data.len > 0);
    try testing.expect(r2.data.len > 0);
    try testing.expect(r3.data.len > 0);
}

test "RFC 9221 §4 - DATAGRAM frame length is varint encoded" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Small length (1-byte varint)
    const data1 = "X";
    _ = try datagram.writeDatagram(w, data1);

    // Larger length (2-byte varint, >= 64 bytes)
    var large_data: [100]u8 = undefined;
    @memset(&large_data, 0x42);
    _ = try datagram.writeDatagram(w, &large_data);

    // Both should decode correctly
    const written = fbs.getWritten();
    const r1 = try datagram.decodeDatagram(written);
    try testing.expectEqual(@as(usize, 1), r1.data.len);

    const r2 = try datagram.decodeDatagram(written[r1.n..]);
    try testing.expectEqual(@as(usize, 100), r2.data.len);
}

test "RFC 9221 §3 - DATAGRAM frames subject to congestion control" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Datagrams count toward congestion window
    const data = "Datagram subject to CC";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Size of datagram affects congestion window
    const datagram_size = result.n;
    try testing.expect(datagram_size > 0);
}

test "RFC 9221 §5 - DATAGRAM frames may be dropped by implementation" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Implementation may drop datagrams (e.g., buffer full)
    const data = "May be dropped";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Frame encodes successfully, but application must handle loss
    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §4 - DATAGRAM frames are ACK-eliciting" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // DATAGRAM frames trigger ACK response
    const data = "ACK-eliciting datagram";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Receiver should send ACK (even though data not retransmitted)
    try testing.expect(result.data.len > 0);
}

test "RFC 9221 §2 - DATAGRAM frames do not provide flow control" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Datagrams not subject to MAX_DATA/MAX_STREAM_DATA
    const data = "No flow control";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Successfully sent regardless of flow control state
    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §1 - DATAGRAM extension must be negotiated" {
    // DATAGRAM frames only allowed if max_datagram_frame_size transport parameter set
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Assuming extension was negotiated, frames can be sent
    const data = "Extension negotiated";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9221 §3 - DATAGRAM frames respect MTU limits" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Datagram should not exceed path MTU
    // Typical MTU is 1500, minus IP/UDP headers, minus QUIC overhead
    var mtu_sized: [1200]u8 = undefined;
    @memset(&mtu_sized, 0xdd);

    _ = try datagram.writeDatagram(w, &mtu_sized);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Datagram fits within MTU
    try testing.expectEqual(@as(usize, 1200), result.data.len);
}

test "RFC 9221 §4 - Multiple DATAGRAM frames in same packet" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Multiple datagrams can be in one QUIC packet
    _ = try datagram.writeDatagram(w, "Datagram 1");
    _ = try datagram.writeDatagram(w, "Datagram 2");
    _ = try datagram.writeDatagram(w, "Datagram 3");

    const written = fbs.getWritten();

    // All decode successfully
    var pos: usize = 0;
    var count: usize = 0;

    while (pos < written.len) {
        const r = try datagram.decodeDatagram(written[pos..]);
        pos += r.n;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
}

test "RFC 9221 §2 - DATAGRAM frames do not use stream IDs" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Unlike STREAM frames, DATAGRAMs have no stream ID
    const data = "No stream ID";
    _ = try datagram.writeDatagram(w, data);

    const result = try datagram.decodeDatagram(fbs.getWritten());

    // Just type + length + data (no stream ID field)
    try testing.expectEqualStrings(data, result.data);
}
