//! Unit tests for frame/crypto.zig
//!
//! RFC References:
//! - RFC 9000 §19.6: CRYPTO Frame
//! - RFC 9001 §4: TLS Handshake
//!
//! Coverage:
//! - Positive cases: Basic encoding/decoding, various offsets and lengths
//! - Negative cases: Truncated buffers, wrong frame type, invalid length
//! - Edge cases: Zero offset, empty data, maximum values, large payloads
//! - RFC compliance: Frame format, offset semantics, TLS handshake data carrier

const std = @import("std");
const testing = std.testing;

const crypto = @import("crypto");
const types = @import("types");

// =============================================================================
// Basic CRYPTO Frame Tests
// =============================================================================

test "RFC 9000 §19.6 - writeCrypto encodes frame with offset and data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data = "Hello";
    const n = try crypto.writeCrypto(w, offset, data);

    // Frame type (0x06) + offset (varint 0) + length (varint 5) + data
    try testing.expect(n > data.len);
    try testing.expectEqual(@as(u8, 0x06), buf[0]); // CRYPTO frame type
}

test "RFC 9000 §19.6 - decodeCrypto reads frame correctly" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 100;
    const data = "Test data";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 100), result.offset);
    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9000 §19.6 - CRYPTO frame round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 42;
    const data = "QUIC CRYPTO frame test";
    const written = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 42), result.offset);
    try testing.expectEqualStrings(data, result.data);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// Offset Variation Tests
// =============================================================================

test "RFC 9000 §19.6 - CRYPTO frame with zero offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data = "Initial handshake";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.offset);
    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9000 §19.6 - CRYPTO frame with small offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 127; // Small varint
    const data = "Data";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 127), result.offset);
}

test "RFC 9000 §19.6 - CRYPTO frame with large offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 100000; // Large varint
    const data = "Data";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 100000), result.offset);
}

test "RFC 9000 §19.6 - CRYPTO frame with maximum offset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = (1 << 62) - 1; // Max varint value
    const data = "X";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, (1 << 62) - 1), result.offset);
}

// =============================================================================
// Data Length Variation Tests
// =============================================================================

test "RFC 9000 §19.6 - CRYPTO frame with empty data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data: []const u8 = "";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.offset);
    try testing.expectEqual(@as(usize, 0), result.data.len);
}

test "RFC 9000 §19.6 - CRYPTO frame with single byte data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data = "X";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9000 §19.6 - CRYPTO frame with small data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data = "Small payload";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqualStrings(data, result.data);
}

test "RFC 9000 §19.6 - CRYPTO frame with large data" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Create large payload (simulate TLS handshake message)
    var large_data: [1024]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }

    const offset: u64 = 0;
    _ = try crypto.writeCrypto(w, offset, &large_data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqualSlices(u8, &large_data, result.data);
}

// =============================================================================
// Multiple Frames Tests
// =============================================================================

test "RFC 9000 §19.6 - Multiple CRYPTO frames with increasing offsets" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // First frame at offset 0
    const data1 = "Part1";
    const n1 = try crypto.writeCrypto(w, 0, data1);

    // Second frame at offset 5
    const data2 = "Part2";
    const n2 = try crypto.writeCrypto(w, 5, data2);

    const written = fbs.getWritten();

    // Decode first frame
    const result1 = try crypto.decodeCrypto(written);
    try testing.expectEqual(@as(u64, 0), result1.offset);
    try testing.expectEqualStrings(data1, result1.data);
    try testing.expectEqual(n1, result1.n);

    // Decode second frame
    const result2 = try crypto.decodeCrypto(written[result1.n..]);
    try testing.expectEqual(@as(u64, 5), result2.offset);
    try testing.expectEqualStrings(data2, result2.data);
    try testing.expectEqual(n2, result2.n);
}

test "RFC 9000 §19.6 - Out-of-order CRYPTO frames" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Simulate out-of-order delivery (offset 100, then offset 0)
    const data1 = "Later";
    _ = try crypto.writeCrypto(w, 100, data1);

    const data2 = "Earlier";
    _ = try crypto.writeCrypto(w, 0, data2);

    const written = fbs.getWritten();

    // Both should decode correctly with their offsets preserved
    const result1 = try crypto.decodeCrypto(written);
    try testing.expectEqual(@as(u64, 100), result1.offset);

    const result2 = try crypto.decodeCrypto(written[result1.n..]);
    try testing.expectEqual(@as(u64, 0), result2.offset);
}

// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: decodeCrypto with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, crypto.decodeCrypto(buf));
}

test "negative: decodeCrypto with wrong frame type" {
    const buf = [_]u8{ 0x01, 0x00 }; // PING frame type instead of CRYPTO
    try testing.expectError(error.InvalidFrameType, crypto.decodeCrypto(&buf));
}

test "negative: decodeCrypto truncated at offset" {
    const buf = [_]u8{0x06}; // Only frame type, missing offset
    try testing.expectError(error.Truncated, crypto.decodeCrypto(&buf));
}

test "negative: decodeCrypto truncated at length" {
    const buf = [_]u8{ 0x06, 0x00 }; // Frame type + offset, missing length
    try testing.expectError(error.Truncated, crypto.decodeCrypto(&buf));
}

test "negative: decodeCrypto truncated data" {
    // Frame type + offset (0) + length (10) + only 2 bytes of data
    const buf = [_]u8{ 0x06, 0x00, 0x0a, 0xaa, 0xbb };
    try testing.expectError(error.Truncated, crypto.decodeCrypto(&buf));
}

test "negative: decodeCrypto length exceeds buffer" {
    // Frame type + offset (0) + length (100) + short data
    const buf = [_]u8{ 0x06, 0x00, 0x64, 0x01, 0x02 };
    try testing.expectError(error.Truncated, crypto.decodeCrypto(&buf));
}

test "negative: decodeCrypto with partial varint offset" {
    // Frame type + partial 2-byte varint (missing second byte)
    const buf = [_]u8{ 0x06, 0x40 };
    try testing.expectError(error.Truncated, crypto.decodeCrypto(&buf));
}

test "negative: decodeCrypto with partial varint length" {
    // Frame type + offset (0) + partial 2-byte varint length
    const buf = [_]u8{ 0x06, 0x00, 0x40 };
    try testing.expectError(error.Truncated, crypto.decodeCrypto(&buf));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: CRYPTO frame encodes to exact buffer size" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data = "12345"; // Frame type (1) + offset (1) + length (1) + data (5) = 8 bytes
    const n = try crypto.writeCrypto(w, offset, data);

    try testing.expect(n == 8);
    try testing.expectEqualStrings(data, fbs.getWritten()[3..8]);
}

test "boundary: CRYPTO frame bytes consumed matches written" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 123;
    const data = "Boundary test";
    const written = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(written, result.n);
}

test "boundary: CRYPTO frame with offset requiring multi-byte varint" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Offset requires 2-byte varint (>= 64)
    const offset: u64 = 16384; // 0x4000
    const data = "Data";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(u64, 16384), result.offset);
}

test "boundary: CRYPTO frame with length requiring multi-byte varint" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Create data requiring 2-byte varint length (>= 64 bytes)
    var large_data: [128]u8 = undefined;
    @memset(&large_data, 0xAB);

    const offset: u64 = 0;
    _ = try crypto.writeCrypto(w, offset, &large_data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    try testing.expectEqual(@as(usize, 128), result.data.len);
}

test "boundary: CRYPTO frame data slice is correct subset" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 0;
    const data = "ABCDEFGH";
    _ = try crypto.writeCrypto(w, offset, data);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    // Verify data slice points to correct region in buffer
    try testing.expectEqualStrings(data, result.data);
    // Verify it's actually a slice of the original buffer
    try testing.expect(@intFromPtr(result.data.ptr) >= @intFromPtr(&buf[0]));
    try testing.expect(@intFromPtr(result.data.ptr) < @intFromPtr(&buf[0]) + buf.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §19.6 - CRYPTO frame type is 0x06" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try crypto.writeCrypto(w, 0, "X");

    try testing.expectEqual(@as(u8, 0x06), buf[0]);
    try testing.expectEqual(@as(u8, 0x06), @intFromEnum(types.FrameType.CRYPTO));
}

test "RFC 9000 §19.6 - CRYPTO frame format: Type + Offset + Length + Data" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const offset: u64 = 42;
    const data = "Test";
    _ = try crypto.writeCrypto(w, offset, data);

    const written = fbs.getWritten();

    // Verify format manually
    try testing.expectEqual(@as(u8, 0x06), written[0]); // Type

    // The rest should decode correctly
    const result = try crypto.decodeCrypto(written);
    try testing.expectEqual(@as(u64, 42), result.offset); // Offset decoded
    try testing.expectEqualStrings(data, result.data); // Data decoded
}

test "RFC 9001 §4 - CRYPTO carries TLS handshake messages" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Simulate TLS ClientHello message (simplified)
    const tls_handshake = "ClientHello TLS 1.3 data...";

    const offset: u64 = 0;
    _ = try crypto.writeCrypto(w, offset, tls_handshake);

    const result = try crypto.decodeCrypto(fbs.getWritten());

    // CRYPTO frame successfully carries handshake data
    try testing.expectEqualStrings(tls_handshake, result.data);
}

test "RFC 9000 §19.6 - CRYPTO frame offset enables stream-like delivery" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Send fragments at different offsets
    _ = try crypto.writeCrypto(w, 0, "AAA");
    _ = try crypto.writeCrypto(w, 3, "BBB");
    _ = try crypto.writeCrypto(w, 6, "CCC");

    const written = fbs.getWritten();

    // Decode each fragment
    var pos: usize = 0;
    const r1 = try crypto.decodeCrypto(written[pos..]);
    try testing.expectEqual(@as(u64, 0), r1.offset);
    pos += r1.n;

    const r2 = try crypto.decodeCrypto(written[pos..]);
    try testing.expectEqual(@as(u64, 3), r2.offset);
    pos += r2.n;

    const r3 = try crypto.decodeCrypto(written[pos..]);
    try testing.expectEqual(@as(u64, 6), r3.offset);

    // Offsets enable reassembly: offset 0 + "AAA" (len 3) → offset 3
    try testing.expectEqual(r1.offset + r1.data.len, r2.offset);
    try testing.expectEqual(r2.offset + r2.data.len, r3.offset);
}

test "RFC 9000 §19.6 - CRYPTO frame used during handshake" {
    // CRYPTO frames are only sent in Initial and Handshake packets
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Initial packet: ClientHello
    const client_hello = "ClientHello";
    _ = try crypto.writeCrypto(w, 0, client_hello);

    // Handshake packet: Certificate, CertificateVerify, Finished
    const server_handshake = "Certificate";
    _ = try crypto.writeCrypto(w, client_hello.len, server_handshake);

    // Both CRYPTO frames encode successfully
    try testing.expect(fbs.pos > 0);
}

test "RFC 9000 §19.6 - CRYPTO frame offset supports retransmission" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Original transmission at offset 100
    const data = "Retransmitted data";
    _ = try crypto.writeCrypto(w, 100, data);

    // If lost, can retransmit same offset
    var buf2: [256]u8 = undefined;
    var fbs2 = std.io.fixedBufferStream(&buf2);
    const w2 = fbs2.writer();
    _ = try crypto.writeCrypto(w2, 100, data);

    const result1 = try crypto.decodeCrypto(fbs.getWritten());
    const result2 = try crypto.decodeCrypto(fbs2.getWritten());

    // Same offset and data can be transmitted multiple times
    try testing.expectEqual(result1.offset, result2.offset);
    try testing.expectEqualStrings(result1.data, result2.data);
}

test "RFC 9000 §19.6 - CRYPTO frame length is varint encoded" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Small length (1-byte varint)
    const data1 = "X";
    _ = try crypto.writeCrypto(w, 0, data1);

    // Larger length (2-byte varint, >= 64 bytes)
    var large_data: [100]u8 = undefined;
    @memset(&large_data, 0x42);
    _ = try crypto.writeCrypto(w, 1, &large_data);

    // Both should decode correctly
    const written = fbs.getWritten();
    const r1 = try crypto.decodeCrypto(written);
    try testing.expectEqual(@as(usize, 1), r1.data.len);

    const r2 = try crypto.decodeCrypto(written[r1.n..]);
    try testing.expectEqual(@as(usize, 100), r2.data.len);
}

test "RFC 9000 §7.5 - CRYPTO data processed in offset order" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Receive frames out of order
    _ = try crypto.writeCrypto(w, 10, "Second");
    _ = try crypto.writeCrypto(w, 0, "First");
    _ = try crypto.writeCrypto(w, 5, "Middle");

    const written = fbs.getWritten();

    // Decode all frames
    var frames: [3]struct { offset: u64, data: []const u8 } = undefined;
    var pos: usize = 0;
    for (0..frames.len) |i| {
        const result = try crypto.decodeCrypto(written[pos..]);
        frames[i] = .{ .offset = result.offset, .data = result.data };
        pos += result.n;
    }

    // Application should process by offset order:
    // frames[1] (offset 0), frames[2] (offset 5), frames[0] (offset 10)
    try testing.expectEqual(@as(u64, 10), frames[0].offset);
    try testing.expectEqual(@as(u64, 0), frames[1].offset);
    try testing.expectEqual(@as(u64, 5), frames[2].offset);
}
