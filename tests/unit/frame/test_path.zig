//! Unit tests for frame/path.zig
//!
//! RFC References:
//! - RFC 9000 §19.17: PATH_CHALLENGE Frame
//! - RFC 9000 §19.18: PATH_RESPONSE Frame
//! - RFC 9000 §9: Connection Migration and Path Validation
//! - RFC 9000 §8.2: Path Validation
//!
//! Coverage:
//! - Positive cases: Basic encoding/decoding, challenge-response pairing, data variations
//! - Negative cases: Truncated buffers, wrong frame type
//! - Edge cases: All-zero data, all-ones data, random data, pattern data
//! - RFC compliance: Frame format, path validation semantics, data echo requirement

const std = @import("std");
const testing = std.testing;

const path = @import("path");
const types = @import("types");

// =============================================================================
// PATH_CHALLENGE Frame Tests
// =============================================================================

test "RFC 9000 §19.17 - writePathChallenge encodes frame with 8-byte data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const n = try path.writePathChallenge(w, data);

    try testing.expectEqual(@as(usize, 9), n); // 1 byte type + 8 bytes data
    try testing.expectEqual(@as(u8, 0x1a), buf[0]); // PATH_CHALLENGE frame type
}

test "RFC 9000 §19.17 - decodePathChallenge reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    _ = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
    try testing.expectEqual(@as(usize, 9), result.n);
}

test "RFC 9000 §19.17 - PATH_CHALLENGE round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    const written = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// PATH_RESPONSE Frame Tests
// =============================================================================

test "RFC 9000 §19.18 - writePathResponse encodes frame with 8-byte data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const n = try path.writePathResponse(w, data);

    try testing.expectEqual(@as(usize, 9), n); // 1 byte type + 8 bytes data
    try testing.expectEqual(@as(u8, 0x1b), buf[0]); // PATH_RESPONSE frame type
}

test "RFC 9000 §19.18 - decodePathResponse reads frame correctly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    _ = try path.writePathResponse(w, data);

    const result = try path.decodePathResponse(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
    try testing.expectEqual(@as(usize, 9), result.n);
}

test "RFC 9000 §19.18 - PATH_RESPONSE round trip" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const written = try path.writePathResponse(w, data);

    const result = try path.decodePathResponse(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// Challenge-Response Pairing Tests
// =============================================================================

test "RFC 9000 §9 - PATH_RESPONSE echoes PATH_CHALLENGE data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Sender sends PATH_CHALLENGE
    const challenge_data = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    _ = try path.writePathChallenge(w, challenge_data);

    // Receiver responds with PATH_RESPONSE using same data
    _ = try path.writePathResponse(w, challenge_data);

    const written = fbs.getWritten();

    // Decode challenge
    const challenge = try path.decodePathChallenge(written);
    try testing.expectEqualSlices(u8, &challenge_data, &challenge.data);

    // Decode response
    const response = try path.decodePathResponse(written[challenge.n..]);
    try testing.expectEqualSlices(u8, &challenge_data, &response.data);

    // Verify response echoes challenge
    try testing.expectEqualSlices(u8, &challenge.data, &response.data);
}

test "RFC 9000 §8.2 - Multiple challenge-response pairs" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // First challenge-response pair
    const data1 = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    _ = try path.writePathChallenge(w, data1);
    _ = try path.writePathResponse(w, data1);

    // Second challenge-response pair
    const data2 = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
    _ = try path.writePathChallenge(w, data2);
    _ = try path.writePathResponse(w, data2);

    const written = fbs.getWritten();

    // Decode all frames
    var pos: usize = 0;

    const c1 = try path.decodePathChallenge(written[pos..]);
    pos += c1.n;

    const r1 = try path.decodePathResponse(written[pos..]);
    pos += r1.n;

    const c2 = try path.decodePathChallenge(written[pos..]);
    pos += c2.n;

    const r2 = try path.decodePathResponse(written[pos..]);

    // Verify each response echoes its challenge
    try testing.expectEqualSlices(u8, &c1.data, &r1.data);
    try testing.expectEqualSlices(u8, &c2.data, &r2.data);
}

test "RFC 9000 §9 - PATH_CHALLENGE data must match in PATH_RESPONSE" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const challenge_data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    _ = try path.writePathChallenge(w, challenge_data);

    const challenge = try path.decodePathChallenge(fbs.getWritten());

    // Response must use exact challenge data
    var fbs2 = std.io.fixedBufferStream(&buf);
    const w2 = fbs2.writer();
    _ = try path.writePathResponse(w2, challenge.data);

    const response = try path.decodePathResponse(fbs2.getWritten());

    try testing.expectEqualSlices(u8, &challenge.data, &response.data);
}

// =============================================================================
// Data Variation Tests
// =============================================================================

test "RFC 9000 §19.17 - PATH_CHALLENGE with all-zero data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{0} ** 8;
    _ = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
}

test "RFC 9000 §19.17 - PATH_CHALLENGE with all-ones data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{0xff} ** 8;
    _ = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
}

test "RFC 9000 §19.17 - PATH_CHALLENGE with sequential data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    _ = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
}

test "RFC 9000 §19.17 - PATH_CHALLENGE with alternating pattern" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55 };
    _ = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
}

test "RFC 9000 §19.18 - PATH_RESPONSE with random-looking data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Simulate cryptographically random data
    const data = [_]u8{ 0x8f, 0x3d, 0xa1, 0x67, 0xc2, 0x5e, 0x94, 0xb3 };
    _ = try path.writePathResponse(w, data);

    const result = try path.decodePathResponse(fbs.getWritten());

    try testing.expectEqualSlices(u8, &data, &result.data);
}

// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: decodePathChallenge with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, path.decodePathChallenge(buf));
}

test "negative: decodePathChallenge with only type byte" {
    const buf = [_]u8{0x1a};
    try testing.expectError(error.Truncated, path.decodePathChallenge(&buf));
}

test "negative: decodePathChallenge with partial data" {
    const buf = [_]u8{ 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05 }; // Only 5 data bytes
    try testing.expectError(error.Truncated, path.decodePathChallenge(&buf));
}

test "negative: decodePathChallenge with wrong frame type" {
    const buf = [_]u8{ 0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try testing.expectError(error.InvalidFrameType, path.decodePathChallenge(&buf));
}

test "negative: decodePathResponse with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, path.decodePathResponse(buf));
}

test "negative: decodePathResponse with only type byte" {
    const buf = [_]u8{0x1b};
    try testing.expectError(error.Truncated, path.decodePathResponse(&buf));
}

test "negative: decodePathResponse with partial data" {
    const buf = [_]u8{ 0x1b, 0xaa, 0xbb, 0xcc }; // Only 3 data bytes
    try testing.expectError(error.Truncated, path.decodePathResponse(&buf));
}

test "negative: decodePathResponse with wrong frame type" {
    const buf = [_]u8{ 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try testing.expectError(error.InvalidFrameType, path.decodePathResponse(&buf));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: PATH_CHALLENGE exact buffer size" {
    var buf: [9]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const n = try path.writePathChallenge(w, data);

    try testing.expectEqual(@as(usize, 9), n);
    try testing.expectEqual(@as(usize, 9), fbs.pos);
}

test "boundary: PATH_RESPONSE exact buffer size" {
    var buf: [9]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    const n = try path.writePathResponse(w, data);

    try testing.expectEqual(@as(usize, 9), n);
    try testing.expectEqual(@as(usize, 9), fbs.pos);
}

test "boundary: PATH_CHALLENGE bytes consumed matches written" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const written = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqual(written, result.n);
}

test "boundary: PATH_RESPONSE bytes consumed matches written" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 };
    const written = try path.writePathResponse(w, data);

    const result = try path.decodePathResponse(fbs.getWritten());

    try testing.expectEqual(written, result.n);
}

test "boundary: PATH_CHALLENGE data is exact 8 bytes" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    _ = try path.writePathChallenge(w, data);

    const result = try path.decodePathChallenge(fbs.getWritten());

    try testing.expectEqual(@as(usize, 8), result.data.len);
}

test "boundary: PATH_RESPONSE data is exact 8 bytes" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    _ = try path.writePathResponse(w, data);

    const result = try path.decodePathResponse(fbs.getWritten());

    try testing.expectEqual(@as(usize, 8), result.data.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §19.17 - PATH_CHALLENGE frame type is 0x1a" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{1} ** 8;
    _ = try path.writePathChallenge(w, data);

    try testing.expectEqual(@as(u8, 0x1a), buf[0]);
    try testing.expectEqual(@as(u8, 0x1a), @intFromEnum(types.FrameType.PATH_CHALLENGE));
}

test "RFC 9000 §19.18 - PATH_RESPONSE frame type is 0x1b" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{1} ** 8;
    _ = try path.writePathResponse(w, data);

    try testing.expectEqual(@as(u8, 0x1b), buf[0]);
    try testing.expectEqual(@as(u8, 0x1b), @intFromEnum(types.FrameType.PATH_RESPONSE));
}

test "RFC 9000 §19.17 - PATH_CHALLENGE format: Type (1 byte) + Data (8 bytes)" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    const n = try path.writePathChallenge(w, data);

    try testing.expectEqual(@as(usize, 9), n); // 1 + 8

    const written = fbs.getWritten();
    try testing.expectEqual(@as(u8, 0x1a), written[0]); // Type
    try testing.expectEqualSlices(u8, &data, written[1..9]); // Data
}

test "RFC 9000 §19.18 - PATH_RESPONSE format: Type (1 byte) + Data (8 bytes)" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const data = [_]u8{ 0xf0, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21 };
    const n = try path.writePathResponse(w, data);

    try testing.expectEqual(@as(usize, 9), n); // 1 + 8

    const written = fbs.getWritten();
    try testing.expectEqual(@as(u8, 0x1b), written[0]); // Type
    try testing.expectEqualSlices(u8, &data, written[1..9]); // Data
}

test "RFC 9000 §9 - Path validation with challenge-response" {
    var buf: [64]u8 = undefined;

    // Endpoint A sends PATH_CHALLENGE on new path
    var fbs1 = std.io.fixedBufferStream(&buf);
    const challenge_data = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 };
    _ = try path.writePathChallenge(fbs1.writer(), challenge_data);

    const challenge = try path.decodePathChallenge(fbs1.getWritten());

    // Endpoint B receives challenge and sends PATH_RESPONSE
    var fbs2 = std.io.fixedBufferStream(&buf);
    _ = try path.writePathResponse(fbs2.writer(), challenge.data);

    const response = try path.decodePathResponse(fbs2.getWritten());

    // Path is validated when response data matches challenge data
    try testing.expectEqualSlices(u8, &challenge.data, &response.data);
}

test "RFC 9000 §8.2 - PATH_CHALLENGE contains unpredictable data" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // In practice, data should be cryptographically random
    // Here we use pseudo-random for testing
    const data1 = [_]u8{ 0x9f, 0x2a, 0x71, 0xb4, 0xd8, 0x3e, 0x65, 0xc0 };
    const data2 = [_]u8{ 0x1c, 0x8d, 0x42, 0xf7, 0xa3, 0x60, 0x9b, 0xe5 };

    // Two challenges should have different data
    _ = try path.writePathChallenge(w, data1);
    _ = try path.writePathChallenge(w, data2);

    const written = fbs.getWritten();

    const c1 = try path.decodePathChallenge(written);
    const c2 = try path.decodePathChallenge(written[c1.n..]);

    // Data should be different (not predictable)
    try testing.expect(!std.mem.eql(u8, &c1.data, &c2.data));
}

test "RFC 9000 §9.1 - Connection migration requires path validation" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Before migration, send PATH_CHALLENGE on new path
    const challenge_data = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    _ = try path.writePathChallenge(w, challenge_data);

    // Receive PATH_RESPONSE on new path
    _ = try path.writePathResponse(w, challenge_data);

    const written = fbs.getWritten();

    const challenge = try path.decodePathChallenge(written);
    const response = try path.decodePathResponse(written[challenge.n..]);

    // Migration proceeds after successful validation
    try testing.expectEqualSlices(u8, &challenge.data, &response.data);
}

test "RFC 9000 §9.4 - PATH_RESPONSE must echo PATH_CHALLENGE data exactly" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const challenge_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    _ = try path.writePathChallenge(w, challenge_data);

    const challenge = try path.decodePathChallenge(fbs.getWritten());

    // Response must use exact challenge data (byte-for-byte copy)
    var fbs2 = std.io.fixedBufferStream(&buf);
    _ = try path.writePathResponse(fbs2.writer(), challenge.data);

    const response = try path.decodePathResponse(fbs2.getWritten());

    // Every byte must match
    for (challenge.data, response.data) |c, r| {
        try testing.expectEqual(c, r);
    }
}

test "RFC 9000 §9 - Multiple outstanding PATH_CHALLENGE frames" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Send multiple challenges (probing multiple paths)
    const data1 = [_]u8{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    const data2 = [_]u8{ 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
    const data3 = [_]u8{ 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };

    _ = try path.writePathChallenge(w, data1);
    _ = try path.writePathChallenge(w, data2);
    _ = try path.writePathChallenge(w, data3);

    const written = fbs.getWritten();

    // Decode all challenges
    var pos: usize = 0;
    const c1 = try path.decodePathChallenge(written[pos..]);
    pos += c1.n;

    const c2 = try path.decodePathChallenge(written[pos..]);
    pos += c2.n;

    const c3 = try path.decodePathChallenge(written[pos..]);

    // Each challenge has unique data
    try testing.expectEqualSlices(u8, &data1, &c1.data);
    try testing.expectEqualSlices(u8, &data2, &c2.data);
    try testing.expectEqualSlices(u8, &data3, &c3.data);
}

test "RFC 9000 §8.2 - PATH_CHALLENGE sent on untested path" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Before using a new path, validate it with challenge
    const challenge_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
    _ = try path.writePathChallenge(w, challenge_data);

    const challenge = try path.decodePathChallenge(fbs.getWritten());

    // Endpoint must respond to prove path viability
    var fbs2 = std.io.fixedBufferStream(&buf);
    _ = try path.writePathResponse(fbs2.writer(), challenge.data);

    const response = try path.decodePathResponse(fbs2.getWritten());

    // Successful response validates the path
    try testing.expectEqualSlices(u8, &challenge.data, &response.data);
}

test "RFC 9000 §9.3 - PATH_RESPONSE sent in response to PATH_CHALLENGE" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Receive PATH_CHALLENGE
    const received_data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
    _ = try path.writePathChallenge(w, received_data);

    const challenge = try path.decodePathChallenge(fbs.getWritten());

    // Send PATH_RESPONSE with echoed data
    var fbs2 = std.io.fixedBufferStream(&buf);
    _ = try path.writePathResponse(fbs2.writer(), challenge.data);

    const response = try path.decodePathResponse(fbs2.getWritten());

    // Response successfully echoes challenge
    try testing.expectEqualSlices(u8, &challenge.data, &response.data);
}
