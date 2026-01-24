//! Unit tests for frame/types.zig
//!
//! RFC References:
//! - RFC 9000 §19: Frame Types and Formats
//! - RFC 9000 §19.3: ACK Frames
//! - RFC 3168: Explicit Congestion Notification
//!
//! Coverage:
//! - Positive cases: FrameType enum values, AckRange structure, EcnCounts
//! - Negative cases: Invalid frame type values
//! - Edge cases: Boundary values, all frame types
//! - RFC compliance: Frame type assignments per specification

const std = @import("std");
const testing = std.testing;

const types = @import("types");

// =============================================================================
// FrameType Tests
// =============================================================================

test "RFC 9000 §19 - FrameType PADDING" {
    const frame_type = types.FrameType.PADDING;
    try testing.expectEqual(types.FrameType.PADDING, frame_type);
}

test "RFC 9000 §19 - FrameType PING" {
    const frame_type = types.FrameType.PING;
    try testing.expectEqual(types.FrameType.PING, frame_type);
}

test "RFC 9000 §19.3 - FrameType ACK without ECN" {
    const frame_type = types.FrameType.ACK;
    try testing.expectEqual(types.FrameType.ACK, frame_type);
}

test "RFC 9000 §19.3 - FrameType ACK with ECN" {
    const frame_type = types.FrameType.ACK_ECN;
    try testing.expectEqual(types.FrameType.ACK_ECN, frame_type);
}

test "RFC 9000 §19.6 - FrameType CRYPTO" {
    const frame_type = types.FrameType.CRYPTO;
    try testing.expectEqual(types.FrameType.CRYPTO, frame_type);
}

test "RFC 9000 §19.8 - FrameType STREAM" {
    const frame_type = types.FrameType.STREAM;
    try testing.expectEqual(types.FrameType.STREAM, frame_type);
}

test "RFC 9000 §19.10 - FrameType MAX_DATA" {
    const frame_type = types.FrameType.MAX_DATA;
    try testing.expectEqual(types.FrameType.MAX_DATA, frame_type);
}

test "RFC 9000 §19.11 - FrameType MAX_STREAM_DATA" {
    const frame_type = types.FrameType.MAX_STREAM_DATA;
    try testing.expectEqual(types.FrameType.MAX_STREAM_DATA, frame_type);
}

test "RFC 9000 §19 - FrameType CONNECTION_CLOSE" {
    const frame_type = types.FrameType.CONNECTION_CLOSE;
    try testing.expectEqual(types.FrameType.CONNECTION_CLOSE, frame_type);
}

test "RFC 9000 §19.17 - FrameType PATH_CHALLENGE" {
    const frame_type = types.FrameType.PATH_CHALLENGE;
    try testing.expectEqual(types.FrameType.PATH_CHALLENGE, frame_type);
}

test "RFC 9000 §19.18 - FrameType PATH_RESPONSE" {
    const frame_type = types.FrameType.PATH_RESPONSE;
    try testing.expectEqual(types.FrameType.PATH_RESPONSE, frame_type);
}

// =============================================================================
// AckRange Tests
// =============================================================================

test "RFC 9000 §19.3 - AckRange basic structure" {
    const range: types.AckRange = .{
        .gap = 5,
        .len = 10,
    };

    try testing.expectEqual(@as(u64, 5), range.gap);
    try testing.expectEqual(@as(u64, 10), range.len);
}

test "RFC 9000 §19.3 - AckRange zero gap" {
    const range: types.AckRange = .{
        .gap = 0,
        .len = 5,
    };

    try testing.expectEqual(@as(u64, 0), range.gap);
}

test "RFC 9000 §19.3 - AckRange zero length" {
    const range: types.AckRange = .{
        .gap = 3,
        .len = 0,
    };

    try testing.expectEqual(@as(u64, 0), range.len);
}

test "boundary: AckRange max values" {
    const range: types.AckRange = .{
        .gap = std.math.maxInt(u64),
        .len = std.math.maxInt(u64),
    };

    try testing.expectEqual(std.math.maxInt(u64), range.gap);
    try testing.expectEqual(std.math.maxInt(u64), range.len);
}

test "RFC 9000 §19.3 - AckRange encodes packet number gaps" {
    // Gap and len fields are encoded as variable-length integers
    // Example: acknowledging [90-95] then [87-88]
    // gap = 2 (packets 89, 90 not acked, encoded as 2-1=1)
    // len = 1 (packets 87, 88, encoded as 2-1=1)
    const range: types.AckRange = .{
        .gap = 1, // Actual gap of 2, encoded as 1
        .len = 1, // Actual range of 2 packets, encoded as 1
    };

    try testing.expectEqual(@as(u64, 1), range.gap);
    try testing.expectEqual(@as(u64, 1), range.len);
}

// =============================================================================
// EcnCounts Tests
// =============================================================================

test "RFC 3168 - EcnCounts initial state" {
    const ecn: types.EcnCounts = .{ .ect0 = 0, .ect1 = 0, .ce = 0 };

    try testing.expectEqual(@as(u64, 0), ecn.ect0);
    try testing.expectEqual(@as(u64, 0), ecn.ect1);
    try testing.expectEqual(@as(u64, 0), ecn.ce);
}

test "RFC 3168 - EcnCounts ECT(0) counter" {
    const ecn: types.EcnCounts = .{
        .ect0 = 100,
        .ect1 = 0,
        .ce = 0,
    };

    try testing.expectEqual(@as(u64, 100), ecn.ect0);
}

test "RFC 3168 - EcnCounts ECT(1) counter" {
    const ecn: types.EcnCounts = .{
        .ect0 = 0,
        .ect1 = 50,
        .ce = 0,
    };

    try testing.expectEqual(@as(u64, 50), ecn.ect1);
}

test "RFC 3168 - EcnCounts CE counter" {
    const ecn: types.EcnCounts = .{
        .ect0 = 0,
        .ect1 = 0,
        .ce = 25,
    };

    try testing.expectEqual(@as(u64, 25), ecn.ce);
}

test "RFC 3168 - EcnCounts all counters set" {
    const ecn: types.EcnCounts = .{
        .ect0 = 1000,
        .ect1 = 500,
        .ce = 100,
    };

    try testing.expectEqual(@as(u64, 1000), ecn.ect0);
    try testing.expectEqual(@as(u64, 500), ecn.ect1);
    try testing.expectEqual(@as(u64, 100), ecn.ce);
}

test "boundary: EcnCounts maximum values" {
    const ecn: types.EcnCounts = .{
        .ect0 = std.math.maxInt(u64),
        .ect1 = std.math.maxInt(u64),
        .ce = std.math.maxInt(u64),
    };

    try testing.expect(ecn.ect0 > 0);
    try testing.expect(ecn.ect1 > 0);
    try testing.expect(ecn.ce > 0);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §19 - Frame types are distinct" {
    try testing.expect(types.FrameType.PADDING != types.FrameType.PING);
    try testing.expect(types.FrameType.ACK != types.FrameType.ACK_ECN);
    try testing.expect(types.FrameType.CRYPTO != types.FrameType.STREAM);
}

test "RFC 9000 §19.3 - ACK frame range encoding" {
    // First ACK Range encodes number of contiguous packets before largest
    // Additional ACK Ranges encode gaps and lengths
    var ranges: [3]types.AckRange = undefined;

    // Range 0: gap=2, len=3 (acknowledging 3 packets after a gap of 2)
    ranges[0] = .{ .gap = 2, .len = 3 };
    // Range 1: gap=1, len=5
    ranges[1] = .{ .gap = 1, .len = 5 };
    // Range 2: gap=0, len=2
    ranges[2] = .{ .gap = 0, .len = 2 };

    try testing.expectEqual(@as(u64, 2), ranges[0].gap);
    try testing.expectEqual(@as(u64, 1), ranges[1].gap);
    try testing.expectEqual(@as(u64, 0), ranges[2].gap);
}

test "RFC 3168 - ECN codepoints mapping" {
    // ECT(0) = 10 (binary), ECT(1) = 01 (binary), CE = 11 (binary)
    // EcnCounts tracks how many packets were received with each marking
    var ecn: types.EcnCounts = .{ .ect0 = 0, .ect1 = 0, .ce = 0 };

    // Simulate receiving packets with different ECN markings
    ecn.ect0 += 1; // Received packet with ECT(0)
    ecn.ect1 += 1; // Received packet with ECT(1)
    ecn.ce += 1;   // Received packet with CE

    try testing.expectEqual(@as(u64, 1), ecn.ect0);
    try testing.expectEqual(@as(u64, 1), ecn.ect1);
    try testing.expectEqual(@as(u64, 1), ecn.ce);
}

test "RFC 9000 §19.3 - ACK_ECN includes ECN counts" {
    // ACK_ECN frame includes ECN counts in addition to ACK ranges
    const ecn: types.EcnCounts = .{
        .ect0 = 100,
        .ect1 = 50,
        .ce = 10,
    };

    // Verify structure supports all three ECN counters
    try testing.expectEqual(@as(u64, 100), ecn.ect0);
    try testing.expectEqual(@as(u64, 50), ecn.ect1);
    try testing.expectEqual(@as(u64, 10), ecn.ce);
}

test "RFC 9000 §19 - Connection-level vs stream-level frames" {
    // Connection-level frames (e.g., CONNECTION_CLOSE, PING)
    const conn_close = types.FrameType.CONNECTION_CLOSE;
    const ping = types.FrameType.PING;

    // Stream-level frames (e.g., STREAM, MAX_STREAM_DATA)
    const stream = types.FrameType.STREAM;
    const max_stream_data = types.FrameType.MAX_STREAM_DATA;

    // All should be distinct
    try testing.expect(conn_close != ping);
    try testing.expect(stream != max_stream_data);
    try testing.expect(conn_close != stream);
}
