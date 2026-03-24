//! Unit tests for frame/ack.zig
//!
//! RFC References:
//! - RFC 9000 §19.3: ACK Frame
//! - RFC 9000 §19.3.2: ACK_ECN Frame
//! - RFC 9000 §13.2: Generating Acknowledgments
//! - RFC 3168: Explicit Congestion Notification
//!
//! Coverage:
//! - Positive cases: Basic ACK/ACK_ECN encoding/decoding, ranges, ECN counts
//! - Negative cases: Truncated buffers, wrong frame type, invalid ranges
//! - Edge cases: No ranges, multiple ranges, maximum values, ECN counts
//! - RFC compliance: Frame format, range semantics, ECN handling, delay encoding

const std = @import("std");
const testing = std.testing;

const ack = @import("ack");
const types = @import("types");

// =============================================================================
// Basic ACK Frame Tests (No Additional Ranges, No ECN)
// =============================================================================

test "RFC 9000 §19.3 - writeAck encodes basic ACK frame" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 100;
    const ack_delay: u64 = 25;
    const first_range: u64 = 10;
    const ranges: []const types.AckRange = &[_]types.AckRange{};
    const ecn: ?types.EcnCounts = null;

    const n = try ack.writeAck(w, largest, ack_delay, first_range, ranges, ecn);

    try testing.expect(n > 0);
    try testing.expectEqual(@as(u8, 0x02), buf[0]); // ACK frame type
}

test "RFC 9000 §19.3 - decodeAck reads basic ACK frame" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 50;
    const ack_delay: u64 = 10;
    const first_range: u64 = 5;
    const ranges: []const types.AckRange = &[_]types.AckRange{};
    _ = try ack.writeAck(w, largest, ack_delay, first_range, ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 50), result.largest);
    try testing.expectEqual(@as(u64, 10), result.ack_delay);
    try testing.expectEqual(@as(u64, 5), result.first_range);
    try testing.expectEqual(@as(usize, 0), result.ranges.len);
    try testing.expectEqual(@as(?types.EcnCounts, null), result.ecn);
}

test "RFC 9000 §19.3 - ACK frame round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 1000;
    const ack_delay: u64 = 100;
    const first_range: u64 = 20;
    const ranges: []const types.AckRange = &[_]types.AckRange{};
    const written = try ack.writeAck(w, largest, ack_delay, first_range, ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(largest, result.largest);
    try testing.expectEqual(ack_delay, result.ack_delay);
    try testing.expectEqual(first_range, result.first_range);
    try testing.expectEqual(written, result.n);
}

// =============================================================================
// ACK Frame with Additional Ranges Tests
// =============================================================================

test "RFC 9000 §19.3 - ACK frame with single additional range" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 100;
    const ack_delay: u64 = 10;
    const first_range: u64 = 5; // Acks 100-95
    const ranges = [_]types.AckRange{
        .{ .gap = 2, .len = 3 }, // Gap of 2, then ack 3 packets
    };

    _ = try ack.writeAck(w, largest, ack_delay, first_range, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 100), result.largest);
    try testing.expectEqual(@as(u64, 5), result.first_range);
    try testing.expectEqual(@as(usize, 1), result.ranges.len);
    try testing.expectEqual(@as(u64, 2), result.ranges[0].gap);
    try testing.expectEqual(@as(u64, 3), result.ranges[0].len);
}

test "RFC 9000 §19.3 - ACK frame with multiple additional ranges" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 200;
    const ack_delay: u64 = 20;
    const first_range: u64 = 10; // Acks 200-190
    const ranges = [_]types.AckRange{
        .{ .gap = 5, .len = 8 }, // Range 1
        .{ .gap = 3, .len = 12 }, // Range 2
        .{ .gap = 1, .len = 6 }, // Range 3
    };

    _ = try ack.writeAck(w, largest, ack_delay, first_range, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(usize, 3), result.ranges.len);
    try testing.expectEqual(@as(u64, 5), result.ranges[0].gap);
    try testing.expectEqual(@as(u64, 8), result.ranges[0].len);
    try testing.expectEqual(@as(u64, 3), result.ranges[1].gap);
    try testing.expectEqual(@as(u64, 12), result.ranges[1].len);
    try testing.expectEqual(@as(u64, 1), result.ranges[2].gap);
    try testing.expectEqual(@as(u64, 6), result.ranges[2].len);
}

test "RFC 9000 §19.3 - ACK frame range semantics" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Acknowledge packets: 100-95 (first_range), then gap, then 92-90
    const largest: u64 = 100;
    const first_range: u64 = 5; // Acks 100, 99, 98, 97, 96, 95 (6 packets)
    const ranges = [_]types.AckRange{
        .{ .gap = 2, .len = 2 }, // Skip 94, 93; ack 92, 91, 90 (3 packets)
    };

    _ = try ack.writeAck(w, largest, 0, first_range, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    // First range: largest - first_range = 100 - 5 = 95 (lowest)
    // So acks: 100, 99, 98, 97, 96, 95
    try testing.expectEqual(@as(u64, 5), result.first_range);

    // Gap = 2 means skip 2 packets (94, 93)
    // Then len = 2 means ack 3 packets (2 + 1): 92, 91, 90
    try testing.expectEqual(@as(u64, 2), result.ranges[0].gap);
    try testing.expectEqual(@as(u64, 2), result.ranges[0].len);
}

// =============================================================================
// ACK_ECN Frame Tests (with ECN Counts)
// =============================================================================

test "RFC 9000 §19.3.2 - writeAck with ECN counts creates ACK_ECN frame" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ecn_counts = types.EcnCounts{
        .ect0 = 10,
        .ect1 = 5,
        .ce = 2,
    };

    _ = try ack.writeAck(w, 100, 10, 5, &[_]types.AckRange{}, ecn_counts);

    try testing.expectEqual(@as(u8, 0x03), buf[0]); // ACK_ECN frame type
}

test "RFC 9000 §19.3.2 - decodeAck reads ACK_ECN frame correctly" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ecn_counts = types.EcnCounts{
        .ect0 = 50,
        .ect1 = 30,
        .ce = 10,
    };

    _ = try ack.writeAck(w, 200, 20, 10, &[_]types.AckRange{}, ecn_counts);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expect(result.ecn != null);
    try testing.expectEqual(@as(u64, 50), result.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 30), result.ecn.?.ect1);
    try testing.expectEqual(@as(u64, 10), result.ecn.?.ce);
}

test "RFC 9000 §19.3.2 - ACK_ECN frame round trip" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 300;
    const ack_delay: u64 = 15;
    const first_range: u64 = 8;
    const ecn_counts = types.EcnCounts{
        .ect0 = 100,
        .ect1 = 75,
        .ce = 25,
    };

    const written = try ack.writeAck(w, largest, ack_delay, first_range, &[_]types.AckRange{}, ecn_counts);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(largest, result.largest);
    try testing.expectEqual(ack_delay, result.ack_delay);
    try testing.expectEqual(first_range, result.first_range);
    try testing.expect(result.ecn != null);
    try testing.expectEqual(ecn_counts.ect0, result.ecn.?.ect0);
    try testing.expectEqual(ecn_counts.ect1, result.ecn.?.ect1);
    try testing.expectEqual(ecn_counts.ce, result.ecn.?.ce);
    try testing.expectEqual(written, result.n);
}

test "RFC 3168 - ECN counts track congestion signals" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // ECT(0) = ECN-Capable Transport (0)
    // ECT(1) = ECN-Capable Transport (1)
    // CE = Congestion Experienced
    const ecn_counts = types.EcnCounts{
        .ect0 = 1000, // Most packets ECT(0)
        .ect1 = 50, // Some packets ECT(1)
        .ce = 5, // Few packets experienced congestion
    };

    _ = try ack.writeAck(w, 1100, 50, 100, &[_]types.AckRange{}, ecn_counts);

    const result = try ack.decodeAck(fbs.getWritten());

    // Receiver reports ECN counts to sender
    try testing.expectEqual(@as(u64, 1000), result.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 50), result.ecn.?.ect1);
    try testing.expectEqual(@as(u64, 5), result.ecn.?.ce);
}

// =============================================================================
// Largest Acknowledged Variation Tests
// =============================================================================

test "RFC 9000 §19.3 - ACK frame with largest = 0" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try ack.writeAck(w, 0, 0, 0, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.largest);
}

test "RFC 9000 §19.3 - ACK frame with small largest" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try ack.writeAck(w, 127, 10, 5, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 127), result.largest);
}

test "RFC 9000 §19.3 - ACK frame with large largest" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const largest: u64 = 1_000_000;
    _ = try ack.writeAck(w, largest, 100, 50, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 1_000_000), result.largest);
}

// =============================================================================
// ACK Delay Variation Tests
// =============================================================================

test "RFC 9000 §19.3 - ACK frame with zero ack_delay" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try ack.writeAck(w, 100, 0, 5, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.ack_delay);
}

test "RFC 9000 §19.3 - ACK frame with small ack_delay" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ack_delay: u64 = 25; // 25 * 2^ack_delay_exponent microseconds
    _ = try ack.writeAck(w, 100, ack_delay, 5, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 25), result.ack_delay);
}

test "RFC 9000 §19.3 - ACK frame with large ack_delay" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ack_delay: u64 = 10000;
    _ = try ack.writeAck(w, 100, ack_delay, 5, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 10000), result.ack_delay);
}

// =============================================================================
// First Range Variation Tests
// =============================================================================

test "RFC 9000 §19.3 - ACK frame with zero first_range" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // first_range = 0 means only largest packet is acknowledged
    _ = try ack.writeAck(w, 50, 10, 0, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 0), result.first_range);
}

test "RFC 9000 §19.3 - ACK frame with large first_range" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Acknowledge many contiguous packets
    const first_range: u64 = 1000;
    _ = try ack.writeAck(w, 1500, 50, first_range, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 1000), result.first_range);
}

// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: decodeAck with empty buffer" {
    const buf: []const u8 = &[_]u8{};
    try testing.expectError(error.Truncated, ack.decodeAck(buf));
}

test "negative: decodeAck with wrong frame type" {
    const buf = [_]u8{ 0x08, 0x00 }; // STREAM frame, not ACK
    try testing.expectError(error.InvalidFrameType, ack.decodeAck(&buf));
}

test "negative: decodeAck truncated at largest" {
    const buf = [_]u8{0x02}; // Only frame type, missing largest
    try testing.expectError(error.Truncated, ack.decodeAck(&buf));
}

test "negative: decodeAck truncated at ack_delay" {
    const buf = [_]u8{ 0x02, 0x64 }; // Type + largest, missing ack_delay
    try testing.expectError(error.Truncated, ack.decodeAck(&buf));
}

test "negative: decodeAck truncated at range count" {
    const buf = [_]u8{ 0x02, 0x64, 0x0a }; // Type + largest + ack_delay, missing range count
    try testing.expectError(error.Truncated, ack.decodeAck(&buf));
}

test "negative: decodeAck truncated at first_range" {
    const buf = [_]u8{ 0x02, 0x64, 0x0a, 0x00 }; // Missing first_range
    try testing.expectError(error.Truncated, ack.decodeAck(&buf));
}

test "negative: decodeAck truncated in additional ranges" {
    // Type + largest + ack_delay + range_count (1) + first_range + gap (missing len)
    const buf = [_]u8{ 0x02, 0x64, 0x0a, 0x01, 0x05, 0x02 };
    try testing.expectError(error.Truncated, ack.decodeAck(&buf));
}

test "negative: decodeAck ACK_ECN truncated at ECN counts" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Write valid ACK_ECN frame
    const ecn_counts = types.EcnCounts{ .ect0 = 10, .ect1 = 5, .ce = 2 };
    _ = try ack.writeAck(w, 100, 10, 5, &[_]types.AckRange{}, ecn_counts);

    // Truncate before all ECN counts
    const written = fbs.getWritten();
    const truncated = written[0 .. written.len - 2]; // Remove last 2 bytes

    try testing.expectError(error.Truncated, ack.decodeAck(truncated));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: ACK frame bytes consumed matches written" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ranges = [_]types.AckRange{
        .{ .gap = 5, .len = 8 },
        .{ .gap = 3, .len = 12 },
    };

    const written = try ack.writeAck(w, 500, 50, 25, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(written, result.n);
}

test "boundary: ACK frame with 16 ranges (within buffer)" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // 16 ranges — well within the 64-range buffer capacity
    var ranges: [16]types.AckRange = undefined;
    for (&ranges, 0..) |*r, i| {
        r.* = .{ .gap = @intCast(i + 1), .len = @intCast(i * 2) };
    }

    _ = try ack.writeAck(w, 1000, 100, 50, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(usize, 16), result.ranges.len);
}

test "boundary: ACK frame with maximum range count (64)" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // 64 ranges — exactly at buffer capacity
    var ranges: [64]types.AckRange = undefined;
    for (&ranges, 0..) |*r, i| {
        r.* = .{ .gap = @intCast(i + 1), .len = @intCast(i % 8) };
    }

    _ = try ack.writeAck(w, 5000, 200, 100, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(usize, 64), result.ranges.len);
}

test "security: ACK frame with oversized range count (>256) is rejected" {
    // Craft a raw ACK frame with range_count = 257 (exceeds hard ceiling of 256).
    // ACK frame: type(0x02) + largest(varint) + ack_delay(varint) + range_count(varint) + first_range(varint) + ranges...
    // We only need the header to trigger the rejection before any ranges are parsed.
    var raw: [16]u8 = undefined;
    raw[0] = 0x02; // ACK frame type
    raw[1] = 0x00; // largest = 0 (1-byte varint)
    raw[2] = 0x00; // ack_delay = 0 (1-byte varint)
    // range_count = 257: 2-byte varint encoding: 0x41, 0x01
    raw[3] = 0x41;
    raw[4] = 0x01;
    // first_range = 0 (1-byte varint)
    raw[5] = 0x00;
    // No actual range data needed — decoder should reject before parsing ranges

    const result = ack.decodeAck(&raw);
    try testing.expectError(error.TooManyAckRanges, result);
}

test "security: ACK frame with 65 ranges (exceeds buffer capacity) is rejected" {
    // Craft a raw ACK frame with range_count = 65 (exceeds internal buffer of 64).
    var raw: [16]u8 = undefined;
    raw[0] = 0x02; // ACK frame type
    raw[1] = 0x00; // largest = 0
    raw[2] = 0x00; // ack_delay = 0
    // range_count = 65: 2-byte varint: 0x40 (prefix 01 + high 6 bits = 0), 0x41 (low 8 bits = 65)
    raw[3] = 0x40;
    raw[4] = 0x41;
    raw[5] = 0x00; // first_range = 0

    const result = ack.decodeAck(&raw);
    try testing.expectError(error.TooManyAckRanges, result);
}

test "boundary: ACK_ECN with all ECN counts zero" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ecn_counts = types.EcnCounts{ .ect0 = 0, .ect1 = 0, .ce = 0 };
    _ = try ack.writeAck(w, 100, 10, 5, &[_]types.AckRange{}, ecn_counts);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expect(result.ecn != null);
    try testing.expectEqual(@as(u64, 0), result.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 0), result.ecn.?.ect1);
    try testing.expectEqual(@as(u64, 0), result.ecn.?.ce);
}

test "boundary: ACK_ECN with large ECN counts" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ecn_counts = types.EcnCounts{
        .ect0 = 1_000_000,
        .ect1 = 500_000,
        .ce = 100_000,
    };

    _ = try ack.writeAck(w, 2_000_000, 1000, 100, &[_]types.AckRange{}, ecn_counts);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 1_000_000), result.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 500_000), result.ecn.?.ect1);
    try testing.expectEqual(@as(u64, 100_000), result.ecn.?.ce);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §19.3 - ACK frame type is 0x02" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    _ = try ack.writeAck(w, 100, 10, 5, &[_]types.AckRange{}, null);

    try testing.expectEqual(@as(u8, 0x02), buf[0]);
    try testing.expectEqual(@as(u8, 0x02), @intFromEnum(types.FrameType.ACK));
}

test "RFC 9000 §19.3.2 - ACK_ECN frame type is 0x03" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ecn_counts = types.EcnCounts{ .ect0 = 10, .ect1 = 5, .ce = 2 };
    _ = try ack.writeAck(w, 100, 10, 5, &[_]types.AckRange{}, ecn_counts);

    try testing.expectEqual(@as(u8, 0x03), buf[0]);
    try testing.expectEqual(@as(u8, 0x03), @intFromEnum(types.FrameType.ACK_ECN));
}

test "RFC 9000 §19.3 - ACK frame format: Type + Largest + Delay + RangeCount + FirstRange + [Ranges]" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    const ranges = [_]types.AckRange{.{ .gap = 2, .len = 3 }};
    _ = try ack.writeAck(w, 100, 25, 10, &ranges, null);

    const written = fbs.getWritten();

    // Type byte
    try testing.expectEqual(@as(u8, 0x02), written[0]);

    // Decode to verify structure
    const result = try ack.decodeAck(written);
    try testing.expectEqual(@as(u64, 100), result.largest);
    try testing.expectEqual(@as(u64, 25), result.ack_delay);
    try testing.expectEqual(@as(u64, 10), result.first_range);
    try testing.expectEqual(@as(usize, 1), result.ranges.len);
}

test "RFC 9000 §13.2 - ACK frame acknowledges received packets" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Acknowledge packets 100-90 (first_range = 10)
    const largest: u64 = 100;
    const first_range: u64 = 10; // Acks 100, 99, ..., 90 (11 packets)

    _ = try ack.writeAck(w, largest, 0, first_range, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    // Lowest acknowledged = largest - first_range = 100 - 10 = 90
    const lowest_acked = result.largest - result.first_range;
    try testing.expectEqual(@as(u64, 90), lowest_acked);
}

test "RFC 9000 §13.2 - ACK ranges encode non-contiguous acknowledgments" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Ack packets: 100-98, skip 97-95, ack 94-92
    const largest: u64 = 100;
    const first_range: u64 = 2; // Acks 100, 99, 98
    const ranges = [_]types.AckRange{
        .{ .gap = 2, .len = 2 }, // Skip 97, 96, 95 (gap=2); ack 94, 93, 92 (len=2)
    };

    _ = try ack.writeAck(w, largest, 0, first_range, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    // Verify range encoding
    try testing.expectEqual(@as(u64, 2), result.first_range);
    try testing.expectEqual(@as(usize, 1), result.ranges.len);
    try testing.expectEqual(@as(u64, 2), result.ranges[0].gap);
    try testing.expectEqual(@as(u64, 2), result.ranges[0].len);
}

test "RFC 9000 §13.2.1 - ACK delay scaled by ack_delay_exponent" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // ack_delay is encoded scaled value
    // Actual delay = ack_delay * 2^ack_delay_exponent microseconds
    // Default exponent is 3
    const ack_delay_encoded: u64 = 100; // Represents 100 * 2^3 = 800 microseconds

    _ = try ack.writeAck(w, 100, ack_delay_encoded, 5, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    try testing.expectEqual(@as(u64, 100), result.ack_delay);
    // Application multiplies by 2^ack_delay_exponent to get actual delay
}

test "RFC 3168 - ACK_ECN frame reports ECN feedback" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Receiver counts ECN markings on received packets
    const ecn_counts = types.EcnCounts{
        .ect0 = 95, // 95 packets marked ECT(0)
        .ect1 = 3, // 3 packets marked ECT(1)
        .ce = 2, // 2 packets marked CE (congestion experienced)
    };

    _ = try ack.writeAck(w, 100, 10, 99, &[_]types.AckRange{}, ecn_counts);

    const result = try ack.decodeAck(fbs.getWritten());

    // Sender uses ECN feedback to detect congestion
    try testing.expect(result.ecn != null);
    const total_ecn = result.ecn.?.ect0 + result.ecn.?.ect1 + result.ecn.?.ce;
    try testing.expectEqual(@as(u64, 100), total_ecn);
}

test "RFC 9000 §19.3 - ACK frame must acknowledge at least one packet" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // first_range = 0 means only largest is acknowledged (1 packet)
    _ = try ack.writeAck(w, 50, 10, 0, &[_]types.AckRange{}, null);

    const result = try ack.decodeAck(fbs.getWritten());

    // At least packet 50 is acknowledged
    try testing.expectEqual(@as(u64, 50), result.largest);
    try testing.expectEqual(@as(u64, 0), result.first_range);
}

test "RFC 9000 §13.2 - Multiple ACK frames can acknowledge same packets" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // First ACK acknowledges packets 0-50
    const n1 = try ack.writeAck(w, 50, 10, 50, &[_]types.AckRange{}, null);

    // Second ACK acknowledges packets 0-100 (includes previous range)
    const n2 = try ack.writeAck(w, 100, 20, 100, &[_]types.AckRange{}, null);

    const written = fbs.getWritten();

    const r1 = try ack.decodeAck(written);
    try testing.expectEqual(@as(u64, 50), r1.largest);

    const r2 = try ack.decodeAck(written[r1.n..]);
    try testing.expectEqual(@as(u64, 100), r2.largest);

    try testing.expect(n1 > 0 and n2 > 0);
}

test "RFC 9000 §19.3 - Range gap calculation" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Ack 100-98 (first_range=2)
    // Gap of 3 means skip 3 packets: 97, 96, 95
    // Then ack 94-92 (len=2 means 3 packets)
    const ranges = [_]types.AckRange{
        .{ .gap = 3, .len = 2 },
    };

    _ = try ack.writeAck(w, 100, 0, 2, &ranges, null);

    const result = try ack.decodeAck(fbs.getWritten());

    // First range: 100 - 2 = 98 (lowest in first range)
    // Gap: 98 - 3 - 1 = 94 (highest in next range)
    // Next range: 94 - 2 = 92 (lowest in next range)
    try testing.expectEqual(@as(u64, 3), result.ranges[0].gap);
    try testing.expectEqual(@as(u64, 2), result.ranges[0].len);
}
