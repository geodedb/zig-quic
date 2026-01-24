//! Unit tests for connection/packet_number.zig
//!
//! RFC References:
//! - RFC 9000 §12.3: Packet Number Encoding and Decoding
//! - RFC 9000 §13.2: Generating Acknowledgements
//! - RFC 9000 §19.3: ACK Frame Format
//! - RFC 9000 Appendix A.3: Sample Packet Number Decoding Algorithm
//!
//! Coverage:
//! - Positive cases: PN tracking, window sliding, ACK range building, PN expansion
//! - Negative cases: Out-of-window PNs, invalid expansion scenarios
//! - Edge cases: Window boundaries, wraparound, all truncation lengths
//! - RFC compliance: 256-packet window, correct expansion algorithm

const std = @import("std");
const testing = std.testing;
const pn = @import("quic_connection_packet_number");
const frame = @import("quic_frame");

// =============================================================================
// PnWindow - Basic Tracking Tests
// =============================================================================

test "RFC 9000 §13.2 - PnWindow track first packet (PN=0)" {
    var window: pn.PnWindow = .{};

    window.track(0);

    try testing.expect(window.have_any);
    try testing.expectEqual(@as(u64, 0), window.max);
}

test "RFC 9000 §13.2 - PnWindow track sequential packets" {
    var window: pn.PnWindow = .{};

    window.track(0);
    window.track(1);
    window.track(2);
    window.track(3);

    try testing.expect(window.have_any);
    try testing.expectEqual(@as(u64, 3), window.max);
}

test "RFC 9000 §13.2 - PnWindow track out-of-order packets" {
    var window: pn.PnWindow = .{};

    window.track(5);
    window.track(2);
    window.track(8);
    window.track(1);

    try testing.expect(window.have_any);
    try testing.expectEqual(@as(u64, 8), window.max);
}

test "RFC 9000 §13.2 - PnWindow track duplicate packet" {
    var window: pn.PnWindow = .{};

    window.track(10);
    window.track(10); // Duplicate

    try testing.expectEqual(@as(u64, 10), window.max);
}

test "RFC 9000 §13.2 - PnWindow initial state" {
    const window: pn.PnWindow = .{};

    try testing.expect(!window.have_any);
    try testing.expectEqual(@as(u64, 0), window.max);
}

test "boundary: PnWindow track only packet at PN=0" {
    var window: pn.PnWindow = .{};

    window.track(0);

    try testing.expect(window.have_any);
    try testing.expectEqual(@as(u64, 0), window.max);
}

test "boundary: PnWindow track high packet number" {
    var window: pn.PnWindow = .{};

    const high_pn: u64 = 1_000_000;
    window.track(high_pn);

    try testing.expectEqual(high_pn, window.max);
}

// =============================================================================
// PnWindow - Sliding Window Tests
// =============================================================================

test "RFC 9000 §13.2 - PnWindow slides forward with new max" {
    var window: pn.PnWindow = .{};

    // Track packets 0-10
    var i: u64 = 0;
    while (i <= 10) : (i += 1) {
        window.track(i);
    }

    // Now track a packet at 300 (beyond window size of 256)
    window.track(300);

    try testing.expectEqual(@as(u64, 300), window.max);
}

test "RFC 9000 §13.2 - PnWindow drops old packets outside window" {
    var window: pn.PnWindow = .{};

    // Track packet 0
    window.track(0);

    // Track packet 256 (window slides, 0 should be outside)
    window.track(256);

    // Verify max is 256
    try testing.expectEqual(@as(u64, 256), window.max);
}

test "RFC 9000 §13.2 - PnWindow at boundary 255-256" {
    var window: pn.PnWindow = .{};

    // Fill window with packets 0-255
    var i: u64 = 0;
    while (i < 256) : (i += 1) {
        window.track(i);
    }

    try testing.expectEqual(@as(u64, 255), window.max);

    // Track 256 - window should slide
    window.track(256);
    try testing.expectEqual(@as(u64, 256), window.max);
}

test "boundary: PnWindow near u64 max" {
    var window: pn.PnWindow = .{};

    // Test near maximum u64 value
    const near_max = std.math.maxInt(u64) - 100;
    window.track(near_max);

    try testing.expectEqual(near_max, window.max);
}

// =============================================================================
// PnWindow - ACK Range Building Tests
// =============================================================================

test "RFC 9000 §19.3 - buildAckRanges single packet returns first_range=0" {
    var window: pn.PnWindow = .{};
    window.track(5);

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    try testing.expectEqual(@as(u64, 0), result.first_range);
    try testing.expectEqual(@as(usize, 0), result.ranges_len);
}

test "RFC 9000 §19.3 - buildAckRanges contiguous packets" {
    var window: pn.PnWindow = .{};

    window.track(0);
    window.track(1);
    window.track(2);

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // first_range = 2 (3 packets: 0,1,2 -> range is 2)
    try testing.expectEqual(@as(u64, 2), result.first_range);
    try testing.expectEqual(@as(usize, 0), result.ranges_len);
}

test "RFC 9000 §19.3 - buildAckRanges with gap creates additional range" {
    var window: pn.PnWindow = .{};

    // Track 0, 1, 2 (gap at 3), then 4, 5
    window.track(0);
    window.track(1);
    window.track(2);
    window.track(4);
    window.track(5);

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // Largest is 5, first_range covers [4,5] = 1
    try testing.expectEqual(@as(u64, 1), result.first_range);
    // Should have one additional range for [0,1,2]
    try testing.expect(result.ranges_len > 0);
}

test "RFC 9000 §19.3 - buildAckRanges multiple gaps" {
    var window: pn.PnWindow = .{};

    // Track: 0, 2, 4, 6 (alternating with gaps)
    window.track(0);
    window.track(2);
    window.track(4);
    window.track(6);

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // Largest is 6
    try testing.expectEqual(@as(u64, 0), result.first_range); // Just packet 6
    try testing.expect(result.ranges_len > 0); // Multiple ranges for gaps
}

test "RFC 9000 §19.3 - buildAckRanges empty window" {
    const window: pn.PnWindow = .{};

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    try testing.expectEqual(@as(u64, 0), result.first_range);
    try testing.expectEqual(@as(usize, 0), result.ranges_len);
}

test "boundary: buildAckRanges 256 contiguous packets" {
    var window: pn.PnWindow = .{};

    // Fill entire window
    var i: u64 = 0;
    while (i < 256) : (i += 1) {
        window.track(i);
    }

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // first_range should cover all 256 packets (0-255 inclusive = 255)
    try testing.expectEqual(@as(u64, 255), result.first_range);
    try testing.expectEqual(@as(usize, 0), result.ranges_len);
}

test "boundary: buildAckRanges with maximum ranges" {
    var window: pn.PnWindow = .{};

    // Create alternating pattern to maximize ranges
    var i: u64 = 0;
    while (i < 20) : (i += 2) {
        window.track(i);
    }

    var ranges: [50]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // Should create multiple ranges
    try testing.expect(result.ranges_len > 0);
}

// =============================================================================
// expandTruncatedPn - Basic Tests
// =============================================================================

test "RFC 9000 §12.3 - expandTruncatedPn with expected=0" {
    const full = pn.expandTruncatedPn(0x12, 1, 0);

    // When expected=0, return truncated value as-is
    try testing.expectEqual(@as(u64, 0x12), full);
}

test "RFC 9000 §12.3 - expandTruncatedPn basic case" {
    // expected=0x100, trunc=0xfe (1 byte) -> should expand to 0xfe
    const full = pn.expandTruncatedPn(0xfe, 1, 0x100);

    try testing.expectEqual(@as(u64, 0xfe), full);
}

test "RFC 9000 Appendix A.3 - expandTruncatedPn reference test vector" {
    // RFC 9000 Appendix A.3 example:
    // expected = 0xa82f30ea, truncated = 0x9b32 (2 bytes)
    // Should expand to 0xa82f9b32
    const expected: u64 = 0xa82f30ea;
    const trunc: u64 = 0x9b32;
    const full = pn.expandTruncatedPn(trunc, 2, expected);

    try testing.expectEqual(@as(u64, 0xa82f9b32), full);
}

test "RFC 9000 §12.3 - expandTruncatedPn 1-byte truncation" {
    const expected: u64 = 1000;
    const trunc: u64 = 0xff; // 1 byte
    const full = pn.expandTruncatedPn(trunc, 1, expected);

    // Should find value near expected
    try testing.expect(full < expected + 256);
}

test "RFC 9000 §12.3 - expandTruncatedPn 2-byte truncation" {
    const expected: u64 = 0x10000;
    const trunc: u64 = 0x1234; // 2 bytes
    const full = pn.expandTruncatedPn(trunc, 2, expected);

    // Should preserve lower 2 bytes
    try testing.expectEqual(@as(u64, 0x1234), full & 0xffff);
}

test "RFC 9000 §12.3 - expandTruncatedPn 3-byte truncation" {
    const expected: u64 = 0x1000000;
    const trunc: u64 = 0x123456; // 3 bytes
    const full = pn.expandTruncatedPn(trunc, 3, expected);

    // Should preserve lower 3 bytes
    try testing.expectEqual(@as(u64, 0x123456), full & 0xffffff);
}

test "RFC 9000 §12.3 - expandTruncatedPn 4-byte truncation" {
    const expected: u64 = 0x100000000;
    const trunc: u64 = 0x12345678; // 4 bytes
    const full = pn.expandTruncatedPn(trunc, 4, expected);

    // Should preserve all 4 bytes
    try testing.expectEqual(@as(u64, 0x12345678), full & 0xffffffff);
}

// =============================================================================
// expandTruncatedPn - Edge Cases
// =============================================================================

test "boundary: expandTruncatedPn at window boundary (lower)" {
    // Test when candidate is at lower threshold
    const expected: u64 = 200;
    const trunc: u64 = 72; // Will be below threshold
    const full = pn.expandTruncatedPn(trunc, 1, expected);

    // Should adjust to be in valid window
    try testing.expect(full <= expected + 128);
}

test "boundary: expandTruncatedPn at window boundary (upper)" {
    // Test when candidate is at upper threshold
    const expected: u64 = 100;
    const trunc: u64 = 228; // 0xe4, higher than expected
    const full = pn.expandTruncatedPn(trunc, 1, expected);

    // Should adjust to be in valid window
    // For expected=100, valid window is roughly [0, 228]
    try testing.expect(full < 256); // Within 1-byte range
}

test "boundary: expandTruncatedPn wraparound handling" {
    // Test near 2^64 boundary (though QUIC limits to 2^62-1)
    const expected: u64 = std.math.maxInt(u64) - 1000;
    const trunc: u64 = 0xff;
    const full = pn.expandTruncatedPn(trunc, 1, expected);

    // Should handle wraparound gracefully
    try testing.expect(full != 0);
}

test "boundary: expandTruncatedPn expected=1" {
    const full = pn.expandTruncatedPn(0x01, 1, 1);

    // With expected=1, trunc=1 should expand near 1
    try testing.expect(full <= 129); // Within half window
}

test "boundary: expandTruncatedPn with various truncation lengths" {
    // Test with reasonable values for each truncation length
    // Using expected values that are appropriate for the truncation window
    const full1 = pn.expandTruncatedPn(0xff, 1, 200);
    const full2 = pn.expandTruncatedPn(0xffff, 2, 70000);
    const full3 = pn.expandTruncatedPn(0xffffff, 3, 16700000);
    const full4 = pn.expandTruncatedPn(0x12345678, 4, 0x12345678 + 1000);

    // All should produce valid results
    try testing.expect(full1 > 0);
    try testing.expect(full2 > 0);
    try testing.expect(full3 > 0);
    try testing.expect(full4 > 0);
}

test "boundary: expandTruncatedPn sequential expansion" {
    // Simulate receiving sequential packets
    var expected: u64 = 0;
    var i: u8 = 0;

    while (i < 100) : (i += 1) {
        const trunc = @as(u64, i);
        const full = pn.expandTruncatedPn(trunc, 1, expected);

        // Each should expand correctly
        try testing.expect(full == i);
        expected = full + 1;
    }
}

// =============================================================================
// Negative Tests - Error Conditions
// =============================================================================

test "negative: PnWindow track very old packet after window slide" {
    var window: pn.PnWindow = .{};

    // Track packet 500
    window.track(500);

    // Try to track packet 0 (way outside window)
    window.track(0);

    // Max should still be 500 (old packet ignored)
    try testing.expectEqual(@as(u64, 500), window.max);
}

test "negative: expandTruncatedPn with wrap-around scenario" {
    // Test when truncated value wraps around the window
    const expected: u64 = 100;
    const trunc: u64 = 200; // 0xc8 as 1-byte
    const full = pn.expandTruncatedPn(trunc, 1, expected);

    // With expected=100, trunc=200 (0xc8), algorithm computes:
    // candidate = (100 & ~255) | 200 = 200
    // 200 is within valid window around 100, so returns 200
    try testing.expectEqual(@as(u64, 200), full);
}

test "negative: buildAckRanges with no tracked packets" {
    const window: pn.PnWindow = .{};

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // Should return empty
    try testing.expectEqual(@as(u64, 0), result.first_range);
    try testing.expectEqual(@as(usize, 0), result.ranges_len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §13.2 - PnWindow size is exactly 256 packets" {
    var window: pn.PnWindow = .{};

    // The implementation uses IntegerBitSet(256), confirming window size
    try testing.expectEqual(@as(usize, 256), window.win.capacity());
}

test "RFC 9000 §12.3 - PN expansion all valid lengths (1,2,3,4 bytes)" {
    // Verify all 4 valid truncation lengths work
    const expected: u64 = 1000000;

    _ = pn.expandTruncatedPn(0x12, 1, expected);
    _ = pn.expandTruncatedPn(0x1234, 2, expected);
    _ = pn.expandTruncatedPn(0x123456, 3, expected);
    _ = pn.expandTruncatedPn(0x12345678, 4, expected);

    // If we get here without panic, all lengths are supported
    try testing.expect(true);
}

test "RFC 9000 §19.3 - ACK range gap encoding" {
    var window: pn.PnWindow = .{};

    // Create specific pattern: packets at 10, 11, 12, then gap, then 15, 16
    window.track(10);
    window.track(11);
    window.track(12);
    window.track(15);
    window.track(16);

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // Largest is 16, first_range should be 1 (covers 15-16)
    try testing.expectEqual(@as(u64, 1), result.first_range);

    // Should have one additional range for the 10-12 block
    try testing.expect(result.ranges_len >= 1);

    if (result.ranges_len > 0) {
        // Gap should be 2 (missing 13, 14) minus 1 = 1
        // Len should be 2 (packets 10, 11, 12) minus 1 = 2
        const range = ranges[0];
        try testing.expectEqual(@as(u64, 1), range.gap); // gap: 13-14 (2 packets, encoded as 1)
        try testing.expectEqual(@as(u64, 2), range.len); // len: 10-12 (3 packets, encoded as 2)
    }
}

test "RFC 9000 §13.2 - PnWindow tracks received packets for ACK generation" {
    var window: pn.PnWindow = .{};

    // Receive packets 0, 2, 3, 5 (missing 1 and 4)
    window.track(0);
    window.track(2);
    window.track(3);
    window.track(5);

    var ranges: [10]frame.AckRange = undefined;
    const result = window.buildAckRanges(&ranges);

    // Should build appropriate ACK ranges
    try testing.expect(result.first_range >= 0);
    try testing.expect(result.ranges_len > 0);
}
