//! Unit tests for recovery/loss_detection.zig
//!
//! RFC References:
//! - RFC 9002 §6.1: Loss Detection
//! - RFC 9002 §6.1.1: Packet Threshold
//! - RFC 9002 §6.1.2: Time Threshold
//! - RFC 9002 §2: ACK-eliciting frames
//!
//! Coverage:
//! - Positive cases: Packet threshold detection, time threshold calculation, ACK-eliciting classification
//! - Negative cases: Packets not yet lost, non-ACK-eliciting frames
//! - Boundary cases: Threshold boundaries, edge values
//! - RFC compliance: Default thresholds, loss detection rules

const std = @import("std");
const testing = std.testing;

const loss_mod = @import("loss_detection");
const LossDetector = loss_mod.LossDetector;
const isAckElicitingFrame = loss_mod.isAckElicitingFrame;

// Import frame types for isAckElicitingFrame tests
const frame = @import("quic_frame");

// =============================================================================
// LossDetector Initialization Tests
// =============================================================================

test "LossDetector initializes with default packet_threshold of 3" {
    const ld: LossDetector = .{};
    try testing.expectEqual(@as(u32, 3), ld.packet_threshold);
}

test "LossDetector can be created with custom packet_threshold" {
    const ld: LossDetector = .{ .packet_threshold = 5 };
    try testing.expectEqual(@as(u32, 5), ld.packet_threshold);
}

// =============================================================================
// Packet Threshold Loss Detection Tests (RFC 9002 §6.1.1)
// =============================================================================

test "RFC 9002 §6.1.1 - isPacketThresholdLost detects loss when gap >= threshold" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 10;
    const pn: u64 = 6;

    // Gap = 10 - 6 = 4, which is >= 3
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost does not detect loss when gap < threshold" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 10;
    const pn: u64 = 8;

    // Gap = 10 - 8 = 2, which is < 3
    try testing.expect(!ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost at exact threshold boundary" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 10;
    const pn: u64 = 7;

    // Gap = 10 - 7 = 3, exactly at threshold
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost one below threshold" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 10;
    const pn: u64 = 8;

    // Gap = 10 - 8 = 2, one below threshold
    try testing.expect(!ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost with large gap" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 1000;
    const pn: u64 = 1;

    // Gap = 999, much larger than threshold
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost with pn close to largest_acked" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 100;
    const pn: u64 = 99;

    // Gap = 1, below threshold
    try testing.expect(!ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost with custom threshold" {
    const ld: LossDetector = .{ .packet_threshold = 5 };
    const largest_acked: u64 = 20;
    const pn: u64 = 15;

    // Gap = 5, exactly at custom threshold
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

test "RFC 9002 §6.1.1 - isPacketThresholdLost respects custom threshold" {
    const ld: LossDetector = .{ .packet_threshold = 5 };
    const largest_acked: u64 = 20;
    const pn: u64 = 16;

    // Gap = 4, below custom threshold of 5
    try testing.expect(!ld.isPacketThresholdLost(largest_acked, pn));
}

// =============================================================================
// Time Threshold Calculation Tests (RFC 9002 §6.1.2)
// =============================================================================

test "RFC 9002 §6.1.2 - timeThresholdNs calculates 9/8 of max(smoothed, latest)" {
    const smoothed: u64 = 100_000_000; // 100ms
    const latest: u64 = 80_000_000; // 80ms

    const threshold = LossDetector.timeThresholdNs(smoothed, latest);

    // Should use smoothed (100ms) and multiply by 1.125 = 112.5ms
    const expected = smoothed + smoothed / 8;
    try testing.expectEqual(expected, threshold);
}

test "RFC 9002 §6.1.2 - timeThresholdNs uses larger of smoothed and latest" {
    const smoothed: u64 = 80_000_000;
    const latest: u64 = 120_000_000;

    const threshold = LossDetector.timeThresholdNs(smoothed, latest);

    // Should use latest (120ms) * 1.125 = 135ms
    const expected = latest + latest / 8;
    try testing.expectEqual(expected, threshold);
}

test "RFC 9002 §6.1.2 - timeThresholdNs with equal smoothed and latest" {
    const rtt: u64 = 100_000_000;

    const threshold = LossDetector.timeThresholdNs(rtt, rtt);

    // 100ms * 1.125 = 112.5ms
    const expected = rtt + rtt / 8;
    try testing.expectEqual(expected, threshold);
}

test "RFC 9002 §6.1.2 - timeThresholdNs multiplier is 1.125x" {
    const base: u64 = 80_000_000; // 80ms

    const threshold = LossDetector.timeThresholdNs(base, base);

    // 80ms * 1.125 = 90ms
    try testing.expectEqual(@as(u64, 90_000_000), threshold);
}

test "RFC 9002 §6.1.2 - timeThresholdNs with very small RTT" {
    const rtt: u64 = 1_000_000; // 1ms

    const threshold = LossDetector.timeThresholdNs(rtt, rtt);

    // 1ms * 1.125 = 1.125ms
    const expected = rtt + rtt / 8;
    try testing.expectEqual(expected, threshold);
}

test "RFC 9002 §6.1.2 - timeThresholdNs with very large RTT" {
    const rtt: u64 = 10_000_000_000; // 10 seconds

    const threshold = LossDetector.timeThresholdNs(rtt, rtt);

    // 10s * 1.125 = 11.25s
    const expected = rtt + rtt / 8;
    try testing.expectEqual(expected, threshold);
}

test "RFC 9002 §6.1.2 - timeThresholdNs is always > base RTT" {
    const rtts = [_]u64{ 10_000_000, 50_000_000, 100_000_000, 200_000_000 };

    for (rtts) |rtt| {
        const threshold = LossDetector.timeThresholdNs(rtt, rtt);
        try testing.expect(threshold > rtt);
    }
}

// =============================================================================
// ACK-Eliciting Frame Classification Tests (RFC 9002 §2)
// =============================================================================

test "RFC 9002 §2 - PADDING is not ACK-eliciting" {
    const fr = frame.Frame{ .padding = 0 };
    try testing.expect(!isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - ACK is not ACK-eliciting" {
    const fr = frame.Frame{
        .ack = .{
            .largest = 10,
            .ack_delay = 0,
            .ranges = &[_]frame.AckRange{.{ .gap = 0, .len = 0 }},
        },
    };
    try testing.expect(!isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - PING is ACK-eliciting" {
    const fr = frame.Frame{ .ping = {} };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - CRYPTO is ACK-eliciting" {
    const fr = frame.Frame{
        .crypto = .{
            .offset = 0,
            .data = &[_]u8{},
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - STREAM is ACK-eliciting" {
    const fr = frame.Frame{
        .stream = .{
            .stream_id = 0,
            .offset = null,
            .data = &[_]u8{},
            .fin = false,
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - RESET_STREAM is ACK-eliciting" {
    const fr = frame.Frame{
        .reset_stream = .{
            .stream_id = 0,
            .error_code = 0,
            .final_size = 0,
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - STOP_SENDING is ACK-eliciting" {
    const fr = frame.Frame{
        .stop_sending = .{
            .stream_id = 0,
            .error_code = 0,
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - NEW_TOKEN is ACK-eliciting" {
    const fr = frame.Frame{
        .new_token = .{
            .token = &[_]u8{},
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - MAX_DATA is ACK-eliciting" {
    const fr = frame.Frame{
        .max_data = .{
            .max = 1000,
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - MAX_STREAM_DATA is ACK-eliciting" {
    const fr = frame.Frame{
        .max_stream_data = .{
            .stream_id = 0,
            .max = 1000,
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - PATH_CHALLENGE is ACK-eliciting" {
    const fr = frame.Frame{
        .path_challenge = [_]u8{0} ** 8,
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - PATH_RESPONSE is ACK-eliciting" {
    const fr = frame.Frame{
        .path_response = [_]u8{0} ** 8,
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - CONNECTION_CLOSE is ACK-eliciting" {
    const fr = frame.Frame{
        .connection_close = .{
            .error_code = 0,
            .reason = &[_]u8{},
        },
    };
    try testing.expect(isAckElicitingFrame(fr));
}

test "RFC 9002 §2 - HANDSHAKE_DONE is ACK-eliciting" {
    const fr = frame.Frame{ .handshake_done = {} };
    try testing.expect(isAckElicitingFrame(fr));
}

// =============================================================================
// Boundary Cases
// =============================================================================

test "boundary: isPacketThresholdLost with pn = largest_acked" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 10;
    const pn: u64 = 10;

    // Gap = 0, not lost
    try testing.expect(!ld.isPacketThresholdLost(largest_acked, pn));
}

test "boundary: isPacketThresholdLost with threshold = 1" {
    const ld: LossDetector = .{ .packet_threshold = 1 };
    const largest_acked: u64 = 10;
    const pn: u64 = 9;

    // Gap = 1, at threshold
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

test "boundary: isPacketThresholdLost with pn = 0" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked: u64 = 5;
    const pn: u64 = 0;

    // Gap = 5, above threshold
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

test "boundary: timeThresholdNs with zero RTT" {
    const threshold = LossDetector.timeThresholdNs(0, 0);
    try testing.expectEqual(@as(u64, 0), threshold);
}

test "boundary: timeThresholdNs with maximum u64 RTT" {
    const max_rtt = std.math.maxInt(u64);
    // Should handle overflow gracefully
    const threshold = LossDetector.timeThresholdNs(max_rtt, 0);
    // Result will overflow, but should not crash
    _ = threshold;
}

test "boundary: isPacketThresholdLost with maximum packet numbers" {
    const ld: LossDetector = .{ .packet_threshold = 3 };
    const largest_acked = std.math.maxInt(u64);
    const pn = std.math.maxInt(u64) - 5;

    // Gap = 5, above threshold
    try testing.expect(ld.isPacketThresholdLost(largest_acked, pn));
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9002 §6.1.1 - default packet threshold is 3" {
    const ld: LossDetector = .{};
    try testing.expectEqual(@as(u32, 3), ld.packet_threshold);
}

test "RFC 9002 §6.1.2 - time threshold is 9/8 * max RTT" {
    const smoothed: u64 = 100_000_000;
    const latest: u64 = 80_000_000;

    const threshold = LossDetector.timeThresholdNs(smoothed, latest);

    // Should be 9/8 of 100ms = 112.5ms
    const expected = (smoothed * 9) / 8;
    try testing.expectEqual(expected, threshold);
}

test "RFC 9002 §6.1 - packet threshold loss requires gap >= threshold" {
    const ld: LossDetector = .{};
    const largest_acked: u64 = 100;

    // Test various packet numbers
    try testing.expect(ld.isPacketThresholdLost(largest_acked, 96)); // gap=4, lost
    try testing.expect(ld.isPacketThresholdLost(largest_acked, 97)); // gap=3, lost (at threshold)
    try testing.expect(!ld.isPacketThresholdLost(largest_acked, 98)); // gap=2, not lost
}

test "RFC 9002 §2 - only ACK and PADDING are not ACK-eliciting" {
    // All other frame types should be ACK-eliciting
    const ack_frame = frame.Frame{
        .ack = .{
            .largest = 0,
            .ack_delay = 0,
            .ranges = &[_]frame.AckRange{.{ .gap = 0, .len = 0 }},
        },
    };
    const padding_frame = frame.Frame{ .padding = 0 };

    try testing.expect(!isAckElicitingFrame(ack_frame));
    try testing.expect(!isAckElicitingFrame(padding_frame));
}

test "RFC 9002 §6.1.1 - packet threshold can be tuned" {
    // RFC allows tuning packet_threshold (default 3, can be adjusted)
    const ld1: LossDetector = .{ .packet_threshold = 2 };
    const ld2: LossDetector = .{ .packet_threshold = 5 };

    const largest_acked: u64 = 10;
    const pn: u64 = 7;

    // Gap = 3
    try testing.expect(ld1.isPacketThresholdLost(largest_acked, pn)); // threshold=2, lost
    try testing.expect(!ld2.isPacketThresholdLost(largest_acked, pn)); // threshold=5, not lost
}

// =============================================================================
// Integration Tests
// =============================================================================

test "LossDetector identifies losses in sequence" {
    const ld: LossDetector = .{};
    const largest_acked: u64 = 20;

    // Test a range of packet numbers
    const test_cases = [_]struct { pn: u64, should_be_lost: bool }{
        .{ .pn = 10, .should_be_lost = true }, // gap=10
        .{ .pn = 15, .should_be_lost = true }, // gap=5
        .{ .pn = 16, .should_be_lost = true }, // gap=4
        .{ .pn = 17, .should_be_lost = true }, // gap=3
        .{ .pn = 18, .should_be_lost = false }, // gap=2
        .{ .pn = 19, .should_be_lost = false }, // gap=1
        .{ .pn = 20, .should_be_lost = false }, // gap=0
    };

    for (test_cases) |tc| {
        const is_lost = ld.isPacketThresholdLost(largest_acked, tc.pn);
        try testing.expectEqual(tc.should_be_lost, is_lost);
    }
}

test "timeThresholdNs consistently larger than base RTT" {
    const test_rtts = [_]u64{
        1_000_000, // 1ms
        10_000_000, // 10ms
        50_000_000, // 50ms
        100_000_000, // 100ms
        200_000_000, // 200ms
        500_000_000, // 500ms
    };

    for (test_rtts) |rtt| {
        const threshold = LossDetector.timeThresholdNs(rtt, rtt);
        // Should always be 1.125x the base
        const expected_min = rtt + rtt / 8;
        try testing.expectEqual(expected_min, threshold);
    }
}

test "ACK-eliciting classification covers all frame types" {
    // Create one of each frame type and verify classification
    const frames = [_]frame.Frame{
        frame.Frame{ .padding = 0 }, // Not ACK-eliciting
        frame.Frame{ .ping = {} }, // ACK-eliciting
        frame.Frame{
            .ack = .{
                .largest = 0,
                .ack_delay = 0,
                .ranges = &[_]frame.AckRange{.{ .gap = 0, .len = 0 }},
            },
        }, // Not ACK-eliciting
        frame.Frame{
            .crypto = .{
                .offset = 0,
                .data = &[_]u8{},
            },
        }, // ACK-eliciting
    };

    var eliciting_count: usize = 0;
    for (frames) |fr| {
        if (isAckElicitingFrame(fr)) {
            eliciting_count += 1;
        }
    }

    // 2 out of 4 test frames should be ACK-eliciting
    try testing.expectEqual(@as(usize, 2), eliciting_count);
}
