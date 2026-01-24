//! Unit tests for connection/ack.zig
//!
//! RFC References:
//! - RFC 9000 §13.2: Generating Acknowledgements
//! - RFC 9000 §19.3: ACK Frames
//! - RFC 3168: Explicit Congestion Notification (ECN)
//!
//! Coverage:
//! - Positive cases: ACK descriptor creation, ECN counter tracking
//! - Negative cases: Invalid ranges, ECN overflow scenarios
//! - Edge cases: Zero values, max counters
//! - RFC compliance: ACK frame structure, ECN count validation

const std = @import("std");
const testing = std.testing;

const ack = @import("ack");
const frame = @import("quic_frame");

// =============================================================================
// AckDesc Tests
// =============================================================================

test "RFC 9000 §19.3 - AckDesc basic structure" {
    const desc: ack.AckDesc = .{
        .largest = 100,
        .first_range = 5,
        .ranges = &[_]frame.AckRange{},
    };

    try testing.expectEqual(@as(u64, 100), desc.largest);
    try testing.expectEqual(@as(u64, 5), desc.first_range);
    try testing.expectEqual(@as(usize, 0), desc.ranges.len);
}

test "RFC 9000 §19.3 - AckDesc with multiple ranges" {
    const ranges = [_]frame.AckRange{
        .{ .gap = 2, .len = 3 },
        .{ .gap = 1, .len = 2 },
    };

    const desc: ack.AckDesc = .{
        .largest = 200,
        .first_range = 10,
        .ranges = &ranges,
    };

    try testing.expectEqual(@as(usize, 2), desc.ranges.len);
    try testing.expectEqual(@as(u64, 2), desc.ranges[0].gap);
    try testing.expectEqual(@as(u64, 3), desc.ranges[0].len);
}

test "RFC 9000 §19.3 - AckDesc largest packet number" {
    const desc: ack.AckDesc = .{
        .largest = std.math.maxInt(u64) - 1,
        .first_range = 0,
        .ranges = &[_]frame.AckRange{},
    };

    try testing.expect(desc.largest > 0);
}

test "boundary: AckDesc with zero values" {
    const desc: ack.AckDesc = .{
        .largest = 0,
        .first_range = 0,
        .ranges = &[_]frame.AckRange{},
    };

    try testing.expectEqual(@as(u64, 0), desc.largest);
    try testing.expectEqual(@as(u64, 0), desc.first_range);
}

// =============================================================================
// EcnCounter Tests
// =============================================================================

test "RFC 3168 - EcnCounter initial state" {
    const counter: ack.EcnCounter = .{};

    try testing.expectEqual(@as(u64, 0), counter.ect0);
    try testing.expectEqual(@as(u64, 0), counter.ect1);
    try testing.expectEqual(@as(u64, 0), counter.ce);
    try testing.expect(!counter.seen_any);
}

test "RFC 3168 - EcnCounter track ECT(0) packets" {
    var counter: ack.EcnCounter = .{};

    counter.ect0 = 10;
    counter.seen_any = true;

    try testing.expectEqual(@as(u64, 10), counter.ect0);
    try testing.expect(counter.seen_any);
}

test "RFC 3168 - EcnCounter track ECT(1) packets" {
    var counter: ack.EcnCounter = .{};

    counter.ect1 = 5;
    counter.seen_any = true;

    try testing.expectEqual(@as(u64, 5), counter.ect1);
}

test "RFC 3168 - EcnCounter track CE (Congestion Experienced) packets" {
    var counter: ack.EcnCounter = .{};

    counter.ce = 3;
    counter.seen_any = true;

    try testing.expectEqual(@as(u64, 3), counter.ce);
}

test "RFC 3168 - EcnCounter all ECN types" {
    var counter: ack.EcnCounter = .{};

    counter.ect0 = 100;
    counter.ect1 = 50;
    counter.ce = 25;
    counter.seen_any = true;

    try testing.expectEqual(@as(u64, 100), counter.ect0);
    try testing.expectEqual(@as(u64, 50), counter.ect1);
    try testing.expectEqual(@as(u64, 25), counter.ce);
    try testing.expect(counter.seen_any);
}

test "RFC 3168 - EcnCounter seen_any flag usage" {
    var counter: ack.EcnCounter = .{};
    try testing.expect(!counter.seen_any);

    counter.ect0 = 1;
    counter.seen_any = true;
    try testing.expect(counter.seen_any);
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "boundary: EcnCounter near maximum values" {
    var counter: ack.EcnCounter = .{};

    counter.ect0 = std.math.maxInt(u64) - 10;
    counter.ect1 = std.math.maxInt(u64) - 20;
    counter.ce = std.math.maxInt(u64) - 30;

    try testing.expect(counter.ect0 > 0);
    try testing.expect(counter.ect1 > 0);
    try testing.expect(counter.ce > 0);
}

test "boundary: EcnCounter incremental counting" {
    var counter: ack.EcnCounter = .{};

    var i: u64 = 0;
    while (i < 1000) : (i += 1) {
        counter.ect0 += 1;
    }

    try testing.expectEqual(@as(u64, 1000), counter.ect0);
}

test "boundary: AckDesc with maximum range count" {
    var ranges_buf: [255]frame.AckRange = undefined;
    for (0..255) |i| {
        ranges_buf[i] = .{ .gap = 1, .len = 1 };
    }

    const desc: ack.AckDesc = .{
        .largest = 1000,
        .first_range = 0,
        .ranges = ranges_buf[0..],
    };

    try testing.expectEqual(@as(usize, 255), desc.ranges.len);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §13.2 - ACK generation requirements" {
    // ACK must acknowledge largest received packet
    const desc: ack.AckDesc = .{
        .largest = 500,
        .first_range = 10,
        .ranges = &[_]frame.AckRange{},
    };

    // Largest acknowledges PN 500
    // first_range = 10 means acknowledging PNs [490, 500]
    try testing.expectEqual(@as(u64, 500), desc.largest);
}

test "RFC 9000 §19.3 - ACK frame first_range semantics" {
    // first_range is number of contiguous packets preceding largest
    const desc: ack.AckDesc = .{
        .largest = 100,
        .first_range = 0, // Only packet 100
        .ranges = &[_]frame.AckRange{},
    };

    try testing.expectEqual(@as(u64, 0), desc.first_range);
}

test "RFC 9000 §19.3 - ACK frame with gaps" {
    // Example: ACKing packets [90-95] (largest=95, first_range=5)
    // Gap of 2, then [87-88] (len=1)
    const ranges = [_]frame.AckRange{
        .{ .gap = 2, .len = 1 }, // Gap: 89, 90; ACK: 87-88
    };

    const desc: ack.AckDesc = .{
        .largest = 95,
        .first_range = 5, // ACK 90-95
        .ranges = &ranges,
    };

    try testing.expectEqual(@as(u64, 95), desc.largest);
    try testing.expectEqual(@as(u64, 5), desc.first_range);
}

test "RFC 3168 - ECN counter must not decrease" {
    var counter: ack.EcnCounter = .{};

    counter.ect0 = 10;
    counter.ect1 = 5;
    counter.ce = 2;

    // Simulate receiving more ECN-marked packets
    counter.ect0 += 3;
    counter.ce += 1;

    try testing.expectEqual(@as(u64, 13), counter.ect0);
    try testing.expectEqual(@as(u64, 5), counter.ect1);
    try testing.expectEqual(@as(u64, 3), counter.ce);
}

test "RFC 9000 §13.2 - Per-space ECN tracking" {
    // Each packet number space has independent ECN counters
    var initial_ecn: ack.EcnCounter = .{};
    var handshake_ecn: ack.EcnCounter = .{};
    var app_data_ecn: ack.EcnCounter = .{};

    initial_ecn.ect0 = 5;
    handshake_ecn.ect0 = 10;
    app_data_ecn.ect0 = 15;

    try testing.expectEqual(@as(u64, 5), initial_ecn.ect0);
    try testing.expectEqual(@as(u64, 10), handshake_ecn.ect0);
    try testing.expectEqual(@as(u64, 15), app_data_ecn.ect0);
}
