//! Unit tests for connection/amplification.zig
//!
//! RFC References:
//! - RFC 9000 §8.1: Address Validation
//! - RFC 9000 §8.1.1: Address Validation Using Retry Packets
//! - RFC 9000 §8.1.2: Address Validation for Future Connections
//! - RFC 9000 §8.1.3: Address Validation Token Integrity
//!
//! Coverage:
//! - Positive cases: RX/TX tracking, amplification factor, validation bypass
//! - Negative cases: Exceeding limits, unvalidated transmission
//! - Edge cases: Zero values, max values, exact 3x boundary
//! - RFC compliance: 3x amplification limit, validation requirements

const std = @import("std");
const testing = std.testing;

const amp = @import("amplification");

// =============================================================================
// AmplificationLimits Initialization Tests
// =============================================================================

test "RFC 9000 §8.1 - AmplificationLimits initial state" {
    const limits: amp.AmplificationLimits = .{};

    try testing.expectEqual(@as(usize, 0), limits.rx_unvalidated);
    try testing.expectEqual(@as(usize, 0), limits.tx_unvalidated);
    try testing.expectEqual(@as(usize, 3), limits.amplification_factor);
}

test "RFC 9000 §8.1 - AmplificationLimits default 3x factor" {
    const limits: amp.AmplificationLimits = .{};

    // RFC 9000 §8.1: Default amplification factor is 3
    try testing.expectEqual(@as(usize, 3), limits.amplification_factor);
}

// =============================================================================
// RX/TX Tracking Tests
// =============================================================================

test "RFC 9000 §8.1 - addRxUnvalidated tracks received bytes" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 100);

    try testing.expectEqual(@as(usize, 100), limits.rx_unvalidated);
}

test "RFC 9000 §8.1 - addTxUnvalidated tracks transmitted bytes" {
    var limits: amp.AmplificationLimits = .{};

    amp.addTxUnvalidated(&limits, 200);

    try testing.expectEqual(@as(usize, 200), limits.tx_unvalidated);
}

test "RFC 9000 §8.1 - addRxUnvalidated cumulative" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 100);
    amp.addRxUnvalidated(&limits, 200);
    amp.addRxUnvalidated(&limits, 50);

    try testing.expectEqual(@as(usize, 350), limits.rx_unvalidated);
}

test "RFC 9000 §8.1 - addTxUnvalidated cumulative" {
    var limits: amp.AmplificationLimits = .{};

    amp.addTxUnvalidated(&limits, 300);
    amp.addTxUnvalidated(&limits, 600);
    amp.addTxUnvalidated(&limits, 100);

    try testing.expectEqual(@as(usize, 1000), limits.tx_unvalidated);
}

// =============================================================================
// Amplification Limit Check Tests
// =============================================================================

test "RFC 9000 §8.1 - canSendUnderAmplification within limit" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 1000);
    amp.addTxUnvalidated(&limits, 2000);

    // RX=1000, TX=2000, limit=3000 (3x), so can send 1000 more
    try testing.expect(amp.canSendUnderAmplification(&limits, false));
}

test "RFC 9000 §8.1 - canSendUnderAmplification at exact limit" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 1000);
    amp.addTxUnvalidated(&limits, 3000);

    // RX=1000, TX=3000, limit=3000 (3x), exactly at limit
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "RFC 9000 §8.1 - canSendUnderAmplification over limit" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 1000);
    amp.addTxUnvalidated(&limits, 3500);

    // RX=1000, TX=3500, limit=3000 (3x), over limit
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "RFC 9000 §8.1 - canSendUnderAmplification bypassed when validated" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 10);
    amp.addTxUnvalidated(&limits, 1000);

    // Over limit, but validated=true bypasses check
    try testing.expect(amp.canSendUnderAmplification(&limits, true));
}

test "RFC 9000 §8.1 - overAmplification detects limit exceeded" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 100);
    amp.addTxUnvalidated(&limits, 400);

    // RX=100, TX=400, limit=300 (3x), over limit
    try testing.expect(amp.overAmplification(&limits, false));
}

test "RFC 9000 §8.1 - overAmplification false when within limit" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 100);
    amp.addTxUnvalidated(&limits, 200);

    // RX=100, TX=200, limit=300 (3x), within limit
    try testing.expect(!amp.overAmplification(&limits, false));
}

test "RFC 9000 §8.1 - overAmplification false when validated" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 10);
    amp.addTxUnvalidated(&limits, 10000);

    // Validated addresses have no amplification limit
    try testing.expect(!amp.overAmplification(&limits, true));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: AmplificationLimits zero received allows no transmission" {
    var limits: amp.AmplificationLimits = .{};

    // RX=0, TX=0, limit=0 (3*0=0)
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "boundary: AmplificationLimits first packet allows 3x response" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 1200); // First packet received

    // Can send up to 3600 bytes (3 * 1200)
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 3600);

    // Now at limit
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "boundary: AmplificationLimits saturating add prevents overflow" {
    var limits: amp.AmplificationLimits = .{};

    // Add maximum value
    amp.addRxUnvalidated(&limits, std.math.maxInt(usize));

    // Should saturate, not overflow
    try testing.expectEqual(std.math.maxInt(usize), limits.rx_unvalidated);

    // Adding more should keep it at max
    amp.addRxUnvalidated(&limits, 100);
    try testing.expectEqual(std.math.maxInt(usize), limits.rx_unvalidated);
}

test "boundary: AmplificationLimits TX saturating add" {
    var limits: amp.AmplificationLimits = .{};

    amp.addTxUnvalidated(&limits, std.math.maxInt(usize) - 50);
    amp.addTxUnvalidated(&limits, 100);

    // Should saturate at max
    try testing.expectEqual(std.math.maxInt(usize), limits.tx_unvalidated);
}

test "boundary: AmplificationLimits exact 3x boundary" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 1000);
    amp.addTxUnvalidated(&limits, 2999);

    // 1 byte under limit
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 1);

    // Exactly at limit
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

// =============================================================================
// Custom Amplification Factor Tests
// =============================================================================

test "RFC 9000 §8.1 - AmplificationLimits custom factor" {
    var limits: amp.AmplificationLimits = .{
        .amplification_factor = 5, // Custom 5x factor
    };

    amp.addRxUnvalidated(&limits, 100);
    amp.addTxUnvalidated(&limits, 400);

    // RX=100, TX=400, limit=500 (5x), within limit
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 100);

    // RX=100, TX=500, limit=500 (5x), at limit
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "boundary: AmplificationLimits factor of 1" {
    var limits: amp.AmplificationLimits = .{
        .amplification_factor = 1, // Strict 1:1
    };

    amp.addRxUnvalidated(&limits, 1000);
    amp.addTxUnvalidated(&limits, 999);

    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 1);

    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: AmplificationLimits cannot send without receiving first" {
    var limits: amp.AmplificationLimits = .{};

    // RX=0, cannot send anything
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "negative: AmplificationLimits transmission blocked after exceeding" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 100);
    amp.addTxUnvalidated(&limits, 500); // Way over 3x

    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
    try testing.expect(amp.overAmplification(&limits, false));
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9000 §8.1 - Server must limit to 3x received before validation" {
    var limits: amp.AmplificationLimits = .{};

    // Server receives 1200-byte Initial packet from client
    amp.addRxUnvalidated(&limits, 1200);

    // Server can send up to 3600 bytes
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 3600);

    // Cannot send more until receiving more or validating
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "RFC 9000 §8.1 - Amplification limit removed after validation" {
    var limits: amp.AmplificationLimits = .{};

    amp.addRxUnvalidated(&limits, 100);

    // Before validation: Can send up to 3x (300 bytes)
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    // After validation: no limit
    try testing.expect(amp.canSendUnderAmplification(&limits, true));
}

test "RFC 9000 §8.1 - Retry packet counts toward amplification" {
    var limits: amp.AmplificationLimits = .{};

    // Receive Initial from unvalidated address
    amp.addRxUnvalidated(&limits, 1200);

    // Send Retry packet (counts toward limit)
    amp.addTxUnvalidated(&limits, 100);

    // Can still send up to 3600 total
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 3500);

    // Now at limit
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
}

test "RFC 9000 §8.1 - Multiple packets increase RX budget" {
    var limits: amp.AmplificationLimits = .{};

    // First packet: 1200 bytes
    amp.addRxUnvalidated(&limits, 1200);
    amp.addTxUnvalidated(&limits, 3600); // At limit

    // Second packet: another 1200 bytes
    amp.addRxUnvalidated(&limits, 1200);

    // Now can send 3600 more (total RX=2400, limit=7200)
    try testing.expect(amp.canSendUnderAmplification(&limits, false));
}

test "RFC 9000 §8.1 - Accurate tracking prevents amplification attacks" {
    var limits: amp.AmplificationLimits = .{};

    // Receive small packet from attacker-spoofed address
    amp.addRxUnvalidated(&limits, 100);

    // Can only send 300 bytes back (3x)
    try testing.expect(amp.canSendUnderAmplification(&limits, false));

    amp.addTxUnvalidated(&limits, 300);

    // Blocked from further amplification
    try testing.expect(!amp.canSendUnderAmplification(&limits, false));
    try testing.expect(amp.overAmplification(&limits, false));
}
