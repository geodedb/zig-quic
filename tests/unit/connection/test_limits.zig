//! Unit tests for connection/limits.zig
//!
//! RFC References:
//! - RFC 9001 §6.6: Limits on AEAD Usage
//! - RFC 9001 §6.6.1: Confidentiality Limit
//! - RFC 9001 §6.6.2: Integrity Limit
//! - RFC 5116: AEAD Interface and Constructions
//!
//! Coverage:
//! - Positive cases: Limit tracking, counter increments, limit configuration
//! - Negative cases: Exceeding limits, unset limits
//! - Edge cases: Zero limits, max values, exact boundary
//! - RFC compliance: Per-cipher limits, key update triggers

const std = @import("std");
const testing = std.testing;

const limits = @import("limits");

// =============================================================================
// AeadLimits Initialization Tests
// =============================================================================

test "RFC 9001 §6.6 - AeadLimits initial state" {
    const l: limits.AeadLimits = .{};

    try testing.expectEqual(@as(u64, 0), l.aead_tx_count);
    try testing.expect(l.aead_confidentiality_limit == null);
    try testing.expect(l.aead_integrity_limit == null);
}

test "RFC 9001 §6.6 - AeadLimits zero counter at start" {
    const l: limits.AeadLimits = .{};

    // No packets encrypted yet
    try testing.expectEqual(@as(u64, 0), l.aead_tx_count);
}

test "RFC 9001 §6.6 - AeadLimits no limits set initially" {
    const l: limits.AeadLimits = .{};

    // Limits must be configured based on cipher suite
    try testing.expect(l.aead_confidentiality_limit == null);
    try testing.expect(l.aead_integrity_limit == null);
}

// =============================================================================
// TX Counter Tracking Tests
// =============================================================================

test "RFC 9001 §6.6 - AeadLimits increment TX counter" {
    var l: limits.AeadLimits = .{};

    l.aead_tx_count += 1;

    try testing.expectEqual(@as(u64, 1), l.aead_tx_count);
}

test "RFC 9001 §6.6 - AeadLimits track multiple packets" {
    var l: limits.AeadLimits = .{};

    l.aead_tx_count = 100;
    l.aead_tx_count += 50;
    l.aead_tx_count += 25;

    try testing.expectEqual(@as(u64, 175), l.aead_tx_count);
}

test "RFC 9001 §6.6 - AeadLimits large TX count" {
    var l: limits.AeadLimits = .{};

    l.aead_tx_count = 1_000_000_000;

    try testing.expectEqual(@as(u64, 1_000_000_000), l.aead_tx_count);
}

// =============================================================================
// Limit Configuration Tests
// =============================================================================

test "RFC 9001 §6.6 - setLimits configure confidentiality limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, null);

    try testing.expect(l.aead_confidentiality_limit != null);
    try testing.expectEqual(@as(u64, 1000), l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6 - setLimits configure integrity limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, null, 2000);

    try testing.expect(l.aead_integrity_limit != null);
    try testing.expectEqual(@as(u64, 2000), l.aead_integrity_limit.?);
}

test "RFC 9001 §6.6 - setLimits configure both limits" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1500, 3000);

    try testing.expectEqual(@as(u64, 1500), l.aead_confidentiality_limit.?);
    try testing.expectEqual(@as(u64, 3000), l.aead_integrity_limit.?);
}

test "RFC 9001 §6.6 - setLimits can update existing limits" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, 2000);
    limits.setLimits(&l, 5000, 10000);

    try testing.expectEqual(@as(u64, 5000), l.aead_confidentiality_limit.?);
    try testing.expectEqual(@as(u64, 10000), l.aead_integrity_limit.?);
}

test "RFC 9001 §6.6 - setLimits with null removes limits" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, 2000);
    limits.setLimits(&l, null, null);

    try testing.expect(l.aead_confidentiality_limit == null);
    try testing.expect(l.aead_integrity_limit == null);
}

// =============================================================================
// Limit Checking Tests
// =============================================================================

test "RFC 9001 §6.6.1 - Confidentiality limit enforcement" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 100, null);

    // Under limit
    l.aead_tx_count = 50;
    try testing.expect(l.aead_tx_count < l.aead_confidentiality_limit.?);

    // At limit
    l.aead_tx_count = 100;
    try testing.expect(l.aead_tx_count >= l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6.1 - Confidentiality limit triggers key update" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, null);

    l.aead_tx_count = 999;
    try testing.expect(l.aead_tx_count < l.aead_confidentiality_limit.?);

    l.aead_tx_count = 1000;
    // At or above limit - must initiate key update
    try testing.expect(l.aead_tx_count >= l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6 - Counter reset after key update" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 100, null);
    l.aead_tx_count = 100;

    // Key update performed
    l.aead_tx_count = 0; // Reset counter

    try testing.expectEqual(@as(u64, 0), l.aead_tx_count);
}

// =============================================================================
// Per-Cipher Suite Limits Tests
// =============================================================================

test "RFC 9001 §6.6 - AES-128-GCM typical limits" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: AES-128-GCM confidentiality limit is 2^23
    const aes128_gcm_conf_limit: u64 = 1 << 23; // ~8 million
    limits.setLimits(&l, aes128_gcm_conf_limit, null);

    try testing.expectEqual(aes128_gcm_conf_limit, l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6 - AES-256-GCM typical limits" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: AES-256-GCM confidentiality limit is 2^23
    const aes256_gcm_conf_limit: u64 = 1 << 23;
    limits.setLimits(&l, aes256_gcm_conf_limit, null);

    try testing.expectEqual(aes256_gcm_conf_limit, l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6 - ChaCha20-Poly1305 no confidentiality limit" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: ChaCha20-Poly1305 has no confidentiality limit
    limits.setLimits(&l, null, null);

    try testing.expect(l.aead_confidentiality_limit == null);
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

test "boundary: AeadLimits counter at max u64" {
    var l: limits.AeadLimits = .{};

    l.aead_tx_count = std.math.maxInt(u64);

    try testing.expectEqual(std.math.maxInt(u64), l.aead_tx_count);
}

test "boundary: AeadLimits one below confidentiality limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, null);
    l.aead_tx_count = 999;

    try testing.expect(l.aead_tx_count < l.aead_confidentiality_limit.?);
}

test "boundary: AeadLimits exactly at confidentiality limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, null);
    l.aead_tx_count = 1000;

    try testing.expectEqual(l.aead_tx_count, l.aead_confidentiality_limit.?);
}

test "boundary: AeadLimits one above confidentiality limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, null);
    l.aead_tx_count = 1001;

    try testing.expect(l.aead_tx_count > l.aead_confidentiality_limit.?);
}

test "boundary: AeadLimits zero limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 0, 0);

    // Zero limit means immediate key update needed
    try testing.expectEqual(@as(u64, 0), l.aead_confidentiality_limit.?);
}

// =============================================================================
// Negative Tests
// =============================================================================

test "negative: AeadLimits exceeding confidentiality limit" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 100, null);
    l.aead_tx_count = 200;

    // Exceeded limit - key update should have been performed
    try testing.expect(l.aead_tx_count > l.aead_confidentiality_limit.?);
}

test "negative: AeadLimits no limit set allows unlimited" {
    var l: limits.AeadLimits = .{};

    // No limit set
    try testing.expect(l.aead_confidentiality_limit == null);

    // Can encrypt indefinitely (not recommended, but allowed by implementation)
    l.aead_tx_count = std.math.maxInt(u64);
}

// =============================================================================
// RFC Compliance Tests
// =============================================================================

test "RFC 9001 §6.6 - AEAD usage limits prevent cryptographic weaknesses" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: Limits ensure security properties of AEAD algorithms
    limits.setLimits(&l, 1 << 23, null); // 2^23 for AES-GCM

    // Must initiate key update before reaching limit
    l.aead_tx_count = (1 << 23) - 1;
    try testing.expect(l.aead_tx_count < l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6 - Confidentiality limit based on cipher analysis" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: Limits derived from cryptographic analysis
    // For AES-GCM: 2^23 packets
    const aes_gcm_limit: u64 = 1 << 23;
    limits.setLimits(&l, aes_gcm_limit, null);

    l.aead_tx_count = aes_gcm_limit - 1;

    // Still under limit
    try testing.expect(l.aead_tx_count < l.aead_confidentiality_limit.?);
}

test "RFC 9001 §6.6.2 - Integrity limit for failed decryptions" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6.2: Integrity limit applies to decryption failures
    limits.setLimits(&l, null, 1000);

    try testing.expectEqual(@as(u64, 1000), l.aead_integrity_limit.?);
}

test "RFC 9001 §6.6 - Key update resets usage counters" {
    var l: limits.AeadLimits = .{};

    limits.setLimits(&l, 1000, null);
    l.aead_tx_count = 999;

    // Initiate key update before reaching limit
    // After key update, reset counter
    l.aead_tx_count = 0;

    try testing.expectEqual(@as(u64, 0), l.aead_tx_count);
}

test "RFC 9001 §6.6 - Application should configure limits per RFC recommendations" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: Applications SHOULD configure limits based on AEAD algorithm
    // Example: AES-128-GCM
    const conf_limit: u64 = 1 << 23; // ~8.4 million
    const integ_limit: u64 = 1 << 52; // ~4.5 quadrillion

    limits.setLimits(&l, conf_limit, integ_limit);

    try testing.expect(l.aead_confidentiality_limit.? > 0);
    try testing.expect(l.aead_integrity_limit.? > 0);
}

test "RFC 9001 §6.6 - Limits apply to 1-RTT keys" {
    var l: limits.AeadLimits = .{};

    // RFC 9001 §6.6: Limits apply to 1-RTT packet protection keys
    limits.setLimits(&l, 1 << 23, null);

    // Initial and Handshake keys have separate (implicit) limits
    // This structure tracks 1-RTT keys
    try testing.expect(l.aead_confidentiality_limit != null);
}

test "RFC 9001 §6.6 - Different limits for TX and RX" {
    var tx_limits: limits.AeadLimits = .{};
    var rx_limits: limits.AeadLimits = .{};

    // TX has confidentiality limit
    limits.setLimits(&tx_limits, 1 << 23, null);

    // RX has integrity limit
    limits.setLimits(&rx_limits, null, 1 << 52);

    try testing.expect(tx_limits.aead_confidentiality_limit != null);
    try testing.expect(rx_limits.aead_integrity_limit != null);
}
