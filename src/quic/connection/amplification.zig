// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Anti-amplification limit tracking.
//!
//! RFC 9000 §8.1: Address Validation
//! Servers must limit data sent to unvalidated addresses to prevent amplification attacks.

const std = @import("std");

/// Anti-amplification tracking state.
/// RFC 9000 §8.1: Servers limit transmission to 3x received data before address validation.
pub const AmplificationLimits = struct {
    /// Bytes received from unvalidated peer (for anti-amplification).
    rx_unvalidated: usize = 0,
    /// Bytes sent to unvalidated peer (for anti-amplification).
    tx_unvalidated: usize = 0,
    /// Amplification factor limit (3x by default per RFC 9000 §8.1).
    amplification_factor: usize = 3,
};

/// Check if we can send under anti-amplification limits.
/// RFC 9000 §8.1: Server may send up to 3x the data it has received.
/// RFC 9000 §14.1: Minimum Initial packet size is 1200 bytes.
pub fn canSendUnderAmplification(limits: *const AmplificationLimits, validated: bool) bool {
    if (validated) return true;
    // RFC 9000 §8.1: Prevent amplification with tiny packets
    if (limits.rx_unvalidated < 100) return false;
    const max_tx = limits.rx_unvalidated * limits.amplification_factor;
    return limits.tx_unvalidated < max_tx;
}

/// Check if we are over amplification limit.
/// RFC 9000 §8.1: Endpoints must accurately track bytes sent/received.
pub fn overAmplification(limits: *const AmplificationLimits, validated: bool) bool {
    if (validated) return false;
    return limits.tx_unvalidated >= limits.rx_unvalidated * limits.amplification_factor;
}

/// Add received bytes to unvalidated counter.
pub fn addRxUnvalidated(limits: *AmplificationLimits, n: usize) void {
    // Saturating add to prevent overflow
    const old = limits.rx_unvalidated;
    limits.rx_unvalidated = if (old > std.math.maxInt(usize) - n) std.math.maxInt(usize) else old + n;
}

/// Add transmitted bytes to unvalidated counter.
pub fn addTxUnvalidated(limits: *AmplificationLimits, n: usize) void {
    // Saturating add to prevent overflow
    const old = limits.tx_unvalidated;
    limits.tx_unvalidated = if (old > std.math.maxInt(usize) - n) std.math.maxInt(usize) else old + n;
}
