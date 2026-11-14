// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Loss detection using packet and time thresholds.
//!
//! RFC 9002 §6.1: Loss Detection

const frame = @import("quic_frame");

/// Loss detection helper implementing packet/time threshold loss logic (RFC 9002 §6.1).
pub const LossDetector = struct {
    /// Packet-threshold (default 3) and time-threshold (9/8 * max(smoothed_rtt, latest_rtt)).
    /// RFC 9002 §6.1.1: Packet Threshold
    packet_threshold: u32 = 3,

    /// Return true if pn is considered lost using packet threshold relative to largest_acked.
    /// RFC 9002 §6.1.1: Packet Threshold
    pub fn isPacketThresholdLost(self: *const LossDetector, largest_acked: u64, pn: u64) bool {
        if (largest_acked < pn) return false;
        return largest_acked - pn >= self.packet_threshold;
    }

    /// RFC 9002 §6.1.2 kGranularity: the time threshold never drops below
    /// the timer granularity (1 ms).
    pub const k_granularity_ns: u64 = 1_000_000;

    /// Time threshold: 9/8 of the larger of smoothed/latest RTT, but at
    /// least kGranularity. Without the floor a sub-millisecond RTT (loopback,
    /// a LAN) declared packets lost by time while their ACK was still on its
    /// way, and every such loss resent data and shrank the window
    /// (SONNY-6454).
    /// RFC 9002 §6.1.2: Time Threshold
    pub fn timeThresholdNs(smoothed_rtt_ns: u64, latest_rtt_ns: u64) u64 {
        const std = @import("std");
        const base = if (smoothed_rtt_ns > latest_rtt_ns) smoothed_rtt_ns else latest_rtt_ns;
        const increment = base / 8;
        // Saturate at max u64 on overflow to prevent panic in debug mode
        if (base > std.math.maxInt(u64) - increment) {
            return std.math.maxInt(u64);
        }
        return @max(base + increment, k_granularity_ns); // 1.125x
    }
};

/// Classify whether a frame is ack-eliciting (RFC 9002 §2).
/// ACK-only and PADDING are not ack-eliciting; most others are.
/// Exposed for tests verifying ECN/loss logic classification.
pub fn isAckElicitingFrame(fr: frame.Frame) bool {
    return switch (fr) {
        .ack => false,
        .padding => false,
        // DATAGRAM would be ack-eliciting if enabled; not present yet.
        else => true,
    };
}

test "loss detection packet threshold does not underflow near max packet numbers" {
    const detector = LossDetector{};
    try @import("std").testing.expect(!detector.isPacketThresholdLost(0, @import("std").math.maxInt(u64)));
    try @import("std").testing.expect(!detector.isPacketThresholdLost(2, 5));
    try @import("std").testing.expect(detector.isPacketThresholdLost(5, 2));
}
