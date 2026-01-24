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
        return largest_acked >= pn + self.packet_threshold;
    }

    /// Time threshold as 1.125x of the larger of smoothed/latest RTT.
    /// RFC 9002 §6.1.2: Time Threshold
    pub fn timeThresholdNs(smoothed_rtt_ns: u64, latest_rtt_ns: u64) u64 {
        const std = @import("std");
        const base = if (smoothed_rtt_ns > latest_rtt_ns) smoothed_rtt_ns else latest_rtt_ns;
        const increment = base / 8;
        // Saturate at max u64 on overflow to prevent panic in debug mode
        if (base > std.math.maxInt(u64) - increment) {
            return std.math.maxInt(u64);
        }
        return base + increment; // 1.125x
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
