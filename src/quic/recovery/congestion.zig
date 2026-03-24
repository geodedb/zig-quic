// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Congestion control implementations.
//!
//! RFC 9002 §7: Congestion Control

const std = @import("std");

/// NewReno congestion controller (bytes-based) implementing slow start and congestion avoidance per RFC 9002.
/// RFC 9002 §7.3: NewReno and Appendix B.1
pub const NewReno = struct {
    // Congestion control state (bytes)
    // Configurable max datagram size (RFC 9002 "max_datagram_size").
    mds: usize = 1200,
    cwnd: usize = 10 * 1200, // RFC 9002 §7.2: initial cwnd = 10 * max_datagram_size
    ssthresh: usize = std.math.maxInt(usize) / 2,
    bytes_in_flight: usize = 0,

    /// Track bytes in flight for ack-eliciting packets when sent.
    pub fn onPacketSent(self: *NewReno, bytes: usize, ack_eliciting: bool) void {
        if (ack_eliciting) self.bytes_in_flight += bytes;
    }

    /// Increase cwnd on ACK and exit slow start to congestion avoidance.
    /// RFC 9002 §7.3.1: Slow Start and RFC 9002 §7.3.2: Congestion Avoidance
    pub fn onAck(self: *NewReno, bytes_acked: usize) void {
        if (self.cwnd < self.ssthresh) {
            // Slow start
            self.cwnd += bytes_acked;
        } else {
            // Congestion avoidance: cwnd += mds * bytes_acked / cwnd
            const mds_local: usize = self.mds;
            self.cwnd += (mds_local * bytes_acked) / self.cwnd;
        }
        if (self.bytes_in_flight >= bytes_acked) self.bytes_in_flight -= bytes_acked else self.bytes_in_flight = 0;
    }

    /// Halve cwnd on loss and set ssthresh accordingly.
    /// RFC 9002 §7.3.3: Recovery Period
    pub fn onLoss(self: *NewReno, bytes_lost: usize) void {
        const min_wnd = 2 * self.mds;
        self.cwnd = self.cwnd / 2;
        if (self.cwnd < min_wnd) self.cwnd = min_wnd;
        self.ssthresh = self.cwnd;
        if (self.bytes_in_flight >= bytes_lost) self.bytes_in_flight -= bytes_lost else self.bytes_in_flight = 0;
    }
};

/// CUBIC congestion controller placeholder wrapping NewReno behavior (future expansion).
/// RFC 9002 Appendix B.2: CUBIC
pub const Cubic = struct {
    inner: NewReno = .{},

    /// Track bytes in flight for ack-eliciting packets under CUBIC wrapper.
    pub fn onPacketSent(self: *Cubic, bytes: usize, ack_eliciting: bool) void {
        self.inner.onPacketSent(bytes, ack_eliciting);
    }

    /// Update congestion window on ACK (delegates to inner NewReno placeholder).
    pub fn onAck(self: *Cubic, bytes_acked: usize) void {
        self.inner.onAck(bytes_acked);
    }

    pub fn onLoss(self: *Cubic, bytes_lost: usize) void {
        self.inner.onLoss(bytes_lost);
    }
};

/// RTT-based pacing delay per RFC 9002 Section 7.7.
///
/// Given the current congestion window, bytes in flight, smoothed RTT, and
/// packet size (typically max_datagram_size), returns the inter-packet pacing
/// delay in nanoseconds.
///
/// Formula: interval = packet_size * smoothed_rtt / cwnd
///
/// The slow-start exemption (no pacing when less than half of cwnd is in
/// flight) follows the RFC recommendation to avoid under-utilising the link
/// during ramp-up.
pub fn computePacingDelayNs(cwnd: usize, bytes_in_flight: usize, smoothed_rtt_ns: u64, packet_size: usize) u64 {
    if (cwnd == 0 or smoothed_rtt_ns == 0) return 0;
    // No pacing when utilisation is low (slow-start ramp-up).
    if (bytes_in_flight <= cwnd / 2) return 0;
    // RFC 9002 §7.7: interval = packet_size * smoothed_rtt / cwnd
    return @as(u64, packet_size) * smoothed_rtt_ns / @as(u64, cwnd);
}
