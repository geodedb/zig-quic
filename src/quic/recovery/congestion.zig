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

/// CUBIC congestion controller implementing RFC 8312.
///
/// Uses the W_cubic(t) = C * (t - K)^3 + W_max curve for congestion avoidance,
/// with TCP-friendliness via W_est to ensure at least AIMD-equivalent throughput.
/// Slow start delegates to standard NewReno behavior.
///
/// All window computations use bytes (not packets) for consistency with the
/// QUIC recovery framework. The beta multiplicative decrease factor is 0.7
/// (vs NewReno's 0.5), giving CUBIC its characteristic gentler loss response.
///
/// RFC 8312: CUBIC for Fast Long-Distance Networks
/// RFC 9002 Appendix B.2: CUBIC
pub const Cubic = struct {
    /// CUBIC scaling constant C (RFC 8312 S4).
    pub const C: f64 = 0.4;

    /// CUBIC multiplicative decrease factor beta (RFC 8312 S4).
    /// On loss: ssthresh = cwnd * beta, cwnd = ssthresh.
    pub const BETA: f64 = 0.7;

    // Congestion control state (bytes)
    mds: usize = 1200,
    cwnd: usize = 10 * 1200,
    ssthresh: usize = std.math.maxInt(usize) / 2,
    bytes_in_flight: usize = 0,

    // CUBIC-specific state
    /// W_max: cwnd (bytes) at last loss event.
    w_max: usize = 0,
    /// Nanosecond timestamp when the current CUBIC epoch started (set on first ACK
    /// in congestion avoidance after a loss event). null means no epoch is active.
    epoch_start_ns: ?u64 = null,
    /// Precomputed K value (seconds) for the current epoch.
    /// K = cbrt(W_max * (1 - beta) / C) where W_max is in MSS units.
    k_sec: f64 = 0.0,
    /// TCP-friendliness estimate W_est (bytes), tracks what standard AIMD would achieve.
    w_est: usize = 0,

    /// Track bytes in flight for ack-eliciting packets under CUBIC.
    pub fn onPacketSent(self: *Cubic, bytes: usize, ack_eliciting: bool) void {
        if (ack_eliciting) self.bytes_in_flight += bytes;
    }

    /// Compute K (seconds): time period for W_cubic(t) to reach W_max after a loss.
    ///
    /// K = cbrt(W_max_mss * (1 - beta) / C)
    ///
    /// `w_max_bytes` is the congestion window at the last loss event, in bytes.
    /// `mds` is the max datagram size used to convert to MSS units.
    pub fn computeK(w_max_bytes: usize, mds: usize) f64 {
        if (w_max_bytes == 0 or mds == 0) return 0.0;
        const w_max_mss: f64 = @as(f64, @floatFromInt(w_max_bytes)) / @as(f64, @floatFromInt(mds));
        const val: f64 = w_max_mss * (1.0 - BETA) / C;
        return std.math.cbrt(val);
    }

    /// Compute W_cubic(t) in bytes using the provided mds for unit conversion.
    ///
    /// W_cubic_mss(t) = C * (t - K)^3 + W_max_mss
    /// W_cubic_bytes = W_cubic_mss * mds
    ///
    /// `t_sec`: elapsed seconds since epoch start.
    /// `k_sec_val`: precomputed K value (seconds).
    /// `w_max_bytes`: W_max in bytes.
    /// `mds`: max datagram size for MSS conversion.
    pub fn wCubicBytes(t_sec: f64, k_sec_val: f64, w_max_bytes: usize, mds: usize) usize {
        if (mds == 0) return 0;
        const mds_f: f64 = @floatFromInt(mds);
        const w_max_mss: f64 = @as(f64, @floatFromInt(w_max_bytes)) / mds_f;
        const diff = t_sec - k_sec_val;
        const w_cubic_mss = C * diff * diff * diff + w_max_mss;
        const w_bytes = w_cubic_mss * mds_f;
        if (w_bytes < 0.0) return 0;
        return @intFromFloat(@max(w_bytes, 0.0));
    }

    /// Compute W_est (TCP-friendliness estimate) in bytes.
    ///
    /// W_est(t) = W_max * beta + (3 * (1 - beta) / (1 + beta)) * (t / RTT) * mds
    ///
    /// This represents what a standard AIMD (TCP Reno) would achieve over the
    /// same time period. CUBIC uses max(W_cubic, W_est) to ensure it is never
    /// slower than standard TCP.
    pub fn computeWEst(t_sec: f64, rtt_sec: f64, w_max_bytes: usize, mds: usize) usize {
        if (rtt_sec <= 0.0 or mds == 0) return 0;
        const w_max_f: f64 = @floatFromInt(w_max_bytes);
        const mds_f: f64 = @floatFromInt(mds);
        const base = w_max_f * BETA;
        // 3 * (1 - beta) / (1 + beta) = 3 * 0.3 / 1.7 ~= 0.5294
        const rtt_count = t_sec / rtt_sec;
        const growth = (3.0 * (1.0 - BETA) / (1.0 + BETA)) * rtt_count * mds_f;
        const result = base + growth;
        if (result < 0.0) return 0;
        return @intFromFloat(@max(result, 0.0));
    }

    /// Increase cwnd on ACK using CUBIC congestion avoidance or slow start.
    ///
    /// In slow start (cwnd < ssthresh): standard exponential growth.
    /// In congestion avoidance: uses max(W_cubic(t), W_est(t)) per RFC 8312.
    ///
    /// `now_ns` is the current timestamp in nanoseconds.
    /// `rtt_ns` is the smoothed RTT in nanoseconds (used for TCP-friendliness).
    pub fn onAck(self: *Cubic, bytes_acked: usize, now_ns: u64, rtt_ns: u64) void {
        if (bytes_acked == 0) {
            return;
        }

        // Reduce bytes in flight
        if (self.bytes_in_flight >= bytes_acked) self.bytes_in_flight -= bytes_acked else self.bytes_in_flight = 0;

        if (self.cwnd < self.ssthresh) {
            // Slow start: standard exponential growth
            self.cwnd += bytes_acked;
            return;
        }

        // Congestion avoidance: CUBIC algorithm
        const mds = self.mds;
        if (mds == 0) return;

        // Initialize epoch on first ACK in congestion avoidance after loss
        if (self.epoch_start_ns == null) {
            self.epoch_start_ns = now_ns;
            if (self.w_max == 0) {
                // First time entering congestion avoidance (no prior loss)
                self.w_max = self.cwnd;
            }
            self.k_sec = computeK(self.w_max, mds);
            self.w_est = self.cwnd;
        }

        const epoch_start = self.epoch_start_ns.?;
        const elapsed_ns: u64 = if (now_ns > epoch_start) now_ns - epoch_start else 0;
        const t_sec: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));

        // Compute W_cubic(t)
        const w_cubic = wCubicBytes(t_sec, self.k_sec, self.w_max, mds);

        // Compute W_est for TCP-friendliness
        const rtt_sec: f64 = @as(f64, @floatFromInt(rtt_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        const w_est_val = computeWEst(t_sec, rtt_sec, self.w_max, mds);

        // Target = max(W_cubic, W_est)
        const target = @max(w_cubic, w_est_val);

        // Never decrease cwnd on ACK
        if (target > self.cwnd) {
            self.cwnd = target;
        } else {
            // Ensure at least minimal growth: 1 mds per RTT equivalent
            // (cwnd += mds * bytes_acked / cwnd) -- same as NewReno congestion avoidance
            const inc = (mds * bytes_acked) / @max(self.cwnd, @as(usize, 1));
            if (inc > 0) {
                self.cwnd += inc;
            }
        }
    }

    /// Handle loss event with CUBIC's beta=0.7 multiplicative decrease.
    ///
    /// RFC 8312 S4.6: On loss, W_max = cwnd, ssthresh = cwnd * beta, cwnd = ssthresh.
    /// The epoch is reset so the next ACK starts a fresh CUBIC curve.
    pub fn onLoss(self: *Cubic, bytes_lost: usize) void {
        const min_wnd = 2 * self.mds;

        // Save W_max before reduction
        self.w_max = self.cwnd;

        // Apply beta=0.7 multiplicative decrease
        // Use integer arithmetic: cwnd * 7 / 10
        self.cwnd = @max(self.cwnd * 7 / 10, min_wnd);
        self.ssthresh = self.cwnd;

        // Reset epoch for next CUBIC curve
        self.epoch_start_ns = null;
        self.k_sec = 0.0;
        self.w_est = 0;

        // Account for lost bytes
        if (self.bytes_in_flight >= bytes_lost) self.bytes_in_flight -= bytes_lost else self.bytes_in_flight = 0;
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
