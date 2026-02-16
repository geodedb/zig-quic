// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! RTT estimation and PTO computation.
//!
//! RFC 9002 §5: Estimating the Round-Trip Time
//! RFC 9002 §6.2: Probe Timeout

const std = @import("std");

/// Round-trip time estimator state and PTO computation helpers (RFC 9002 §5-6).
pub const RttState = struct {
    // All values are in nanoseconds for monotonic arithmetic
    // RFC 9002 Appendix A.2: kInitialRtt = 333ms
    const kInitialRttNs: u64 = 333 * std.time.ns_per_ms;

    have_sample: bool = false,
    min_rtt_ns: u64 = 0,
    latest_rtt_ns: u64 = 0,
    smoothed_rtt_ns: u64 = kInitialRttNs, // RFC 9002 §6.2: Use initial RTT before first sample
    rttvar_ns: u64 = kInitialRttNs / 2, // RFC 9002: Initial rttvar = initial_rtt / 2
    max_ack_delay_ns: u64 = 0, // app space only; keep 0 for Initial/Handshake

    /// Update RTT estimator on ACK reception with measured RTT and ACK delay.
    /// RFC 9002 §5.3: Estimating smoothed_rtt and rttvar
    pub fn onAck(self: *RttState, measured_rtt_ns: u64, ack_delay_ns: u64) void {
        // RFC 9002 §5: Adjusted RTT = max(measured_rtt - ack_delay, min_rtt)
        if (!self.have_sample) {
            self.have_sample = true;
            self.min_rtt_ns = measured_rtt_ns;
            self.latest_rtt_ns = measured_rtt_ns;
            self.smoothed_rtt_ns = measured_rtt_ns;
            self.rttvar_ns = measured_rtt_ns / 2;
            return;
        }
        // Only update min_rtt with trustworthy measurements (ack_delay doesn't exceed measured RTT)
        if (measured_rtt_ns >= ack_delay_ns and measured_rtt_ns < self.min_rtt_ns) {
            self.min_rtt_ns = measured_rtt_ns;
        }
        const adjusted = blk: {
            const delayed = if (measured_rtt_ns > ack_delay_ns) measured_rtt_ns - ack_delay_ns else 0;
            // adjusted_rtt = max(delayed, min_rtt)
            break :blk if (delayed > self.min_rtt_ns) delayed else self.min_rtt_ns;
        };
        self.latest_rtt_ns = adjusted;
        const abs_err = if (self.smoothed_rtt_ns > adjusted) self.smoothed_rtt_ns - adjusted else adjusted - self.smoothed_rtt_ns;
        self.rttvar_ns = ((self.rttvar_ns * 3) / 4) + (abs_err / 4);
        self.smoothed_rtt_ns = ((self.smoothed_rtt_ns * 7) / 8) + (adjusted / 8);
    }

    /// PTO = smoothed + 4*rttvar + max_ack_delay
    /// RFC 9002 §6.2.1: Computing PTO
    pub fn computePtoNs(self: *const RttState) u64 {
        // PTO = smoothed + 4*rttvar + max_ack_delay
        return self.smoothed_rtt_ns + (self.rttvar_ns * 4) + self.max_ack_delay_ns;
    }

    /// Compute PTO with exponential backoff and timer granularity.
    /// RFC 9002 §6.2.1: Computing PTO
    pub fn computePtoNsWithBackoff(self: *const RttState, pto_count: u32, granularity_ns: u64) u64 {
        // RFC 9002: PTO_base + timer_granularity, scaled by 2^pto_count
        const base = self.computePtoNs();
        const max_u64: u64 = std.math.maxInt(u64);
        const plus = if (base > (max_u64 - granularity_ns)) max_u64 else base + granularity_ns;
        const shift: u6 = @intCast(if (pto_count > 63) 63 else pto_count);
        if (shift == 63) return max_u64;
        if (plus > (max_u64 >> shift)) return max_u64;
        return plus << shift;
    }
};
