// MIT License
// QUIC Recovery skeleton: RTT estimator, PTO computation, and helpers
const std = @import("std");
const frame = @import("quic_frame");

/// Round-trip time estimator state and PTO computation helpers (RFC 9002 §5-6).
pub const RttState = struct {
    // All values are in nanoseconds for monotonic arithmetic
    have_sample: bool = false,
    min_rtt_ns: u64 = 0,
    latest_rtt_ns: u64 = 0,
    smoothed_rtt_ns: u64 = 0,
    rttvar_ns: u64 = 0,
    max_ack_delay_ns: u64 = 0, // app space only; keep 0 for Initial/Handshake

    /// Update RTT estimator on ACK reception with measured RTT and ACK delay.
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
        if (measured_rtt_ns < self.min_rtt_ns) self.min_rtt_ns = measured_rtt_ns;
        const adjusted = blk: {
            const delayed = if (measured_rtt_ns > ack_delay_ns) measured_rtt_ns - ack_delay_ns else 0;
            // adjusted_rtt = max(delayed, min_rtt)
            break :blk if (delayed > self.min_rtt_ns) delayed else self.min_rtt_ns;
        };
        self.latest_rtt_ns = adjusted;
        // rttvar = (3/4)*rttvar + (1/4)*|smoothed - latest|
        const abs_err = if (self.smoothed_rtt_ns > adjusted) self.smoothed_rtt_ns - adjusted else adjusted - self.smoothed_rtt_ns;
        self.rttvar_ns = ((self.rttvar_ns * 3) / 4) + (abs_err / 4);
        // smoothed = (7/8)*smoothed + (1/8)*latest
        self.smoothed_rtt_ns = ((self.smoothed_rtt_ns * 7) / 8) + (adjusted / 8);
    }

    /// PTO = smoothed + 4*rttvar + max_ack_delay
    pub fn computePtoNs(self: *const RttState) u64 {
        // PTO = smoothed + 4*rttvar + max_ack_delay
        return self.smoothed_rtt_ns + (self.rttvar_ns * 4) + self.max_ack_delay_ns;
    }

    /// Compute PTO with exponential backoff and timer granularity.
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

/// Classify whether a frame is ack-eliciting (RFC 9002 §2).
/// ACK-only and PADDING are not ack-eliciting; most others are.
pub fn isAckElicitingFrame(fr: frame.Frame) bool {
    return switch (fr) {
        .ack => false,
        .padding => false,
        // DATAGRAM would be ack-eliciting if enabled; not present yet.
        else => true,
    };
}

/// NewReno congestion controller (bytes-based) with slow start and CA phases.
pub const NewReno = struct {
    // Congestion control state (bytes)
    cwnd: usize = 10 * 1200, // initial cwnd: 10 * max_datagram_size (approx)
    ssthresh: usize = std.math.maxInt(usize) / 2,
    bytes_in_flight: usize = 0,

    /// Track bytes in flight for ack-eliciting packets when sent.
    pub fn onPacketSent(self: *NewReno, bytes: usize, ack_eliciting: bool) void {
        if (ack_eliciting) self.bytes_in_flight += bytes;
    }

    /// Increase cwnd on ACK and exit slow start to congestion avoidance.
    pub fn onAck(self: *NewReno, bytes_acked: usize) void {
        if (self.cwnd < self.ssthresh) {
            // Slow start
            self.cwnd += bytes_acked;
        } else {
            // Congestion avoidance: cwnd += max_datagram_size * bytes_acked / cwnd
            const mds: usize = 1200;
            self.cwnd += (mds * bytes_acked) / self.cwnd;
        }
        if (self.bytes_in_flight >= bytes_acked) self.bytes_in_flight -= bytes_acked else self.bytes_in_flight = 0;
    }

    /// Halve cwnd on loss and set ssthresh accordingly.
    pub fn onLoss(self: *NewReno, bytes_lost: usize) void {
        if (self.cwnd > 2 * 1200) self.cwnd = self.cwnd / 2 else self.cwnd = 2 * 1200;
        self.ssthresh = self.cwnd;
        if (self.bytes_in_flight >= bytes_lost) self.bytes_in_flight -= bytes_lost else self.bytes_in_flight = 0;
    }
};

/// CUBIC congestion controller (stub): forwards to an internal NewReno for now.
pub const Cubic = struct {
    inner: NewReno = .{},

    pub fn onPacketSent(self: *Cubic, bytes: usize, ack_eliciting: bool) void {
        self.inner.onPacketSent(bytes, ack_eliciting);
    }
    pub fn onAck(self: *Cubic, bytes_acked: usize) void {
        self.inner.onAck(bytes_acked);
    }
    pub fn onLoss(self: *Cubic, bytes_lost: usize) void {
        self.inner.onLoss(bytes_lost);
    }
};

/// Loss detection helpers implementing packet- and time-threshold logic (RFC 9002 §6-7).
pub const LossDetector = struct {
    // Packet-threshold (default 3) and time-threshold (9/8 * max(smoothed_rtt, latest_rtt))
    packet_threshold: u32 = 3,

    /// Return true if pn is considered lost using packet threshold relative to largest_acked.
    pub fn isPacketThresholdLost(self: *const LossDetector, largest_acked: u64, pn: u64) bool {
        return largest_acked >= pn + self.packet_threshold;
    }

    /// Time threshold as 1.125x of the larger of smoothed/latest RTT.
    pub fn timeThresholdNs(smoothed_rtt_ns: u64, latest_rtt_ns: u64) u64 {
        const base = if (smoothed_rtt_ns > latest_rtt_ns) smoothed_rtt_ns else latest_rtt_ns;
        return base + base / 8; // 1.125x
    }
};

/// Optional pacing hook: given cwnd and bytes_in_flight, return an inter-packet pacing delay in ns.
/// This minimal implementation returns 0 (no pacing). Future slices may compute pacing based on BDP.
pub fn computePacingDelayNs(cwnd: usize, bytes_in_flight: usize) u64 {
    _ = cwnd;
    _ = bytes_in_flight;
    return 0;
}
