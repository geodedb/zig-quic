// MIT License
// QUIC Recovery skeleton: RTT estimator, PTO computation, and helpers
const std = @import("std");
const frame = @import("quic_frame");

pub const RttState = struct {
    // All values are in nanoseconds for monotonic arithmetic
    have_sample: bool = false,
    min_rtt_ns: u64 = 0,
    latest_rtt_ns: u64 = 0,
    smoothed_rtt_ns: u64 = 0,
    rttvar_ns: u64 = 0,
    max_ack_delay_ns: u64 = 0, // app space only; keep 0 for Initial/Handshake

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

    pub fn computePtoNs(self: *const RttState) u64 {
        // PTO = smoothed + 4*rttvar + max_ack_delay
        return self.smoothed_rtt_ns + (self.rttvar_ns * 4) + self.max_ack_delay_ns;
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
