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
    // Very simple pacing heuristic:
    // - No delay if less than half of cwnd is in flight.
    // - Small delay if between 1/2 and full cwnd.
    // - Larger delay if at or above cwnd.
    if (cwnd == 0) return 0;
    if (bytes_in_flight < cwnd / 2) return 0;
    if (bytes_in_flight < cwnd) return 250_000; // 0.25 ms
    return 1_000_000; // 1 ms
}

pub const PacketNumberSpace = enum { Initial, Handshake, Application };

/// Sent packet metadata for recovery tracking
pub const SentPacket = struct {
    pn: u64,
    time_ns: u64,
    size: usize,
    ack_eliciting: bool,
    acked: bool = false,
    declared_lost: bool = false,
};

const SpaceState = struct {
    sent: std.ArrayList(SentPacket),
    largest_acked: ?u64 = null,
    loss_time_ns: ?u64 = null,

    fn init(alloc: std.mem.Allocator) SpaceState {
        return .{ .sent = std.ArrayList(SentPacket).init(alloc) };
    }
    fn deinit(self: *SpaceState) void {
        self.sent.deinit();
    }
};

/// Recovery state: RTT, loss detection, PTO backoff, and NewReno CC
pub const Recovery = struct {
    allocator: std.mem.Allocator,
    rtt: RttState = .{},
    cc: NewReno = .{},
    loss: LossDetector = .{},
    pto_count: u32 = 0,
    timer_granularity_ns: u64 = std.time.ns_per_ms, // 1ms
    spaces: [3]SpaceState,
    // Persistent congestion tracking
    k_pc_threshold: u32 = 3, // number of PTOs that must elapse during contiguous loss for PC

    pub fn init(alloc: std.mem.Allocator) Recovery {
        return .{
            .allocator = alloc,
            .spaces = .{
                SpaceState.init(alloc),
                SpaceState.init(alloc),
                SpaceState.init(alloc),
            },
        };
    }

    pub fn deinit(self: *Recovery) void {
        inline for (&self.spaces) |*s| s.deinit();
    }

    fn spaceIdx(space: PacketNumberSpace) usize {
        return @intFromEnum(space);
    }

    /// Record a sent packet for recovery and congestion control.
    pub fn onPacketSent(self: *Recovery, space: PacketNumberSpace, pn: u64, size: usize, ack_eliciting: bool, time_ns: u64) !void {
        const idx = spaceIdx(space);
        try self.spaces[idx].sent.append(.{ .pn = pn, .time_ns = time_ns, .size = size, .ack_eliciting = ack_eliciting });
        self.cc.onPacketSent(size, ack_eliciting);
        // Schedule time-threshold loss if we have an RTT sample; do not promote here.
        if (ack_eliciting and self.rtt.have_sample) {
            const tt_base = LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns);
            const deadline = time_ns + tt_base;
            const cur = self.spaces[idx].loss_time_ns;
            if (cur == null or deadline < cur.?) self.spaces[idx].loss_time_ns = deadline;
        }
    }

    /// Process received ACKs for a number space. Provide acked PNs, ACK delay, and now.
    /// Returns bytes_acked and bytes_lost from immediate loss detection (packet-threshold only).
    pub fn onAckReceived(self: *Recovery, space: PacketNumberSpace, acked_pns: []const u64, ack_delay_ns: u64, now_ns: u64) struct { bytes_acked: usize, bytes_lost: usize } {
        const idx = spaceIdx(space);
        var sstate = &self.spaces[idx];
        var bytes_acked: usize = 0;
        var ack_eliciting_acked = false;
        var largest_pn: u64 = sstate.largest_acked orelse 0;
        var largest_acked_pkt_time: ?u64 = null;

        // Mark acked packets
        for (acked_pns) |pn| {
            // linear scan is fine for tests; production can index by PN
            for (sstate.sent.items) |*sp| {
                if (sp.pn == pn and !sp.acked and !sp.declared_lost) {
                    sp.acked = true;
                    bytes_acked += sp.size;
                    if (sp.ack_eliciting) ack_eliciting_acked = true;
                    if (pn > largest_pn) {
                        largest_pn = pn;
                        largest_acked_pkt_time = sp.time_ns;
                    }
                    break;
                }
            }
        }
        if (largest_acked_pkt_time) |t_ack| {
            const measured = if (now_ns > t_ack) now_ns - t_ack else 0;
            self.rtt.onAck(measured, ack_delay_ns);
        }
        if (largest_pn != (sstate.largest_acked orelse 0)) sstate.largest_acked = largest_pn;

        // Loss detection: packet-threshold only on ACK receipt
        var bytes_lost: usize = 0;
        var first_lost_time: ?u64 = null;
        var last_lost_time: ?u64 = null;
        if (sstate.largest_acked) |la| {
            for (sstate.sent.items) |*sp| {
                if (!sp.acked and !sp.declared_lost) {
                    if (self.loss.isPacketThresholdLost(la, sp.pn)) {
                        sp.declared_lost = true;
                        bytes_lost += sp.size;
                        if (first_lost_time == null or sp.time_ns < first_lost_time.?) first_lost_time = sp.time_ns;
                        if (last_lost_time == null or sp.time_ns > last_lost_time.?) last_lost_time = sp.time_ns;
                    }
                }
            }
        }

        // Time-threshold: only schedule next potential loss time; do not promote here.
        var earliest_loss_time: ?u64 = null;
        if (self.rtt.have_sample) {
            const tt_base = LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns);
            for (sstate.sent.items) |*sp| {
                if (!sp.acked and !sp.declared_lost and sp.ack_eliciting) {
                    const deadline = sp.time_ns + tt_base;
                    if (earliest_loss_time == null or deadline < earliest_loss_time.?) {
                        earliest_loss_time = deadline;
                    }
                }
            }
        }
        sstate.loss_time_ns = earliest_loss_time;

        // Congestion control accounting
        if (bytes_acked > 0) self.cc.onAck(bytes_acked);
        if (bytes_lost > 0) {
            self.cc.onLoss(bytes_lost);
            // Persistent congestion check on packet-threshold loss spans
            if (first_lost_time != null and last_lost_time != null) {
                const pto_base = self.rtt.computePtoNsWithBackoff(0, self.timer_granularity_ns);
                const pc_period = pto_base * self.k_pc_threshold;
                if (last_lost_time.? - first_lost_time.? >= pc_period) {
                    // Enter persistent congestion: reduce cwnd to minimum window (2 * max_datagram_size)
                    const min_window: usize = 2 * 1200;
                    self.cc.cwnd = min_window;
                    self.cc.ssthresh = min_window;
                }
            }
        }
        if (ack_eliciting_acked) self.pto_count = 0;

        return .{ .bytes_acked = bytes_acked, .bytes_lost = bytes_lost };
    }

    /// Compute the earliest PTO deadline across spaces, or null if no ack-eliciting is in flight.
    pub fn computeNextPtoTimeNs(self: *const Recovery, now_ns: u64) ?u64 {
        // Find earliest outstanding ack-eliciting send time
        var earliest_send: ?u64 = null;
        inline for (self.spaces) |sstate| {
            for (sstate.sent.items) |sp| {
                if (!sp.acked and !sp.declared_lost and sp.ack_eliciting) {
                    if (earliest_send == null or sp.time_ns < earliest_send.?) earliest_send = sp.time_ns;
                }
            }
        }
        if (earliest_send == null) return null;
        const pto = self.rtt.computePtoNsWithBackoff(self.pto_count, self.timer_granularity_ns);
        const base = earliest_send.? + pto;
        // If base already passed, return now to indicate immediate probe
        if (base <= now_ns) return now_ns;
        return base;
    }

    /// Compute the PTO deadline for a specific packet number space, or null if none in-flight.
    pub fn computeSpacePtoTimeNs(self: *const Recovery, space: PacketNumberSpace, now_ns: u64) ?u64 {
        const idx = spaceIdx(space);
        var earliest_send: ?u64 = null;
        for (self.spaces[idx].sent.items) |sp| {
            if (!sp.acked and !sp.declared_lost and sp.ack_eliciting) {
                if (earliest_send == null or sp.time_ns < earliest_send.?) earliest_send = sp.time_ns;
            }
        }
        if (earliest_send == null) return null;
        const pto = self.rtt.computePtoNsWithBackoff(self.pto_count, self.timer_granularity_ns);
        const base = earliest_send.? + pto;
        if (base <= now_ns) return now_ns;
        return base;
    }

    /// Promote time-threshold losses if any loss_time has expired at now.
    pub fn onLossTimeExpired(self: *Recovery, now_ns: u64) usize {
        var total_lost: usize = 0;
        var first_lost_time: ?u64 = null;
        var last_lost_time: ?u64 = null;
        inline for (&self.spaces) |*sstate| {
            if (sstate.loss_time_ns) |lt| {
                if (now_ns >= lt) {
                    // Re-run time-threshold pass for this space
                    const tt_base = LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns);
                    var next_loss: ?u64 = null;
                    for (sstate.sent.items) |*sp| {
                        if (!sp.acked and !sp.declared_lost and sp.ack_eliciting) {
                            const deadline = sp.time_ns + tt_base;
                            if (now_ns >= deadline) {
                                sp.declared_lost = true;
                                total_lost += sp.size;
                                if (first_lost_time == null or sp.time_ns < first_lost_time.?) first_lost_time = sp.time_ns;
                                if (last_lost_time == null or sp.time_ns > last_lost_time.?) last_lost_time = sp.time_ns;
                            } else if (next_loss == null or deadline < next_loss.?) {
                                next_loss = deadline;
                            }
                        }
                    }
                    sstate.loss_time_ns = next_loss;
                }
            }
        }
        if (total_lost > 0) {
            self.cc.onLoss(total_lost);
            // Persistent congestion check on time-threshold loss spans
            if (first_lost_time != null and last_lost_time != null) {
                const pto_base = self.rtt.computePtoNsWithBackoff(0, self.timer_granularity_ns);
                const pc_period = pto_base * self.k_pc_threshold;
                if (last_lost_time.? - first_lost_time.? >= pc_period) {
                    const min_window: usize = 2 * 1200;
                    self.cc.cwnd = min_window;
                    self.cc.ssthresh = min_window;
                }
            }
        }
        return total_lost;
    }
};

fn msToNs(ms: u64) u64 {
    return ms * std.time.ns_per_ms;
}
