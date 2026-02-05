// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC recovery primitives: RTT estimator, PTO computation, and helpers.
//!
//! Implements the congestion control and loss detection pieces of RFC 9002.
const std = @import("std");
const frame = @import("quic_frame");

/// Shared CC state used by Recovery for both NewReno and CUBIC (bytes units)
pub const CcState = struct {
    mds: usize = 1200,
    cwnd: usize = 10 * 1200,
    ssthresh: usize = std.math.maxInt(usize) / 2,
    bytes_in_flight: usize = 0,
};

/// CUBIC constant C (scales the cubic function), exposed for tuning/tests.
pub const CUBIC_C_DEFAULT: f64 = 0.4;
/// CUBIC multiplicative decrease factor beta, exposed for tuning/tests.
pub const CUBIC_BETA_DEFAULT: f64 = 0.7;

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
        const abs_err = if (self.smoothed_rtt_ns > adjusted) self.smoothed_rtt_ns - adjusted else adjusted - self.smoothed_rtt_ns;
        self.rttvar_ns = ((self.rttvar_ns * 3) / 4) + (abs_err / 4);
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
/// Exposed for tests verifying ECN/loss logic classification.
pub fn isAckElicitingFrame(fr: frame.Frame) bool {
    return switch (fr) {
        .ack => false,
        .padding => false,
        // DATAGRAM would be ack-eliciting if enabled; not present yet.
        else => true,
    };
}

/// NewReno congestion controller (bytes-based) implementing slow start and congestion avoidance per RFC 9002.
pub const NewReno = struct {
    // Congestion control state (bytes)
    // Configurable max datagram size (RFC 9002 "max_datagram_size").
    mds: usize = 1200,
    cwnd: usize = 10 * 1200, // initial cwnd: 10 * mds (default 1200)
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
            // Congestion avoidance: cwnd += mds * bytes_acked / cwnd
            const mds_local: usize = self.mds;
            self.cwnd += (mds_local * bytes_acked) / self.cwnd;
        }
        if (self.bytes_in_flight >= bytes_acked) self.bytes_in_flight -= bytes_acked else self.bytes_in_flight = 0;
    }

    /// Halve cwnd on loss and set ssthresh accordingly.
    fn onLoss(self: *NewReno, bytes_lost: usize) void {
        const min_wnd = 2 * self.mds;
        if (self.cwnd > min_wnd) self.cwnd = self.cwnd / 2 else self.cwnd = min_wnd;
        self.ssthresh = self.cwnd;
        if (self.bytes_in_flight >= bytes_lost) self.bytes_in_flight -= bytes_lost else self.bytes_in_flight = 0;
    }
};
/// CUBIC congestion controller placeholder wrapping NewReno behavior (future expansion).
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
    fn onLoss(self: *Cubic, bytes_lost: usize) void {
        self.inner.onLoss(bytes_lost);
    }
};

/// Loss detection helper implementing packet/time threshold loss logic (RFC 9002 §6.1).
pub const LossDetector = struct {
    /// Packet-threshold (default 3) and time-threshold (9/8 * max(smoothed_rtt, latest_rtt)).
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
/// This minimal implementation returns a coarse delay based on how full cwnd is.
/// Used only in tests right now; production pacing TBD.
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

/// Packet number spaces used by QUIC: Initial, Handshake, and Application (1-RTT).
/// QUIC packet number spaces (RFC 9000): each maintains separate PN sequence and ACK logic.
pub const PacketNumberSpace = enum { Initial, Handshake, Application };

/// Sent packet metadata tracked for loss recovery and RTT measurement.
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
    allocator: std.mem.Allocator,
    largest_acked: ?u64 = null,
    loss_time_ns: ?u64 = null,
    // Last observed ECN counters from peer's ACK_ECN for this space
    ecn_last: frame.EcnCounts = .{ .ect0 = 0, .ect1 = 0, .ce = 0 },
    ecn_seen_any: bool = false,

    fn init(alloc: std.mem.Allocator) SpaceState {
        // Use .empty for proper Zig 0.15 ArrayListUnmanaged initialization
        return .{ .sent = .empty, .allocator = alloc };
    }
    fn deinit(self: *SpaceState) void {
        self.sent.deinit(self.allocator);
    }
};

/// Recovery state: RTT, loss detection, PTO backoff, and CC (NewReno or CUBIC)
pub const Recovery = struct {
    allocator: std.mem.Allocator,
    rtt: RttState = .{},
    cc: CcState = .{},
    use_cubic: bool = false,
    // CUBIC state (packet units)
    cubic_c: f64 = CUBIC_C_DEFAULT,
    cubic_beta: f64 = CUBIC_BETA_DEFAULT,
    cubic_epoch_start_ns: ?u64 = null,
    cubic_w_max_p: f64 = 0.0,
    cubic_origin_point_p: f64 = 0.0,
    cubic_k: f64 = 0.0,

    loss: LossDetector = .{},
    pto_count: u32 = 0,
    timer_granularity_ns: u64 = std.time.ns_per_ms,
    spaces: [3]SpaceState,
    k_pc_threshold: u32 = 3,

    /// Initialize a Recovery instance with fresh per-space state.
    pub fn init(alloc: std.mem.Allocator) Recovery {
        return .{ .allocator = alloc, .spaces = .{ SpaceState.init(alloc), SpaceState.init(alloc), SpaceState.init(alloc) } };
    }

    /// Free per-space arrays and internal allocations.
    pub fn deinit(self: *Recovery) void {
        inline for (&self.spaces) |*s| s.deinit();
    }

    fn spaceIdx(space: PacketNumberSpace) usize {
        return @intFromEnum(space);
    }

    /// Select congestion control mode (false = NewReno, true = CUBIC).
    pub fn setCcMode(self: *Recovery, cubic: bool) void {
        self.use_cubic = cubic;
        if (cubic) {
            // Initialize CUBIC reference point
            const cwnd_p = @as(f64, @floatFromInt(self.cc.cwnd)) / @as(f64, @floatFromInt(self.cc.mds));
            self.cubic_w_max_p = if (cwnd_p > 0) cwnd_p else 10.0; // default near initial window
            self.cubic_origin_point_p = self.cubic_w_max_p;
            self.cubic_k = 0.0;
            self.cubic_epoch_start_ns = null;
        }
    }

    /// Record a packet as sent in the given space.
    pub fn onPacketSent(self: *Recovery, space: PacketNumberSpace, pn: u64, bytes: usize, ack_eliciting: bool, now_ns: u64) !void {
        const idx = spaceIdx(space);
        try self.spaces[idx].sent.append(self.spaces[idx].allocator, .{ .pn = pn, .time_ns = now_ns, .size = bytes, .ack_eliciting = ack_eliciting });
        if (ack_eliciting) self.cc.bytes_in_flight += bytes;
        // Schedule time-threshold loss if we have an RTT sample; do not promote here.
        if (ack_eliciting and self.rtt.have_sample) {
            const tt_base = LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns);
            const deadline = now_ns + tt_base;
            const cur = self.spaces[idx].loss_time_ns;
            if (cur == null or deadline < cur.?) self.spaces[idx].loss_time_ns = deadline;
        }
    }

    /// Result of ACK/loss processing with aggregate counters.
    pub const AckResult = struct { bytes_acked: usize = 0, bytes_lost: usize = 0 };
    /// Handle ACK frames (no ECN) for a given space, update RTT/loss/cc, and return summary.
    pub fn onAckReceived(self: *Recovery, space: PacketNumberSpace, acked: []const u64, ack_delay_ns: u64, now_ns: u64) AckResult {
        return self.onAckReceivedWithEcn(space, acked, ack_delay_ns, now_ns, null);
    }

    /// Handle ACK frames for a given space with optional ECN counters.
    pub fn onAckReceivedWithEcn(self: *Recovery, space: PacketNumberSpace, acked: []const u64, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        const idx = spaceIdx(space);
        var sstate = &self.spaces[idx];
        var bytes_acked: usize = 0;
        var ack_eliciting_acked = false;
        var largest_pn: u64 = sstate.largest_acked orelse 0;
        var largest_acked_pkt_time: ?u64 = null;

        // Mark acked packets
        for (acked) |pn| {
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

        // Loss detection: packet-threshold only on ACK
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

        // Time-threshold scheduling
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
        if (bytes_acked > 0) self.ccOnAck(bytes_acked, now_ns);
        // ECN processing: on ACK_ECN monotonic counters, reduce cwnd if CE increased
        if (ecn) |counts| {
            // Ignore if counters decreased (reordering or counter reset)
            if ((!sstate.ecn_seen_any) or (counts.ect0 >= sstate.ecn_last.ect0 and counts.ect1 >= sstate.ecn_last.ect1 and counts.ce >= sstate.ecn_last.ce)) {
                const ce_delta: u64 = if (counts.ce > sstate.ecn_last.ce) counts.ce - sstate.ecn_last.ce else 0;
                sstate.ecn_last = counts;
                sstate.ecn_seen_any = true;
                if (ce_delta > 0) {
                    self.ccOnEcn();
                }
            }
        }
        if (bytes_lost > 0) {
            self.ccOnLoss(bytes_lost);
            if (first_lost_time != null and last_lost_time != null) {
                const pto_base = self.rtt.computePtoNsWithBackoff(0, self.timer_granularity_ns);
                const pc_period = pto_base * self.k_pc_threshold;
                if (last_lost_time.? - first_lost_time.? >= pc_period) {
                    const min_window: usize = 2 * self.cc.mds;
                    self.cc.cwnd = min_window;
                    self.cc.ssthresh = min_window;
                }
            }
        }
        if (ack_eliciting_acked) self.pto_count = 0;

        return .{ .bytes_acked = bytes_acked, .bytes_lost = bytes_lost };
    }

    /// Increase cwnd on ACK, reduce bytes_in_flight; NewReno-style growth.
    fn ccOnAck(self: *Recovery, bytes_acked: usize, now_ns: u64) void {
        _ = now_ns; // reserved for future pacing hooks
        if (bytes_acked == 0) return;
        if (self.cc.cwnd < self.cc.ssthresh) {
            // Slow start: cwnd grows by bytes_acked
            self.cc.cwnd += bytes_acked;
        } else {
            // Congestion avoidance: cwnd += mds * bytes_acked / cwnd
            const inc = (self.cc.mds * bytes_acked) / @max(self.cc.cwnd, @as(usize, 1));
            self.cc.cwnd += inc;
        }
        if (self.cc.bytes_in_flight >= bytes_acked) self.cc.bytes_in_flight -= bytes_acked else self.cc.bytes_in_flight = 0;
    }

    /// Cut cwnd on loss (1/2) with floor at 2*mds; reduce bytes_in_flight by lost bytes.
    fn ccOnLoss(self: *Recovery, bytes_lost: usize) void {
        if (bytes_lost == 0) return;
        const min_wnd: usize = 2 * self.cc.mds;
        self.cc.cwnd = @max(self.cc.cwnd / 2, min_wnd);
        self.cc.ssthresh = self.cc.cwnd;
        if (self.cc.bytes_in_flight >= bytes_lost) self.cc.bytes_in_flight -= bytes_lost else self.cc.bytes_in_flight = 0;
    }

    /// React to ECN-CE by reducing cwnd like a loss event (without changing bytes_in_flight).
    fn ccOnEcn(self: *Recovery) void {
        const min_wnd: usize = 2 * self.cc.mds;
        self.cc.cwnd = @max(self.cc.cwnd / 2, min_wnd);
        self.cc.ssthresh = self.cc.cwnd;
    }

    /// Recompute loss detection timeouts and declare any time-threshold losses.
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
            self.ccOnLoss(total_lost);
            if (first_lost_time != null and last_lost_time != null) {
                const pto_base = self.rtt.computePtoNsWithBackoff(0, self.timer_granularity_ns);
                const pc_period = pto_base * self.k_pc_threshold;
                if (last_lost_time.? - first_lost_time.? >= pc_period) {
                    const min_window: usize = 2 * self.cc.mds;
                    self.cc.cwnd = min_window;
                    self.cc.ssthresh = min_window;
                }
            }
        }
        return total_lost;
    }

    /// Compute PTO deadline from now using current backoff counter and granularity.
    pub fn computeNextPtoTimeNs(self: *const Recovery, now_ns: u64) ?u64 {
        // Only arm PTO if any ack-eliciting packets are in flight.
        var any_in_flight = false;
        inline for (&self.spaces) |*sstate| {
            for (sstate.sent.items) |sp| {
                if (sp.ack_eliciting and !sp.acked and !sp.declared_lost) {
                    any_in_flight = true;
                    break;
                }
            }
            if (any_in_flight) break;
        }
        if (!any_in_flight) return null;
        const base = self.rtt.computePtoNsWithBackoff(self.pto_count, self.timer_granularity_ns);
        return now_ns + base;
    }

    /// Compute next PTO deadline for a given space relative to now.
    pub fn computeSpacePtoTimeNs(self: *Recovery, space: PacketNumberSpace, now_ns: u64) ?u64 {
        const idx = spaceIdx(space);
        const pto = self.rtt.computePtoNs();
        const deadline = now_ns + pto;
        const cur = self.spaces[idx].loss_time_ns;
        if (cur == null or deadline < cur.?) self.spaces[idx].loss_time_ns = deadline;
        return deadline;
    }
};

fn msToNs(ms: u64) u64 {
    return ms * std.time.ns_per_ms;
}
