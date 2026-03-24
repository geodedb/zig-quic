// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC recovery coordinator module.
//!
//! This module provides the modular recovery API by combining specialized
//! recovery modules and implementing the main Recovery struct.
//!
//! RFC 9002: QUIC Loss Detection and Congestion Control

const std = @import("std");
const logger = @import("quic_logger");
const frame = @import("quic_frame");

// Import recovery submodules
pub const types = @import("types");
pub const rtt_mod = @import("rtt.zig");
pub const loss_detection = @import("loss_detection.zig");
pub const congestion = @import("congestion.zig");

// Re-export types from submodules
pub const CcState = types.CcState;
pub const CUBIC_C_DEFAULT = types.CUBIC_C_DEFAULT;
pub const CUBIC_BETA_DEFAULT = types.CUBIC_BETA_DEFAULT;
pub const PacketNumberSpace = types.PacketNumberSpace;
pub const SentPacket = types.SentPacket;

pub const RttState = rtt_mod.RttState;

pub const LossDetector = loss_detection.LossDetector;
pub const isAckElicitingFrame = loss_detection.isAckElicitingFrame;

pub const NewReno = congestion.NewReno;
pub const Cubic = congestion.Cubic;
pub const computePacingDelayNs = congestion.computePacingDelayNs;

/// Hard cap on sent_packets entries per space. If exceeded after compaction,
/// the oldest (lowest-index) entries are dropped to stay within budget.
///
/// Ring buffer migration is a future optimization; the current bounded
/// ArrayList with compaction is functionally correct.
const max_sent_packets: usize = 4096;

// Internal space state tracking
const SpaceState = struct {
    sent: std.ArrayList(SentPacket),
    sent_index: std.AutoHashMap(u64, usize),
    allocator: std.mem.Allocator,
    largest_acked: ?u64 = null,
    loss_time_ns: ?u64 = null,
    // Last observed ECN counters from peer's ACK_ECN for this space
    ecn_last: frame.EcnCounts = .{ .ect0 = 0, .ect1 = 0, .ce = 0 },
    ecn_seen_any: bool = false,

    fn init(alloc: std.mem.Allocator) SpaceState {
        return .{
            .sent = std.ArrayList(SentPacket).empty,
            .sent_index = std.AutoHashMap(u64, usize).init(alloc),
            .allocator = alloc,
        };
    }
    fn deinit(self: *SpaceState) void {
        self.sent_index.deinit();
        self.sent.deinit(self.allocator);
    }

    /// Remove acked/declared_lost entries from sent and rebuild sent_index.
    fn compact(self: *SpaceState) void {
        var write_idx: usize = 0;
        for (self.sent.items) |sp| {
            if (!sp.acked and !sp.declared_lost) {
                self.sent.items[write_idx] = sp;
                write_idx += 1;
            }
        }
        self.sent.items.len = write_idx;
        // Rebuild sent_index after compaction
        self.sent_index.clearRetainingCapacity();
        for (self.sent.items, 0..) |sp, i| {
            self.sent_index.put(sp.pn, i) catch |err| {
                logger.err("sent_index rebuild put failed (OOM): {s}", .{@errorName(err)});
            };
        }
    }

    /// Enforce hard capacity cap by dropping oldest entries when over limit.
    fn enforceCapacity(self: *SpaceState) void {
        if (self.sent.items.len <= max_sent_packets) return;
        const excess = self.sent.items.len - max_sent_packets;
        // Remove index entries for dropped packets
        for (self.sent.items[0..excess]) |sp| {
            _ = self.sent_index.remove(sp.pn);
        }
        // Shift remaining entries forward
        std.mem.copyForwards(
            SentPacket,
            self.sent.items[0..max_sent_packets],
            self.sent.items[excess..],
        );
        self.sent.items.len = max_sent_packets;
        // Rebuild index with corrected positions
        self.sent_index.clearRetainingCapacity();
        for (self.sent.items, 0..) |sp, i| {
            self.sent_index.put(sp.pn, i) catch |err| {
                logger.err("sent_index rebuild put failed (OOM): {s}", .{@errorName(err)});
            };
        }
    }
};

/// Recovery state: RTT, loss detection, PTO backoff, and CC (NewReno or CUBIC)
/// Thread-safe: all public methods are protected by an internal mutex.
pub const Recovery = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    rtt: RttState = .{},
    cc: CcState = .{},
    use_cubic: bool = false,
    // CUBIC state (RFC 8312, bytes-based)
    /// W_max: cwnd (bytes) at last loss event.
    cubic_w_max: usize = 0,
    /// Nanosecond timestamp when the current CUBIC epoch started.
    cubic_epoch_start_ns: ?u64 = null,
    /// Precomputed K value (seconds) for the current epoch.
    cubic_k: f64 = 0.0,
    /// TCP-friendliness estimate W_est (bytes).
    cubic_w_est: usize = 0,

    loss: LossDetector = .{},
    pto_count: u32 = 0,
    timer_granularity_ns: u64 = std.time.ns_per_ms,
    spaces: [3]SpaceState,
    k_pc_threshold: u32 = 3,
    /// RFC 9002 S7.3.2: start of the current congestion recovery period (sent_time of trigger).
    /// cwnd is only reduced once per recovery period.
    congestion_recovery_start_time: ?u64 = null,

    /// Initialize a Recovery instance with fresh per-space state.
    pub fn init(alloc: std.mem.Allocator) Recovery {
        return .{ .allocator = alloc, .mutex = .{}, .spaces = .{ SpaceState.init(alloc), SpaceState.init(alloc), SpaceState.init(alloc) } };
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
        self.mutex.lock();
        defer self.mutex.unlock();
        self.use_cubic = cubic;
        if (cubic) {
            // Initialize CUBIC state: W_max starts at current cwnd
            self.cubic_w_max = self.cc.cwnd;
            self.cubic_k = 0.0;
            self.cubic_epoch_start_ns = null;
            self.cubic_w_est = 0;
        }
    }

    /// Record a packet as sent in the given space.
    pub fn onPacketSent(self: *Recovery, space: PacketNumberSpace, pn: u64, bytes: usize, ack_eliciting: bool, now_ns: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = spaceIdx(space);
        const alloc = self.spaces[idx].allocator;
        try self.spaces[idx].sent.append(alloc, .{ .pn = pn, .time_ns = now_ns, .size = bytes, .ack_eliciting = ack_eliciting });
        const sent_slot = self.spaces[idx].sent.items.len - 1;
        try self.spaces[idx].sent_index.put(pn, sent_slot);

        // Enforce hard capacity cap: compact first, then drop oldest if still over.
        if (self.spaces[idx].sent.items.len > max_sent_packets) {
            self.spaces[idx].compact();
            self.spaces[idx].enforceCapacity();
        }

        const old_inflight = self.cc.bytes_in_flight;
        if (ack_eliciting) self.cc.bytes_in_flight += bytes;

        // PHASE 50: Always log to see if function is called
        logger.debugPrint("[PHASE50-CC] onPacketSent: space={s} pn={d} bytes={d} ack_eliciting={} inflight: {d}→{d} cwnd={d}\n", .{
            @tagName(space),
            pn,
            bytes,
            ack_eliciting,
            old_inflight,
            self.cc.bytes_in_flight,
            self.cc.cwnd,
        });

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
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = spaceIdx(space);
        var sstate = &self.spaces[idx];
        var bytes_acked: usize = 0;
        var ack_eliciting_acked = false;
        var largest_pn: u64 = sstate.largest_acked orelse 0;
        var largest_acked_pkt_time: ?u64 = null;

        // PHASE 42 PART 22: Log ACK reception
        logger.debugPrint("[P42-22-ACK-RX] 📥 space={s} acked_count={d} prev_largest={d}\n", .{
            @tagName(space),
            acked.len,
            sstate.largest_acked orelse 0,
        });

        // Mark acked packets using direct PN index lookups instead of nested scans.
        for (acked) |pn| {
            if (sstate.sent_index.get(pn)) |sent_slot| {
                if (sent_slot >= sstate.sent.items.len) {
                    _ = sstate.sent_index.remove(pn);
                    continue;
                }
                const sp = &sstate.sent.items[sent_slot];
                if (!sp.acked and !sp.declared_lost) {
                    sp.acked = true;
                    bytes_acked += sp.size;
                    if (sp.ack_eliciting) ack_eliciting_acked = true;
                    if (pn > largest_pn) {
                        largest_pn = pn;
                        largest_acked_pkt_time = sp.time_ns;
                    }
                }
                _ = sstate.sent_index.remove(pn);
            }
        }
        if (largest_acked_pkt_time) |t_ack| {
            const measured = if (now_ns > t_ack) now_ns - t_ack else 0;
            const old_smoothed = self.rtt.smoothed_rtt_ns;
            const old_rttvar = self.rtt.rttvar_ns;
            self.rtt.onAck(measured, ack_delay_ns);

            // PHASE 42 PART 22: Log RTT update
            logger.debugPrint("[P42-22-RTT] 🕐 measured={d}us old_smoothed={d}us new_smoothed={d}us old_rttvar={d}us new_rttvar={d}us\n", .{
                measured / 1000,
                old_smoothed / 1000,
                self.rtt.smoothed_rtt_ns / 1000,
                old_rttvar / 1000,
                self.rtt.rttvar_ns / 1000,
            });
        }
        if (largest_pn != (sstate.largest_acked orelse 0)) sstate.largest_acked = largest_pn;

        // Loss detection: merged packet-threshold and time-threshold in a single pass
        var bytes_lost: usize = 0;
        var first_lost_time: ?u64 = null;
        var last_lost_time: ?u64 = null;
        var pkt_threshold_lost_count: usize = 0;
        var earliest_loss_time: ?u64 = null;
        var time_threshold_lost_count: usize = 0;
        const have_rtt = self.rtt.have_sample;
        const tt_base: u64 = if (have_rtt) LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns) else 0;
        for (sstate.sent.items) |*sp| {
            if (sp.acked or sp.declared_lost) continue;

            // Packet-threshold loss (applies to all packets)
            const pkt_lost = if (sstate.largest_acked) |la| self.loss.isPacketThresholdLost(la, sp.pn) else false;

            // Time-threshold loss (applies only to ack-eliciting packets)
            var time_lost = false;
            if (have_rtt and sp.ack_eliciting) {
                const deadline = sp.time_ns + tt_base;
                if (now_ns >= deadline) {
                    time_lost = true;
                } else if (earliest_loss_time == null or deadline < earliest_loss_time.?) {
                    earliest_loss_time = deadline;
                }
            }

            if (pkt_lost or time_lost) {
                sp.declared_lost = true;
                _ = sstate.sent_index.remove(sp.pn);
                bytes_lost += sp.size;
                if (pkt_lost) pkt_threshold_lost_count += 1;
                if (time_lost) time_threshold_lost_count += 1;
                if (first_lost_time == null or sp.time_ns < first_lost_time.?) first_lost_time = sp.time_ns;
                if (last_lost_time == null or sp.time_ns > last_lost_time.?) last_lost_time = sp.time_ns;

                if (pkt_lost) {
                    // PHASE 42 PART 22: Log packet-threshold loss
                    logger.debugPrint("[P42-22-LOSS-PKT] ❌ space={s} pn={d} largest_acked={d} gap={d} threshold={d} bytes={d}\n", .{
                        @tagName(space),
                        sp.pn,
                        sstate.largest_acked orelse 0,
                        (sstate.largest_acked orelse 0) - sp.pn,
                        self.loss.packet_threshold,
                        sp.size,
                    });
                }
                if (time_lost) {
                    const age_us = (now_ns - sp.time_ns) / 1000;
                    // PHASE 42 PART 22: Log time-threshold loss
                    logger.debugPrint("[P42-22-LOSS-TIME] ⏱️  space={s} pn={d} age={d}us threshold={d}us bytes={d}\n", .{
                        @tagName(space),
                        sp.pn,
                        age_us,
                        tt_base / 1000,
                        sp.size,
                    });
                }
            }
        }
        sstate.loss_time_ns = earliest_loss_time;

        // PHASE 42 PART 22: Summarize loss detection for this ACK
        if (bytes_lost > 0) {
            logger.debugPrint("[P42-22-LOSS-SUM] 📊 space={s} total_lost={d}B pkt_thresh={d} time_thresh={d}\n", .{
                @tagName(space),
                bytes_lost,
                pkt_threshold_lost_count,
                time_threshold_lost_count,
            });
        }

        // Compact: remove fully-processed entries (acked or declared_lost)
        sstate.compact();

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
            self.ccOnLoss(bytes_lost, last_lost_time, now_ns);
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

    /// Increase cwnd on ACK; uses CUBIC (RFC 8312) when enabled, otherwise NewReno.
    fn ccOnAck(self: *Recovery, bytes_acked: usize, now_ns: u64) void {
        if (bytes_acked == 0) return;

        const old_cwnd = self.cc.cwnd;
        const old_inflight = self.cc.bytes_in_flight;

        if (self.cc.bytes_in_flight >= bytes_acked) self.cc.bytes_in_flight -= bytes_acked else self.cc.bytes_in_flight = 0;

        if (self.cc.cwnd < self.cc.ssthresh) {
            // Slow start: cwnd grows by bytes_acked (same for both NewReno and CUBIC)
            self.cc.cwnd += bytes_acked;
        } else if (self.use_cubic) {
            // CUBIC congestion avoidance (RFC 8312)
            const mds = self.cc.mds;
            if (mds == 0) return;

            // Initialize epoch on first ACK after loss
            if (self.cubic_epoch_start_ns == null) {
                self.cubic_epoch_start_ns = now_ns;
                if (self.cubic_w_max == 0) {
                    self.cubic_w_max = self.cc.cwnd;
                }
                self.cubic_k = Cubic.computeK(self.cubic_w_max, mds);
                self.cubic_w_est = self.cc.cwnd;
            }

            const epoch_start = self.cubic_epoch_start_ns.?;
            const elapsed_ns: u64 = if (now_ns > epoch_start) now_ns - epoch_start else 0;
            const t_sec: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));

            // W_cubic(t)
            const w_cubic = Cubic.wCubicBytes(t_sec, self.cubic_k, self.cubic_w_max, mds);

            // W_est for TCP-friendliness
            const rtt_ns = self.rtt.smoothed_rtt_ns;
            const rtt_sec: f64 = @as(f64, @floatFromInt(rtt_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
            const w_est_val = Cubic.computeWEst(t_sec, rtt_sec, self.cubic_w_max, mds);

            const target = @max(w_cubic, w_est_val);

            if (target > self.cc.cwnd) {
                self.cc.cwnd = target;
            } else {
                // Minimal growth: at least NewReno-equivalent
                const inc = (mds * bytes_acked) / @max(self.cc.cwnd, @as(usize, 1));
                if (inc > 0) {
                    self.cc.cwnd += inc;
                }
            }
        } else {
            // NewReno congestion avoidance: cwnd += mds * bytes_acked / cwnd
            const inc = (self.cc.mds * bytes_acked) / @max(self.cc.cwnd, @as(usize, 1));
            self.cc.cwnd += inc;
        }

        // Enhanced CC logging
        logger.debugPrint("[PHASE49-CC] ACK: acked={d}B cwnd: {d}->{d} inflight: {d}->{d} ssthresh={d} mode={s} available={d}B\n", .{
            bytes_acked,
            old_cwnd,
            self.cc.cwnd,
            old_inflight,
            self.cc.bytes_in_flight,
            self.cc.ssthresh,
            if (old_cwnd < self.cc.ssthresh) "slow_start" else if (self.use_cubic) "cubic" else "cong_avoid",
            if (self.cc.cwnd > self.cc.bytes_in_flight) self.cc.cwnd - self.cc.bytes_in_flight else 0,
        });
    }

    /// Reduce cwnd on loss; uses CUBIC beta=0.7 when enabled, otherwise NewReno beta=0.5.
    /// RFC 9002 S7.3.2: cwnd is only reduced once per congestion recovery period.
    /// `last_lost_sent_time` is the sent timestamp of the most recently sent lost packet.
    /// `now_ns` is the current time used to start a new recovery period.
    fn ccOnLoss(self: *Recovery, bytes_lost: usize, last_lost_sent_time: ?u64, now_ns: u64) void {
        if (bytes_lost == 0) return;

        // Always account for lost bytes leaving the network
        if (self.cc.bytes_in_flight >= bytes_lost) self.cc.bytes_in_flight -= bytes_lost else self.cc.bytes_in_flight = 0;

        // RFC 9002 S7.3.2: skip cwnd reduction if the lost packet was sent
        // before the current recovery period started (already in recovery).
        if (last_lost_sent_time) |sent_time| {
            if (self.congestion_recovery_start_time) |start| {
                if (sent_time <= start) {
                    logger.debugPrint("[CC-LOSS] skip cwnd reduction: sent_time={d}ns <= recovery_start={d}ns\n", .{
                        sent_time,
                        start,
                    });
                    return;
                }
            }
        }

        // Start a new recovery period
        self.congestion_recovery_start_time = now_ns;

        const old_cwnd = self.cc.cwnd;
        const min_wnd: usize = 2 * self.cc.mds;

        if (self.use_cubic) {
            // CUBIC: save W_max and apply beta=0.7
            self.cubic_w_max = self.cc.cwnd;
            self.cc.cwnd = @max(self.cc.cwnd * 7 / 10, min_wnd);
            self.cc.ssthresh = self.cc.cwnd;
            // Reset epoch for next CUBIC curve
            self.cubic_epoch_start_ns = null;
            self.cubic_k = 0.0;
            self.cubic_w_est = 0;
        } else {
            // NewReno: beta=0.5
            self.cc.cwnd = @max(self.cc.cwnd / 2, min_wnd);
            self.cc.ssthresh = self.cc.cwnd;
        }

        // Log congestion control loss reaction
        logger.debugPrint("[CC-LOSS] lost={d}B cwnd: {d}->{d} inflight={d} ssthresh={d} recovery_start={d}ns cubic={}\n", .{
            bytes_lost,
            old_cwnd,
            self.cc.cwnd,
            self.cc.bytes_in_flight,
            self.cc.ssthresh,
            now_ns,
            self.use_cubic,
        });
    }

    /// React to ECN-CE by reducing cwnd like a loss event (without changing bytes_in_flight).
    fn ccOnEcn(self: *Recovery) void {
        const min_wnd: usize = 2 * self.cc.mds;
        if (self.use_cubic) {
            // CUBIC: save W_max and apply beta=0.7
            self.cubic_w_max = self.cc.cwnd;
            self.cc.cwnd = @max(self.cc.cwnd * 7 / 10, min_wnd);
            self.cc.ssthresh = self.cc.cwnd;
            self.cubic_epoch_start_ns = null;
            self.cubic_k = 0.0;
            self.cubic_w_est = 0;
        } else {
            self.cc.cwnd = @max(self.cc.cwnd / 2, min_wnd);
            self.cc.ssthresh = self.cc.cwnd;
        }
    }

    /// Recompute loss detection timeouts and declare any time-threshold losses.
    pub fn onLossTimeExpired(self: *Recovery, now_ns: u64) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
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
                                _ = sstate.sent_index.remove(sp.pn);
                                total_lost += sp.size;
                                if (first_lost_time == null or sp.time_ns < first_lost_time.?) first_lost_time = sp.time_ns;
                                if (last_lost_time == null or sp.time_ns > last_lost_time.?) last_lost_time = sp.time_ns;
                            } else if (next_loss == null or deadline < next_loss.?) {
                                next_loss = deadline;
                            }
                        }
                    }
                    sstate.loss_time_ns = next_loss;
                    // Compact declared_lost entries so sent list doesn't grow unbounded
                    sstate.compact();
                }
            }
        }
        if (total_lost > 0) {
            self.ccOnLoss(total_lost, last_lost_time, now_ns);
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
        const deadline = now_ns + base;

        // PHASE 42 PART 22: Log PTO calculation
        logger.debugPrint("[P42-22-PTO-CALC] ⏰ pto_count={d} base={d}us deadline_from_now={d}us smoothed_rtt={d}us\n", .{
            self.pto_count,
            base / 1000,
            (deadline - now_ns) / 1000,
            self.rtt.smoothed_rtt_ns / 1000,
        });

        return deadline;
    }

    /// Compute next PTO deadline for a given space relative to now.
    pub fn computeSpacePtoTimeNs(self: *Recovery, space: PacketNumberSpace, now_ns: u64) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = spaceIdx(space);
        const pto = self.rtt.computePtoNs();
        const deadline = now_ns + pto;
        const cur = self.spaces[idx].loss_time_ns;
        if (cur == null or deadline < cur.?) self.spaces[idx].loss_time_ns = deadline;
        return deadline;
    }

    pub const PacketDeliveryState = enum {
        unknown,
        in_flight,
        acked,
        lost,
    };

    /// Return delivery state for a tracked packet number in the specified space.
    pub fn getPacketDeliveryState(self: *Recovery, space: PacketNumberSpace, pn: u64) PacketDeliveryState {
        self.mutex.lock();
        defer self.mutex.unlock();

        const idx = spaceIdx(space);
        const sstate = &self.spaces[idx];

        if (sstate.sent_index.get(pn)) |sent_slot| {
            if (sent_slot < sstate.sent.items.len) {
                const sp = sstate.sent.items[sent_slot];
                if (sp.acked) return .acked;
                if (sp.declared_lost) return .lost;
                return .in_flight;
            }
        }

        for (sstate.sent.items) |sp| {
            if (sp.pn != pn) continue;
            if (sp.acked) return .acked;
            if (sp.declared_lost) return .lost;
            return .in_flight;
        }

        return .unknown;
    }

    // Thread-safe accessors for congestion control state

    /// Get current bytes in flight (thread-safe).
    pub fn getBytesInFlight(self: *Recovery) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.cc.bytes_in_flight;
    }

    /// Get current congestion window (thread-safe).
    pub fn getCwnd(self: *Recovery) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.cc.cwnd;
    }

    /// Get maximum datagram size (thread-safe).
    pub fn getMds(self: *Recovery) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.cc.mds;
    }

    /// Set maximum datagram size (thread-safe).
    pub fn setMds(self: *Recovery, mds: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.cc.mds = mds;
    }

    /// Get bytes in flight and cwnd atomically (thread-safe).
    pub fn getCongestionState(self: *Recovery) struct { bytes_in_flight: usize, cwnd: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .bytes_in_flight = self.cc.bytes_in_flight, .cwnd = self.cc.cwnd };
    }
};

fn msToNs(ms: u64) u64 {
    return ms * std.time.ns_per_ms;
}
