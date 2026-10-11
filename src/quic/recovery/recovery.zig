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
const parallel = @import("parallel");

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

fn deadlineAfter(now_ns: u64, delta_ns: u64) u64 {
    return std.math.add(u64, now_ns, delta_ns) catch std.math.maxInt(u64);
}

fn mulSaturating(a: u64, b: u64) u64 {
    return std.math.mul(u64, a, b) catch std.math.maxInt(u64);
}

fn addSaturatingUsize(a: usize, b: usize) usize {
    return std.math.add(usize, a, b) catch std.math.maxInt(usize);
}

fn mulSaturatingUsize(a: usize, b: usize) usize {
    return std.math.mul(usize, a, b) catch std.math.maxInt(usize);
}

fn elapsedSince(now_ns: u64, then_ns: u64) u64 {
    return if (now_ns >= then_ns) now_ns - then_ns else 0;
}

/// Hard cap on sent_packets entries per space. If exceeded after compaction,
/// the oldest (lowest-index) entries are dropped to stay within budget.
///
/// Ring buffer migration is a future optimization; the current bounded
/// ArrayList with compaction is functionally correct.
const max_sent_packets: usize = 4096;
// CANARY: REQ=REQ-QUIC-HC-095; FEATURE="QUIC High-Concurrency Requests"; ASPECT=AckRecoveryParallelThreshold; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
// ACK processing runs on the endpoint receive path. Fork/join parallel loss
// detection at 64 packets made normal high-fanout short-header ACK bursts pay
// thread-pool scheduling overhead while stream readers were waiting for poll
// wakeups. Keep recovery sequential until the outstanding set is large enough
// to amortize dispatch.
const loss_detect_parallel_threshold: usize = 1024;

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
    fn enforceCapacity(self: *SpaceState, cc: *CcState) void {
        if (self.sent.items.len <= max_sent_packets) return;
        const excess = self.sent.items.len - max_sent_packets;
        // Remove index entries for dropped packets and adjust bytes_in_flight
        for (self.sent.items[0..excess]) |sp| {
            _ = self.sent_index.remove(sp.pn);
            // Subtract orphaned packet bytes from congestion accounting
            if (sp.ack_eliciting) {
                if (cc.bytes_in_flight >= sp.size) cc.bytes_in_flight -= sp.size else cc.bytes_in_flight = 0;
            }
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
///
/// Thread-safety model (#160 closure):
///   - Mutating operations (onPacketSent, onAckReceived, onLoss, reduceCwndEcn)
///     hold `mutex` for their full duration.
///   - The hot reader path (pacing delay computation) reads cwnd / bytes_in_flight
///     / smoothed_rtt via `cwndSnapshot()` / `bytesInFlightSnapshot()` /
///     `smoothedRttSnapshot()` — these load atomic mirror fields with
///     `.acquire` ordering and never block on the mutex.
///   - Mutators store to the atomic mirrors with `.release` ordering at the
///     end of every state transition, before releasing the mutex. This forms
///     a single-writer / many-reader pattern that is safe even though readers
///     do not synchronize with writers.
///   - Internal use under `mutex` continues to access `cc.cwnd` /
///     `cc.bytes_in_flight` / `rtt.smoothed_rtt_ns` directly; the atomic
///     mirrors are only for lock-free callers.
pub const Recovery = struct {
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex = std.Io.Mutex.init,
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

    // Lock-free reader mirrors (#160). Updated with .release ordering at the
    // tail of every mutating method while the mutex is still held.
    cwnd_atomic: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    bytes_in_flight_atomic: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    smoothed_rtt_atomic: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    mds_atomic: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    /// Initialize a Recovery instance with fresh per-space state.
    pub fn init(alloc: std.mem.Allocator) Recovery {
        var r: Recovery = .{ .allocator = alloc, .mutex = .init, .spaces = .{ SpaceState.init(alloc), SpaceState.init(alloc), SpaceState.init(alloc) } };
        // Seed atomic mirrors from initial CcState/RttState defaults so lock-free
        // readers get sane values before the first ACK lands.
        r.cwnd_atomic.store(r.cc.cwnd, .release);
        r.bytes_in_flight_atomic.store(r.cc.bytes_in_flight, .release);
        r.smoothed_rtt_atomic.store(r.rtt.smoothed_rtt_ns, .release);
        r.mds_atomic.store(r.cc.mds, .release);
        return r;
    }

    /// Free per-space arrays and internal allocations.
    pub fn deinit(self: *Recovery) void {
        inline for (&self.spaces) |*s| s.deinit();
    }

    /// RFC 9002 section 6.4: discarded packet protection keys make these
    /// packets impossible to acknowledge. Release their credit without
    /// treating the discard as an ACK or a congestion loss event.
    pub fn discardSpace(self: *Recovery, space: PacketNumberSpace) usize {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors();
        const state = &self.spaces[spaceIdx(space)];
        var released: usize = 0;
        for (state.sent.items) |sp| {
            if (sp.ack_eliciting and !sp.acked and !sp.declared_lost)
                released = addSaturatingUsize(released, sp.size);
        }
        self.cc.bytes_in_flight -|= released;
        state.sent.clearRetainingCapacity();
        state.sent_index.clearRetainingCapacity();
        state.largest_acked = null;
        state.loss_time_ns = null;
        state.ecn_last = .{ .ect0 = 0, .ect1 = 0, .ce = 0 };
        state.ecn_seen_any = false;
        self.pto_count = 0;
        return released;
    }

    fn spaceIdx(space: PacketNumberSpace) usize {
        return @intFromEnum(space);
    }

    /// Lock-free read of current congestion window. Acquire-loaded atomic
    /// mirror — safe to call from any thread. (#160 closure)
    pub fn cwndSnapshot(self: *const Recovery) usize {
        return self.cwnd_atomic.load(.acquire);
    }

    /// Lock-free read of current bytes_in_flight. Acquire-loaded atomic mirror.
    pub fn bytesInFlightSnapshot(self: *const Recovery) usize {
        return self.bytes_in_flight_atomic.load(.acquire);
    }

    /// Lock-free read of smoothed RTT (nanoseconds). Acquire-loaded atomic mirror.
    pub fn smoothedRttSnapshot(self: *const Recovery) u64 {
        return self.smoothed_rtt_atomic.load(.acquire);
    }

    /// Lock-free read of max datagram size. Acquire-loaded atomic mirror.
    pub fn mdsSnapshot(self: *const Recovery) usize {
        return self.mds_atomic.load(.acquire);
    }

    /// Refresh atomic mirrors from struct fields. Public so test code that
    /// directly mutates `cc.cwnd` / `cc.bytes_in_flight` / `rtt.smoothed_rtt_ns`
    /// (instead of going through a mutating method) can keep the lock-free
    /// reader path coherent.
    ///
    /// Production code does NOT need to call this directly — every mutating
    /// method ends with a refresh before releasing the mutex (see #160 closure).
    pub inline fn refreshAtomicMirrors(self: *Recovery) void {
        self.cwnd_atomic.store(self.cc.cwnd, .release);
        self.bytes_in_flight_atomic.store(self.cc.bytes_in_flight, .release);
        self.smoothed_rtt_atomic.store(self.rtt.smoothed_rtt_ns, .release);
        self.mds_atomic.store(self.cc.mds, .release);
    }

    /// Select congestion control mode (false = NewReno, true = CUBIC).
    pub fn setCcMode(self: *Recovery, cubic: bool) void {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
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
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        const idx = spaceIdx(space);

        // RFC 9002 §A.1 / §2: Only ack-eliciting packets are tracked for loss
        // recovery. Non-ack-eliciting (ACK-only) packets are never individually
        // acknowledged by the peer, are never retransmitted, and do not count
        // toward bytes_in_flight — so they can never become acked or
        // declared_lost. Appending them to `sent` made the list grow ~1 entry
        // per request on a long-lived connection (they only ever leave via the
        // 4096 hard cap), and every received ACK re-scans `sent` (unprocessed
        // count, loss detection, and the `sent_index` rebuild in compact()),
        // yielding O(n) per-ACK and O(n^2) cumulative cost. Tracking only
        // ack-eliciting packets keeps `sent` bounded by the in-flight window.
        if (ack_eliciting) {
            const alloc = self.spaces[idx].allocator;
            try self.spaces[idx].sent.append(alloc, .{ .pn = pn, .time_ns = now_ns, .size = bytes, .ack_eliciting = ack_eliciting });
            const sent_slot = self.spaces[idx].sent.items.len - 1;
            try self.spaces[idx].sent_index.put(pn, sent_slot);

            // Enforce hard capacity cap: compact first, then drop oldest if still over.
            if (self.spaces[idx].sent.items.len > max_sent_packets) {
                self.spaces[idx].compact();
                self.spaces[idx].enforceCapacity(&self.cc);
            }
        }

        const old_inflight = self.cc.bytes_in_flight;
        if (ack_eliciting) self.cc.bytes_in_flight = addSaturatingUsize(self.cc.bytes_in_flight, bytes);

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

        // Sending alone cannot establish loss. RFC 9002 section 6.1.2
        // requires a later packet ACK in this space; processAck sets the
        // time-loss deadline only for packets satisfying that condition.
    }

    /// Result of ACK/loss processing with aggregate counters.
    pub const AckResult = struct { bytes_acked: usize = 0, bytes_lost: usize = 0 };

    /// Handle ACK frames (no ECN) for a given space, update RTT/loss/cc, and return summary.
    pub fn onAckReceived(self: *Recovery, space: PacketNumberSpace, acked: []const u64, ack_delay_ns: u64, now_ns: u64) AckResult {
        return self.onAckReceivedWithEcn(space, acked, ack_delay_ns, now_ns, null);
    }

    /// Handle ACK frames for a given space with optional ECN counters.
    pub fn onAckReceivedWithEcn(self: *Recovery, space: PacketNumberSpace, acked: []const u64, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        return self.processAck(space, acked, ack_delay_ns, now_ns, ecn);
    }

    /// Large ACK ranges are matched against the bounded sent-packet set.
    /// Do not enumerate a peer-controlled numeric span or truncate its ACKs.
    pub fn onAckIntervalsReceivedWithEcn(self: *Recovery, space: PacketNumberSpace, acked: *const frame.AckIntervals, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        return self.processAck(space, acked, ack_delay_ns, now_ns, ecn);
    }

    fn processAck(self: *Recovery, space: PacketNumberSpace, acked: anytype, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        // Specialize the two representations at compile time so ordinary ACKs
        // keep the original direct-index loop without a per-packet option test.
        const use_intervals = @TypeOf(acked) == *const frame.AckIntervals;
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        const idx = spaceIdx(space);
        var sstate = &self.spaces[idx];
        var bytes_acked: usize = 0;
        var ack_eliciting_acked = false;
        var largest_pn = sstate.largest_acked;
        var largest_acked_pkt_time: ?u64 = null;

        // PHASE 42 PART 22: Log ACK reception
        const candidate_count = if (use_intervals) sstate.sent.items.len else acked.len;
        logger.debugPrint("[P42-22-ACK-RX] 📥 space={s} ack_candidate_count={d} prev_largest={d}\n", .{
            @tagName(space),
            candidate_count,
            sstate.largest_acked orelse 0,
        });

        // Mark acked packets using direct PN index lookups instead of nested scans.
        var candidate_index: usize = 0;
        while (candidate_index < candidate_count) : (candidate_index += 1) {
            const pn = if (use_intervals) sstate.sent.items[candidate_index].pn else acked[candidate_index];
            if (use_intervals) {
                if (!acked.contains(pn)) continue;
            }
            if (sstate.sent_index.get(pn)) |sent_slot| {
                if (sent_slot >= sstate.sent.items.len) {
                    _ = sstate.sent_index.remove(pn);
                    continue;
                }
                const sp = &sstate.sent.items[sent_slot];
                if (!sp.acked and !sp.declared_lost) {
                    sp.acked = true;
                    bytes_acked = addSaturatingUsize(bytes_acked, sp.size);
                    if (sp.ack_eliciting) ack_eliciting_acked = true;
                    if (largest_pn == null or pn > largest_pn.?) {
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
        sstate.largest_acked = largest_pn;

        // Loss detection: parallel scan for large windows (PAR-005), sequential for small.
        //
        // For very large unprocessed sent-packet windows, use thread-pool fork/join to mark packets as
        // lost in parallel (parallel.parallelLossDetect). Then a sequential cleanup
        // pass handles sent_index removal and detailed per-loss statistics/logging.
        // Below threshold, the original merged single-pass is used.
        var bytes_lost: usize = 0;
        var first_lost_time: ?u64 = null;
        var last_lost_time: ?u64 = null;
        var pkt_threshold_lost_count: usize = 0;
        var earliest_loss_time: ?u64 = null;
        var time_threshold_lost_count: usize = 0;
        const have_rtt = self.rtt.have_sample;
        const tt_base: u64 = if (have_rtt) @max(self.timer_granularity_ns, LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns)) else 0;

        // Count unprocessed packets to decide parallel vs sequential
        var unprocessed_count: usize = 0;
        for (sstate.sent.items) |sp| {
            if (!sp.acked and !sp.declared_lost) unprocessed_count += 1;
        }

        if (unprocessed_count >= loss_detect_parallel_threshold and sstate.largest_acked != null) {
            // Parallel path: build SentPacketInfo array, run parallel scan, then cleanup
            var par_infos: [4096]parallel.SentPacketInfo = undefined;
            const count = @min(sstate.sent.items.len, par_infos.len);
            for (sstate.sent.items[0..count], 0..) |sp, i| {
                par_infos[i] = .{
                    .packet_number = sp.pn,
                    .size = sp.size,
                    .time_sent_ns = sp.time_ns,
                    .ack_eliciting = sp.ack_eliciting,
                    .declared_lost = sp.acked or sp.declared_lost, // pre-mark acked as "already handled"
                };
            }

            // Run parallel loss detection (marks declared_lost in par_infos)
            const par_result = parallel.parallelLossDetect(
                par_infos[0..count],
                sstate.largest_acked.?,
                self.loss.packet_threshold,
                tt_base,
                now_ns,
            );
            _ = par_result; // aggregate counts are recomputed below for accurate per-type stats

            // Map parallel results back and do sequential cleanup (index removal, stats, logging)
            for (sstate.sent.items[0..count], 0..) |*sp, i| {
                if (sp.acked or sp.declared_lost) continue;
                if (!par_infos[i].declared_lost) {
                    // Not marked lost by parallel scan — check earliest_loss_time for timer
                    if (have_rtt and sp.ack_eliciting and sp.pn < sstate.largest_acked.?) {
                        const deadline = deadlineAfter(sp.time_ns, tt_base);
                        if (now_ns < deadline) {
                            if (earliest_loss_time == null or deadline < earliest_loss_time.?) {
                                earliest_loss_time = deadline;
                            }
                        }
                    }
                    continue;
                }

                // Packet was marked lost by parallel scan — determine loss type for stats
                const pkt_lost = self.loss.isPacketThresholdLost(sstate.largest_acked.?, sp.pn);
                const time_lost = !pkt_lost; // if parallel marked it and not pkt_lost, must be time_lost

                sp.declared_lost = true;
                _ = sstate.sent_index.remove(sp.pn);
                bytes_lost = addSaturatingUsize(bytes_lost, sp.size);
                if (pkt_lost) pkt_threshold_lost_count += 1;
                if (time_lost) time_threshold_lost_count += 1;
                if (first_lost_time == null or sp.time_ns < first_lost_time.?) first_lost_time = sp.time_ns;
                if (last_lost_time == null or sp.time_ns > last_lost_time.?) last_lost_time = sp.time_ns;

                if (pkt_lost) {
                    logger.debugPrint("[P42-22-LOSS-PKT] space={s} pn={d} largest_acked={d} gap={d} threshold={d} bytes={d}\n", .{
                        @tagName(space),                                                                              sp.pn,                      sstate.largest_acked orelse 0,
                        if ((sstate.largest_acked orelse 0) >= sp.pn) (sstate.largest_acked orelse 0) - sp.pn else 0, self.loss.packet_threshold, sp.size,
                    });
                }
                if (time_lost) {
                    const age_us = elapsedSince(now_ns, sp.time_ns) / 1000;
                    logger.debugPrint("[P42-22-LOSS-TIME] space={s} pn={d} age={d}us threshold={d}us bytes={d}\n", .{
                        @tagName(space), sp.pn, age_us, tt_base / 1000, sp.size,
                    });
                }
            }
        } else {
            // Sequential path: original merged single-pass for small windows
            for (sstate.sent.items) |*sp| {
                if (sp.acked or sp.declared_lost) continue;
                // Age is not evidence of loss until a later packet in this
                // same number space has been acknowledged (RFC 9002 A.10).
                if (sstate.largest_acked == null or sp.pn > sstate.largest_acked.?) continue;

                const pkt_lost = if (sstate.largest_acked) |la| self.loss.isPacketThresholdLost(la, sp.pn) else false;

                var time_lost = false;
                if (have_rtt and sp.ack_eliciting) {
                    const deadline = deadlineAfter(sp.time_ns, tt_base);
                    if (now_ns >= deadline) {
                        time_lost = true;
                    } else if (earliest_loss_time == null or deadline < earliest_loss_time.?) {
                        earliest_loss_time = deadline;
                    }
                }

                if (pkt_lost or time_lost) {
                    sp.declared_lost = true;
                    _ = sstate.sent_index.remove(sp.pn);
                    bytes_lost = addSaturatingUsize(bytes_lost, sp.size);
                    if (pkt_lost) pkt_threshold_lost_count += 1;
                    if (time_lost) time_threshold_lost_count += 1;
                    if (first_lost_time == null or sp.time_ns < first_lost_time.?) first_lost_time = sp.time_ns;
                    if (last_lost_time == null or sp.time_ns > last_lost_time.?) last_lost_time = sp.time_ns;

                    if (pkt_lost) {
                        logger.debugPrint("[P42-22-LOSS-PKT] space={s} pn={d} largest_acked={d} gap={d} threshold={d} bytes={d}\n", .{
                            @tagName(space),                                                                              sp.pn,                      sstate.largest_acked orelse 0,
                            if ((sstate.largest_acked orelse 0) >= sp.pn) (sstate.largest_acked orelse 0) - sp.pn else 0, self.loss.packet_threshold, sp.size,
                        });
                    }
                    if (time_lost) {
                        const age_us = elapsedSince(now_ns, sp.time_ns) / 1000;
                        logger.debugPrint("[P42-22-LOSS-TIME] space={s} pn={d} age={d}us threshold={d}us bytes={d}\n", .{
                            @tagName(space), sp.pn, age_us, tt_base / 1000, sp.size,
                        });
                    }
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
                const pc_period = mulSaturating(pto_base, @intCast(self.k_pc_threshold));
                if (elapsedSince(last_lost_time.?, first_lost_time.?) >= pc_period) {
                    const min_window: usize = mulSaturatingUsize(2, self.cc.mds);
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
            self.cc.cwnd = addSaturatingUsize(self.cc.cwnd, bytes_acked);
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
                const inc = mulSaturatingUsize(mds, bytes_acked) / @max(self.cc.cwnd, @as(usize, 1));
                if (inc > 0) {
                    self.cc.cwnd = addSaturatingUsize(self.cc.cwnd, inc);
                }
            }
        } else {
            // NewReno congestion avoidance: cwnd += mds * bytes_acked / cwnd
            const inc = mulSaturatingUsize(self.cc.mds, bytes_acked) / @max(self.cc.cwnd, @as(usize, 1));
            self.cc.cwnd = addSaturatingUsize(self.cc.cwnd, inc);
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
        const min_wnd: usize = mulSaturatingUsize(2, self.cc.mds);

        if (self.use_cubic) {
            // CUBIC: save W_max and apply beta=0.7
            self.cubic_w_max = self.cc.cwnd;
            self.cc.cwnd = @max(mulSaturatingUsize(self.cc.cwnd, 7) / 10, min_wnd);
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
        const min_wnd: usize = mulSaturatingUsize(2, self.cc.mds);
        if (self.use_cubic) {
            // CUBIC: save W_max and apply beta=0.7
            self.cubic_w_max = self.cc.cwnd;
            self.cc.cwnd = @max(mulSaturatingUsize(self.cc.cwnd, 7) / 10, min_wnd);
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
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        var total_lost: usize = 0;
        var first_lost_time: ?u64 = null;
        var last_lost_time: ?u64 = null;
        inline for (&self.spaces) |*sstate| {
            if (sstate.loss_time_ns) |lt| {
                if (now_ns >= lt) {
                    // Re-run time-threshold pass for this space
                    const tt_base = @max(self.timer_granularity_ns, LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns));
                    var next_loss: ?u64 = null;
                    for (sstate.sent.items) |*sp| {
                        if (!sp.acked and !sp.declared_lost and sp.ack_eliciting and
                            sstate.largest_acked != null and sp.pn < sstate.largest_acked.?)
                        {
                            const deadline = deadlineAfter(sp.time_ns, tt_base);
                            if (now_ns >= deadline) {
                                sp.declared_lost = true;
                                _ = sstate.sent_index.remove(sp.pn);
                                total_lost = addSaturatingUsize(total_lost, sp.size);
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
                const pc_period = mulSaturating(pto_base, @intCast(self.k_pc_threshold));
                if (elapsedSince(last_lost_time.?, first_lost_time.?) >= pc_period) {
                    const min_window: usize = mulSaturatingUsize(2, self.cc.mds);
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
        const deadline = deadlineAfter(now_ns, base);

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
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        const idx = spaceIdx(space);
        var any_in_flight = false;
        for (self.spaces[idx].sent.items) |sp| {
            if (sp.ack_eliciting and !sp.acked and !sp.declared_lost) {
                any_in_flight = true;
                break;
            }
        }
        if (!any_in_flight) {
            return null;
        }
        const pto = self.rtt.computePtoNsWithBackoff(self.pto_count, self.timer_granularity_ns);
        const deadline = deadlineAfter(now_ns, pto);
        // A PTO is a probe deadline, never evidence that an unacknowledged
        // packet is lost. Keep it separate from the ACK-driven loss timer.
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
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

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
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.cc.bytes_in_flight;
    }

    /// Get current congestion window (thread-safe).
    pub fn getCwnd(self: *Recovery) usize {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.cc.cwnd;
    }

    /// Get maximum datagram size (thread-safe).
    pub fn getMds(self: *Recovery) usize {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.cc.mds;
    }

    /// Set maximum datagram size (thread-safe).
    pub fn setMds(self: *Recovery, mds: usize) void {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        self.cc.mds = mds;
    }

    pub fn setInitialCongestionWindowPackets(self: *Recovery, packets: u16) void {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors();
        // CANARY: REQ=REQ-QUIC-HC-088; FEATURE="QUIC High-Concurrency Requests"; ASPECT=ConfigurableInitialCwnd; STATUS=IMPL; TEST=test_quic_condition_timedwait_cadence; OWNER=transport; UPDATED=2026-05-27
        const clamped_packets: usize = @max(@as(usize, packets), 2);
        self.cc.cwnd = mulSaturatingUsize(self.cc.mds, clamped_packets);
        self.cc.ssthresh = std.math.maxInt(usize) / 2;
    }

    /// Get bytes in flight and cwnd atomically (thread-safe).
    pub fn getCongestionState(self: *Recovery) struct { bytes_in_flight: usize, cwnd: usize } {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return .{ .bytes_in_flight = self.cc.bytes_in_flight, .cwnd = self.cc.cwnd };
    }

    /// Number of entries currently retained in the per-space `sent` list.
    /// Exposed so callers/tests can assert the loss-recovery tracking set stays
    /// bounded by the in-flight window (RFC 9002 §A.1) rather than growing with
    /// the connection's total sent history.
    pub fn sentLen(self: *Recovery, space: PacketNumberSpace) usize {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.spaces[spaceIdx(space)].sent.items.len;
    }
};

fn msToNs(ms: u64) u64 {
    return ms * std.time.ns_per_ms;
}

// =============================================================================
// Tests: #160 closure -- atomic snapshot mirrors stay coherent with mutating ops
// =============================================================================

test "recovery: atomic mirrors track cc.cwnd and bytes_in_flight after onPacketSent" {
    var rec = Recovery.init(std.testing.allocator);
    defer rec.deinit();

    rec.cc.cwnd = 14_000;
    rec.cc.mds = 1200;
    rec.refreshAtomicMirrors();

    try std.testing.expectEqual(@as(usize, 14_000), rec.cwndSnapshot());
    try std.testing.expectEqual(@as(usize, 0), rec.bytesInFlightSnapshot());

    try rec.onPacketSent(.Application, 1, 1200, true, 0);
    try std.testing.expectEqual(@as(usize, 1200), rec.bytesInFlightSnapshot());

    try rec.onPacketSent(.Application, 2, 1200, true, 0);
    try std.testing.expectEqual(@as(usize, 2400), rec.bytesInFlightSnapshot());

    // cwnd should not have changed (no ACK / loss path); mirror reflects
    // current cc.cwnd.
    try std.testing.expectEqual(@as(usize, 14_000), rec.cwndSnapshot());
}

test "recovery: smoothedRttSnapshot reflects rtt updates" {
    var rec = Recovery.init(std.testing.allocator);
    defer rec.deinit();

    try std.testing.expectEqual(@as(u64, 0), rec.smoothedRttSnapshot());

    rec.rtt.smoothed_rtt_ns = 25 * std.time.ns_per_ms;
    rec.refreshAtomicMirrors();
    try std.testing.expectEqual(@as(u64, 25 * std.time.ns_per_ms), rec.smoothedRttSnapshot());
}

test "recovery: mds snapshot updates via setMds" {
    var rec = Recovery.init(std.testing.allocator);
    defer rec.deinit();

    rec.setMds(1300);
    try std.testing.expectEqual(@as(usize, 1300), rec.mdsSnapshot());

    rec.setMds(1452);
    try std.testing.expectEqual(@as(usize, 1452), rec.mdsSnapshot());
}

test "recovery: high packet counters saturate instead of overflowing" {
    var rec = Recovery.init(std.testing.allocator);
    defer rec.deinit();

    try rec.onPacketSent(.Application, 1, std.math.maxInt(usize) - 4, true, std.math.maxInt(u64) - 32);
    try rec.onPacketSent(.Application, 2, 16, true, std.math.maxInt(u64) - 16);
    try std.testing.expectEqual(std.math.maxInt(usize), rec.bytesInFlightSnapshot());

    const pto_opt = rec.computeNextPtoTimeNs(std.math.maxInt(u64) - 1);
    try std.testing.expect(pto_opt != null);
    const pto = pto_opt.?;
    try std.testing.expectEqual(std.math.maxInt(u64), pto);

    const app_pto_opt = rec.computeSpacePtoTimeNs(.Application, std.math.maxInt(u64) - 1);
    try std.testing.expect(app_pto_opt != null);
    const app_pto = app_pto_opt.?;
    try std.testing.expectEqual(std.math.maxInt(u64), app_pto);
}
