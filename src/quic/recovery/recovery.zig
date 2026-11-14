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

/// Hard cap on sent_packets entries per space. Past it the oldest entries
/// are dropped (see SpaceState.enforceCapacity).
const max_sent_packets: usize = 4096;
/// Capacity enforcement drops down to this many entries, so the O(n) shift
/// runs once per (max - low water) recorded packets instead of on every
/// packet once the cap is reached (SONNY-6434).
const sent_packets_low_water: usize = max_sent_packets - max_sent_packets / 8;
// CANARY: REQ=REQ-QUIC-HC-095; FEATURE="QUIC High-Concurrency Requests"; ASPECT=AckRecoveryParallelThreshold; STATUS=IMPL; OWNER=transport; UPDATED=2026-05-27
// ACK processing runs on the endpoint receive path. Fork/join parallel loss
// detection at 64 packets made normal high-fanout short-header ACK bursts pay
// thread-pool scheduling overhead while stream readers were waiting for poll
// wakeups. Keep recovery sequential until the outstanding set is large enough
// to amortize dispatch.
const loss_detect_parallel_threshold: usize = 1024;

// Internal space state tracking
const SpaceState = struct {
    /// Tracked packets sorted by ascending packet number; duplicates keep
    /// insertion order. Lookups are binary searches (SONNY-6434: the former
    /// pn -> slot hash index was rebuilt in full by every compaction, i.e.
    /// on every ACK and, at the cap, on every recorded packet).
    sent: std.ArrayList(SentPacket),
    allocator: std.mem.Allocator,
    largest_acked: ?u64 = null,
    loss_time_ns: ?u64 = null,
    /// Send time of the most recent ack-eliciting packet in this space
    /// (RFC 9002 Appendix A.3 time_of_last_ack_eliciting_packet), the base
    /// of the PTO deadline.
    last_ack_eliciting_sent_ns: ?u64 = null,
    /// Keys for this space were discarded (see Recovery.discardSpace).
    discarded: bool = false,
    // Last observed ECN counters from peer's ACK_ECN for this space
    ecn_last: frame.EcnCounts = .{ .ect0 = 0, .ect1 = 0, .ce = 0 },
    ecn_seen_any: bool = false,
    /// True while every packet was recorded with a larger packet number and
    /// a send time no earlier than the one before it, as a connection
    /// records them. Packet-threshold losses (pn far enough below the
    /// largest acked) and time-threshold losses (sent long enough ago) are
    /// then both prefixes of `sent`, so loss detection walks only the lost
    /// prefix. Cleared for good by any out-of-order record, after which the
    /// full scans run.
    in_send_order: bool = true,
    /// Diagnostic counter (SONNY-6434): sent-packet entries examined one by
    /// one by ACK marking, loss detection, compaction and capacity
    /// enforcement. Bulk moves are not counted.
    entries_visited: u64 = 0,
    /// Diagnostic counter (SONNY-6434 follow-up): binary-search probes made
    /// by packet-number lookups.
    search_probes: u64 = 0,

    fn init(alloc: std.mem.Allocator) SpaceState {
        return .{
            .sent = std.ArrayList(SentPacket).empty,
            .allocator = alloc,
        };
    }
    fn deinit(self: *SpaceState) void {
        self.sent.deinit(self.allocator);
    }

    /// Index of the first entry whose packet number is >= `pn`.
    fn lowerBound(self: *SpaceState, pn: u64) usize {
        const items = self.sent.items;
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            self.search_probes +%= 1;
            const mid = lo + (hi - lo) / 2;
            if (items[mid].pn < pn) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Index of the first entry whose packet number is > `pn`.
    fn upperBound(self: *SpaceState, pn: u64) usize {
        const items = self.sent.items;
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            self.search_probes +%= 1;
            const mid = lo + (hi - lo) / 2;
            if (items[mid].pn <= pn) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Slot of the most recently recorded entry for `pn`, if tracked,
    /// checking `hint` and its neighbours before searching. ACK frames list
    /// packet numbers in runs, so passing the previous hit makes marking a
    /// run O(1) per packet, as the former hash index was.
    fn findNear(self: *SpaceState, pn: u64, hint: usize) ?usize {
        const items = self.sent.items;
        if (hint < items.len) {
            // Next slot first (ascending runs), then previous (descending
            // runs, e.g. enumerated from the largest), then the hint itself.
            const candidates = [_]?usize{
                if (hint + 1 < items.len) hint + 1 else null,
                if (hint > 0) hint - 1 else null,
                hint,
            };
            for (candidates) |c| {
                const i = c orelse continue;
                self.search_probes +%= 1;
                if (items[i].pn != pn) continue;
                // Duplicates keep insertion order; the newest is the last.
                if (i + 1 < items.len and items[i + 1].pn == pn) break;
                return i;
            }
        }
        return self.find(pn);
    }

    /// Slot of the most recently recorded entry for `pn`, if tracked.
    fn find(self: *SpaceState, pn: u64) ?usize {
        const i = self.upperBound(pn);
        if (i == 0 or self.sent.items[i - 1].pn != pn) return null;
        return i - 1;
    }

    /// Record `sp`, keeping `sent` sorted. A connection records packet
    /// numbers in increasing order, so this is an append.
    fn record(self: *SpaceState, sp: SentPacket) !void {
        const items = self.sent.items;
        if (!sp.ack_eliciting) self.in_send_order = false;
        if (items.len == 0 or sp.pn > items[items.len - 1].pn) {
            if (items.len > 0 and sp.time_ns < items[items.len - 1].time_ns) self.in_send_order = false;
            try self.sent.append(self.allocator, sp);
        } else {
            self.in_send_order = false;
            try self.sent.insert(self.allocator, self.upperBound(sp.pn), sp);
        }
    }

    /// Remove acked/declared_lost entries from `sent`.
    fn compact(self: *SpaceState) void {
        self.compactHead(self.sent.items.len);
    }

    /// Remove acked/declared_lost entries among the first `head_len`
    /// entries, the only ones an ACK or loss pass touched, and shift the
    /// rest down in one move.
    fn compactHead(self: *SpaceState, head_len: usize) void {
        const items = self.sent.items;
        var write_idx: usize = 0;
        for (items[0..head_len]) |sp| {
            self.entries_visited +%= 1;
            if (!sp.acked and !sp.declared_lost) {
                items[write_idx] = sp;
                write_idx += 1;
            }
        }
        if (write_idx == head_len) return;
        const tail_len = items.len - head_len;
        @memmove(items[write_idx..][0..tail_len], items[head_len..]);
        self.sent.items.len = write_idx + tail_len;
    }

    /// Enforce the hard capacity cap by dropping the oldest entries, down to
    /// `sent_packets_low_water` so the shift is amortized. A dropped packet
    /// leaves bytes_in_flight and is no longer tracked here; its stream data
    /// is not lost: the connection keeps every STREAM frame until an ACK
    /// range covers it or retransmits it once a later packet is acknowledged
    /// (or on PTO), independently of this tracking.
    fn enforceCapacity(self: *SpaceState, cc: *CcState) void {
        if (self.sent.items.len <= max_sent_packets) return;
        const excess = self.sent.items.len - sent_packets_low_water;
        for (self.sent.items[0..excess]) |sp| {
            self.entries_visited +%= 1;
            if (sp.ack_eliciting) {
                if (cc.bytes_in_flight >= sp.size) cc.bytes_in_flight -= sp.size else cc.bytes_in_flight = 0;
            }
        }
        @memmove(self.sent.items[0..sent_packets_low_water], self.sent.items[excess..]);
        self.sent.items.len = sent_packets_low_water;
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
    /// Diagnostic counter (SONNY-6434): cumulative sent-packet entries
    /// examined by getPacketDeliveryState(). Guarded by `mutex`.
    delivery_lookup_entries_visited: u64 = 0,

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
        // A discarded space's keys are gone; nothing sent in it can count.
        if (self.spaces[idx].discarded) return;

        // RFC 9002 §A.1 / §2: Only ack-eliciting packets are tracked for loss
        // recovery. Non-ack-eliciting (ACK-only) packets are never individually
        // acknowledged by the peer, are never retransmitted, and do not count
        // toward bytes_in_flight — so they can never become acked or
        // declared_lost. Appending them to `sent` made the list grow ~1 entry
        // per request on a long-lived connection (they only ever leave via the
        // 4096 hard cap), and every received ACK re-scans `sent` (unprocessed
        // count, loss detection, and compaction), yielding O(n) per-ACK and
        // O(n^2) cumulative cost. Tracking only ack-eliciting packets keeps
        // `sent` bounded by the in-flight window.
        if (ack_eliciting) {
            self.spaces[idx].last_ack_eliciting_sent_ns = now_ns;
            try self.spaces[idx].record(.{ .pn = pn, .time_ns = now_ns, .size = bytes, .ack_eliciting = ack_eliciting });
            // Hard capacity cap. ACK and loss processing compact acked and
            // lost entries away before returning, so every entry here is
            // still in flight: drop the oldest (amortized, see
            // enforceCapacity) without rescanning.
            self.spaces[idx].enforceCapacity(&self.cc);
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

        // Schedule time-threshold loss if we have an RTT sample; do not promote here.
        if (ack_eliciting and self.rtt.have_sample) {
            const tt_base = LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns);
            const deadline = deadlineAfter(now_ns, tt_base);
            const cur = self.spaces[idx].loss_time_ns;
            if (cur == null or deadline < cur.?) self.spaces[idx].loss_time_ns = deadline;
        }
    }

    /// Result of ACK/loss processing with aggregate counters.
    pub const AckResult = struct { bytes_acked: usize = 0, bytes_lost: usize = 0 };

    /// Inclusive packet-number interval acknowledged by one ACK range
    /// (RFC 9000 §19.3.1).
    pub const AckedRange = struct { lo: u64, hi: u64 };

    /// Packets newly acknowledged by one ACK frame, accumulated while marking.
    const AckMark = struct {
        bytes_acked: usize = 0,
        ack_eliciting_acked: bool = false,
        /// Largest acknowledged packet number plus one; 0 while there is
        /// none (from an earlier ACK or marked here). Packet 0 alone used to
        /// leave the largest acknowledged unset (SONNY-6454). Packet numbers
        /// stay below 2^62, so the +1 cannot overflow.
        largest_plus1: u64,
        largest_acked_pkt_time: ?u64 = null,
        /// Slot of the previous packet-number-list hit (see findNear).
        hint: usize = std.math.maxInt(usize),

        fn init(largest_acked: ?u64) AckMark {
            return .{ .largest_plus1 = if (largest_acked) |la| la + 1 else 0 };
        }

        fn add(self: *AckMark, sp: *SentPacket) void {
            if (sp.acked or sp.declared_lost) return;
            sp.acked = true;
            self.bytes_acked = addSaturatingUsize(self.bytes_acked, sp.size);
            if (sp.ack_eliciting) self.ack_eliciting_acked = true;
            if (sp.pn >= self.largest_plus1) {
                self.largest_plus1 = sp.pn + 1;
                self.largest_acked_pkt_time = sp.time_ns;
            }
        }
    };

    /// Mark the tracked packet `pn` acknowledged.
    fn markAckedPn(sstate: *SpaceState, pn: u64, mark: *AckMark) void {
        const sent_slot = sstate.findNear(pn, mark.hint) orelse return;
        mark.hint = sent_slot;
        sstate.entries_visited +%= 1;
        mark.add(&sstate.sent.items[sent_slot]);
    }

    /// Handle ACK frames (no ECN) for a given space, update RTT/loss/cc, and return summary.
    pub fn onAckReceived(self: *Recovery, space: PacketNumberSpace, acked: []const u64, ack_delay_ns: u64, now_ns: u64) AckResult {
        return self.onAckReceivedWithEcn(space, acked, ack_delay_ns, now_ns, null);
    }

    /// Handle ACK frames for a given space with optional ECN counters.
    /// `acked` enumerates acknowledged packet numbers; prefer
    /// onAckRangesReceivedWithEcn(), which takes the ACK frame's ranges and
    /// so is not bounded by how many packet numbers a caller enumerates.
    pub fn onAckReceivedWithEcn(self: *Recovery, space: PacketNumberSpace, acked: []const u64, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        const sstate = &self.spaces[spaceIdx(space)];
        var mark = AckMark.init(sstate.largest_acked);
        for (acked) |pn| markAckedPn(sstate, pn, &mark);
        return self.finishAckLocked(space, &mark, ack_delay_ns, now_ns, ecn);
    }

    /// Handle an ACK frame given as inclusive packet-number ranges, sorted
    /// by descending packet number (ACK frame order, RFC 9000 §19.3.1).
    /// Every tracked packet in any range is acknowledged, however many
    /// packet numbers the ranges span: each range is located by binary
    /// search and only the tracked packets inside it are visited, so
    /// marking costs O(ranges * log tracked + newly acknowledged).
    pub fn onAckRangesReceivedWithEcn(self: *Recovery, space: PacketNumberSpace, ranges: []const AckedRange, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        const sstate = &self.spaces[spaceIdx(space)];
        var mark = AckMark.init(sstate.largest_acked);
        for (ranges) |r| {
            if (r.hi < r.lo) continue;
            var i = sstate.lowerBound(r.lo);
            while (i < sstate.sent.items.len and sstate.sent.items[i].pn <= r.hi) : (i += 1) {
                sstate.entries_visited +%= 1;
                mark.add(&sstate.sent.items[i]);
            }
        }
        return self.finishAckLocked(space, &mark, ack_delay_ns, now_ns, ecn);
    }

    /// RTT update, loss detection and congestion control for one ACK frame
    /// whose newly acknowledged packets are summarized in `mark`. Caller
    /// holds `mutex`.
    fn finishAckLocked(self: *Recovery, space: PacketNumberSpace, mark: *const AckMark, ack_delay_ns: u64, now_ns: u64, ecn: ?frame.EcnCounts) AckResult {
        var sstate = &self.spaces[spaceIdx(space)];
        const bytes_acked = mark.bytes_acked;
        const ack_eliciting_acked = mark.ack_eliciting_acked;
        const largest_pn = mark.largest_plus1 -| 1;
        const largest_acked_pkt_time = mark.largest_acked_pkt_time;

        // PHASE 42 PART 22: Log ACK reception
        logger.debugPrint("[P42-22-ACK-RX] 📥 space={s} acked_bytes={d} prev_largest={d}\n", .{
            @tagName(space),
            bytes_acked,
            sstate.largest_acked orelse 0,
        });

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
        const prev_largest_acked = sstate.largest_acked;
        if (mark.largest_plus1 != 0) sstate.largest_acked = largest_pn;

        // Loss detection: parallel scan for large windows (PAR-005), sequential for small.
        //
        // For very large unprocessed sent-packet windows, use thread-pool fork/join to mark packets as
        // lost in parallel (parallel.parallelLossDetect). Then a sequential cleanup
        // pass handles detailed per-loss statistics/logging.
        // Below threshold, the original merged single-pass is used.
        var bytes_lost: usize = 0;
        var first_lost_time: ?u64 = null;
        var last_lost_time: ?u64 = null;
        var pkt_threshold_lost_count: usize = 0;
        var earliest_loss_time: ?u64 = null;
        var time_threshold_lost_count: usize = 0;
        const have_rtt = self.rtt.have_sample;
        const tt_base: u64 = if (have_rtt) LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns) else 0;

        // Entries compaction must examine; the full scans below may touch any.
        var compact_len: usize = sstate.sent.items.len;

        // Count unprocessed packets to decide parallel vs sequential
        var unprocessed_count: usize = 0;
        if (sstate.in_send_order) {
            // Packets recorded in send order (SONNY-6434): packet-threshold
            // losses (RFC 9002 §6.1.1, pn order) and time-threshold losses
            // (§6.1.2, send-time order) are both prefixes of `sent`, so the
            // walk stops at the first in-flight packet that is neither. That
            // packet's time-threshold deadline is the next loss time: the
            // earliest over packets not declared lost (Appendix A.10). The
            // packets declared lost equal those of the full scans below, at
            // O(lost + acked below them) instead of O(tracked).
            // Loop invariants, held in registers: the stores to
            // `declared_lost` below could otherwise force reloads.
            const la: u64 = sstate.largest_acked orelse 0;
            const have_la = sstate.largest_acked != null;
            const items = sstate.sent.items;
            var visited: u64 = 0;
            defer sstate.entries_visited +%= visited;
            var i: usize = 0;
            while (i < items.len) : (i += 1) {
                const sp = &items[i];
                visited += 1;
                if (sp.acked or sp.declared_lost) continue;
                // RFC 9002 §6.1: only a packet sent before an acknowledged
                // one can be lost, so the walk ends at the largest
                // acknowledged; packets above it are left to the PTO.
                if (!have_la or sp.pn > la) break;
                const pkt_lost = self.loss.isPacketThresholdLost(la, sp.pn);
                var time_lost = false;
                var deadline: ?u64 = null;
                if (have_rtt and sp.ack_eliciting) {
                    const d = deadlineAfter(sp.time_ns, tt_base);
                    if (now_ns >= d) time_lost = true else deadline = d;
                }
                if (!pkt_lost and !time_lost) {
                    earliest_loss_time = deadline;
                    break;
                }

                sp.declared_lost = true;
                bytes_lost = addSaturatingUsize(bytes_lost, sp.size);
                if (pkt_lost) pkt_threshold_lost_count += 1;
                if (time_lost) time_threshold_lost_count += 1;
                // Send order: send times do not decrease along the walk.
                if (first_lost_time == null) first_lost_time = sp.time_ns;
                last_lost_time = sp.time_ns;
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
            // Newly acknowledged packets all lie at or below the largest
            // acknowledged; lost ones end at the walk's stop.
            const acked_end = if (have_la) sstate.upperBound(la) else 0;
            compact_len = @max(i, acked_end);
        } else for (sstate.sent.items) |sp| {
            sstate.entries_visited +%= 1;
            if (!sp.acked and !sp.declared_lost) unprocessed_count += 1;
        }

        if (sstate.in_send_order) {
            // Handled above.
        } else if (unprocessed_count >= loss_detect_parallel_threshold and sstate.largest_acked != null) {
            // Parallel path: build SentPacketInfo array, run parallel scan, then cleanup
            var par_infos: [4096]parallel.SentPacketInfo = undefined;
            const count = @min(sstate.sent.items.len, par_infos.len);
            sstate.entries_visited +%= 2 * @as(u64, count); // copy-out + parallel scan
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
                sstate.entries_visited +%= 1;
                if (sp.acked or sp.declared_lost) continue;
                if (!par_infos[i].declared_lost) {
                    // Not marked lost by parallel scan — check earliest_loss_time for timer
                    // (only packets below the largest acknowledged, RFC 9002 §6.1).
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
                sstate.entries_visited +%= 1;
                if (sp.acked or sp.declared_lost) continue;
                // RFC 9002 §6.1: only packets sent before an acknowledged one.
                const la = sstate.largest_acked orelse continue;
                if (sp.pn > la) continue;

                const pkt_lost = self.loss.isPacketThresholdLost(la, sp.pn);

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

        // RFC 9002 §7.6.2, decided before compaction drops the acknowledged
        // and lost entries it needs. A qualifying run lies within the span
        // of all packets lost here, so the run check (a second walk over
        // the touched head) runs only when that span is long enough, which
        // keeps it off the per-ACK path.
        const persistent = bytes_lost > 0 and lostSpanReaches(self, first_lost_time, last_lost_time) and
            self.persistentCongestion(sstate, compact_len, prev_largest_acked);

        // Compact: remove fully-processed entries (acked or declared_lost)
        sstate.compactHead(compact_len);

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
            if (persistent) {
                const min_window: usize = mulSaturatingUsize(2, self.cc.mds);
                self.cc.cwnd = min_window;
                self.cc.ssthresh = min_window;
            }
        }
        if (ack_eliciting_acked) self.pto_count = 0;

        return .{ .bytes_acked = bytes_acked, .bytes_lost = bytes_lost };
    }

    /// RFC 9002 §7.6.2 for the packets one ACK declared lost: two lost
    /// ack-eliciting packets sent at least the persistent-congestion period
    /// apart, with no packet sent between them acknowledged. The first
    /// `head_len` entries hold everything the ACK touched, in packet-number
    /// (= send) order, still flagged. A packet acknowledged by this ACK
    /// breaks a run. Only packets above the largest acknowledged before this
    /// ACK qualify: an earlier acknowledgement can only cover lower packet
    /// numbers and is no longer visible here (SONNY-6454: the span used to be
    /// taken over every lost packet, across acknowledged ones).
    fn lostSpanReaches(self: *Recovery, first_lost: ?u64, last_lost: ?u64) bool {
        const first = first_lost orelse return false;
        const last = last_lost orelse return false;
        const pc_period = mulSaturating(self.rtt.computePtoNsWithBackoff(0, self.timer_granularity_ns), @intCast(self.k_pc_threshold));
        return elapsedSince(last, first) >= pc_period;
    }

    fn persistentCongestion(self: *Recovery, sstate: *SpaceState, head_len: usize, prev_largest_acked: ?u64) bool {
        const pc_period = mulSaturating(self.rtt.computePtoNsWithBackoff(0, self.timer_granularity_ns), @intCast(self.k_pc_threshold));
        var run_start_ns: ?u64 = null;
        for (sstate.sent.items[0..head_len]) |sp| {
            sstate.entries_visited +%= 1;
            if (sp.acked) {
                run_start_ns = null;
                continue;
            }
            // Still in flight: not acknowledged, so it does not break a run.
            if (!sp.declared_lost) continue;
            if (prev_largest_acked) |prev| {
                if (sp.pn <= prev) {
                    run_start_ns = null;
                    continue;
                }
            }
            const start = run_start_ns orelse blk: {
                run_start_ns = sp.time_ns;
                break :blk sp.time_ns;
            };
            if (elapsedSince(sp.time_ns, start) >= pc_period) return true;
        }
        return false;
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
                    const tt_base = LossDetector.timeThresholdNs(self.rtt.smoothed_rtt_ns, self.rtt.latest_rtt_ns);
                    var next_loss: ?u64 = null;
                    // In send order (SONNY-6434) the expired packets are a
                    // prefix and the first unexpired one holds the next
                    // deadline, so the scan stops there.
                    var scanned: usize = 0;
                    // RFC 9002 §6.1: only packets sent before an
                    // acknowledged one can be declared lost.
                    const la: u64 = sstate.largest_acked orelse 0;
                    const have_la = sstate.largest_acked != null;
                    for (sstate.sent.items) |*sp| {
                        sstate.entries_visited +%= 1;
                        scanned += 1;
                        if (!have_la or sp.pn > la) {
                            if (sstate.in_send_order) break;
                            continue;
                        }
                        if (!sp.acked and !sp.declared_lost and sp.ack_eliciting) {
                            const deadline = deadlineAfter(sp.time_ns, tt_base);
                            if (now_ns < deadline and sstate.in_send_order) {
                                next_loss = deadline;
                                break;
                            }
                            if (now_ns >= deadline) {
                                sp.declared_lost = true;
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
                    sstate.compactHead(scanned);
                }
            }
        }
        if (total_lost > 0) {
            // No persistent congestion from the timer: the packets
            // acknowledged between the lost ones were compacted away by
            // earlier ACKs, so RFC 9002 §7.6.2 cannot be verified here.
            self.ccOnLoss(total_lost, last_lost_time, now_ns);
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
            self.spaces[idx].loss_time_ns = null;
            return null;
        }
        const pto = self.rtt.computePtoNsWithBackoff(self.pto_count, self.timer_granularity_ns);
        const deadline = deadlineAfter(now_ns, pto);
        const cur = self.spaces[idx].loss_time_ns;
        if (cur == null or deadline < cur.?) self.spaces[idx].loss_time_ns = deadline;
        return deadline;
    }

    /// RFC 9002 §6.4 / Appendix A.11 (OnPacketNumberSpaceDiscarded): the
    /// keys for the Initial or Handshake space are gone (RFC 9001 §4.9), so
    /// its packets can never be acknowledged or resent. Remove them from
    /// bytes_in_flight, forget them and reset the PTO backoff. Only the
    /// first call for a space has an effect.
    pub fn discardSpace(self: *Recovery, space: PacketNumberSpace) void {
        std.debug.assert(space != .Application);
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        defer self.refreshAtomicMirrors(); // runs before unlock (LIFO defer)
        const sstate = &self.spaces[spaceIdx(space)];
        if (sstate.discarded) return;
        sstate.discarded = true;
        for (sstate.sent.items) |sp| {
            if (!sp.ack_eliciting or sp.acked or sp.declared_lost) continue;
            self.cc.bytes_in_flight -|= sp.size;
        }
        sstate.sent.clearRetainingCapacity();
        sstate.loss_time_ns = null;
        sstate.last_ack_eliciting_sent_ns = null;
        self.pto_count = 0;
    }

    /// RFC 9002 §6.2.1 / Appendix A.8 PTO deadline for `space`: the send
    /// time of the most recent ack-eliciting packet plus the PTO period with
    /// exponential backoff. Null when no ack-eliciting packet is in flight,
    /// in which case the PTO timer must not be set.
    pub fn ptoDeadlineNs(self: *Recovery, space: PacketNumberSpace) ?u64 {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        const sstate = &self.spaces[spaceIdx(space)];
        var any_in_flight = false;
        for (sstate.sent.items) |sp| {
            if (sp.ack_eliciting and !sp.acked and !sp.declared_lost) {
                any_in_flight = true;
                break;
            }
        }
        if (!any_in_flight) return null;
        const base = sstate.last_ack_eliciting_sent_ns orelse return null;
        return deadlineAfter(base, self.rtt.computePtoNsWithBackoff(self.pto_count, self.timer_granularity_ns));
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

        // `sent` is sorted by packet number: a binary search finds the
        // packet or proves it untracked (SONNY-6434: the former linear
        // fallback ran on every ACK for every retransmission entry).
        const sent_slot = sstate.find(pn) orelse return .unknown;
        self.delivery_lookup_entries_visited +%= 1;
        const sp = sstate.sent.items[sent_slot];
        if (sp.acked) return .acked;
        if (sp.declared_lost) return .lost;
        return .in_flight;
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

    /// Cumulative sent-packet entries visited by ACK marking, loss detection,
    /// compaction and capacity enforcement in `space` (SONNY-6434
    /// diagnostic; lets tests bound amortized recovery work per packet).
    pub fn searchProbes(self: *Recovery, space: PacketNumberSpace) u64 {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.spaces[spaceIdx(space)].search_probes;
    }

    /// Cumulative sent-packet entries visited by ACK marking, loss detection,
    /// compaction and capacity enforcement in `space` (SONNY-6434
    /// diagnostic; lets tests bound amortized recovery work per packet).
    pub fn entriesVisited(self: *Recovery, space: PacketNumberSpace) u64 {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.spaces[spaceIdx(space)].entries_visited;
    }

    /// Cumulative sent-packet entries examined by getPacketDeliveryState()
    /// (SONNY-6434 diagnostic; lets tests bound per-ACK lookup work).
    pub fn deliveryLookupEntriesVisited(self: *Recovery) u64 {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
        return self.delivery_lookup_entries_visited;
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
