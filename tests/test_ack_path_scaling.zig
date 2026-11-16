// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros

//! SONNY-6434: ACK processing must not scale with the number of packets the
//! connection has sent. A bulk server->client transfer (a remote geode backup
//! of more than ~11 MB) stalled because every app-space ACK walked the whole
//! STREAM retransmission map and, for each entry recovery no longer tracked,
//! linearly scanned every sent packet. These tests drive real Connection and
//! Recovery code with an in-memory peer that drops, reorders and delays
//! packets and ACKs, and bound the work each ACK does.

const std = @import("std");
const compat = @import("compat");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");
const frame = @import("quic_frame");
const recovery = @import("quic_recovery");

const app_keys: packet.AeadKeys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

/// Fixed allowance on top of the newly acknowledged packets for the work one
/// ACK may do: a handful of retransmissions plus constant bookkeeping. It
/// must not depend on how many packets are in flight or have been sent.
const per_ack_work_slack: u64 = 64;

/// Mirrors the recovery module's hard cap on tracked packets per space.
const max_tracked_packets: usize = 4096;

/// Amortized bound on recovery's per-entry work: each packet is recorded,
/// acknowledged or declared lost, and compacted away a constant number of
/// times, plus a constant per ACK. Work proportional to the packets in
/// flight on every send or ACK exceeds it by orders of magnitude.
fn recoveryWorkBound(packets: u64, acks: u64) u64 {
    return 16 * packets + 16 * acks;
}

fn initConn(conn: *conn_mod.Connection, allocator: *std.mem.Allocator) void {
    conn.init(allocator, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    conn.app_tx_keys = app_keys;
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_max_data = 1 << 40;
    conn.peer_max_stream_data = 1 << 40;
}

const CountingSender = struct {
    sends: usize = 0,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) anyerror!usize {
        const self: *CountingSender = @ptrCast(@alignCast(ctx));
        self.sends += 1;
        return bytes.len;
    }
};

/// Work counters the ACK path reports; the delta across one ACK is the work
/// that ACK did.
fn ackWork(conn: *conn_mod.Connection) u64 {
    return conn.ack_retx_entries_visited + conn.rec.deliveryLookupEntriesVisited();
}

/// Received packet-number ranges, ascending and non-overlapping, as a
/// receiver keeps them to build ACK frames (RFC 9000 §13.2.3).
const RxRanges = struct {
    const Range = struct { lo: u64, hi: u64 };
    items: std.ArrayList(Range) = .empty,

    fn deinit(self: *RxRanges, alloc: std.mem.Allocator) void {
        self.items.deinit(alloc);
    }

    /// Record `pn`; returns false if it was already received.
    fn insert(self: *RxRanges, alloc: std.mem.Allocator, pn: u64) !bool {
        const xs = self.items.items;
        // First range whose hi >= pn (ranges are few; scan from the newest).
        var i: usize = xs.len;
        while (i > 0 and xs[i - 1].hi >= pn) i -= 1;
        if (i < xs.len and xs[i].lo <= pn) return false;
        const joins_prev = i > 0 and xs[i - 1].hi + 1 == pn;
        const joins_next = i < xs.len and xs[i].lo == pn + 1;
        if (joins_prev and joins_next) {
            xs[i - 1].hi = xs[i].hi;
            _ = self.items.orderedRemove(i);
        } else if (joins_prev) {
            xs[i - 1].hi = pn;
        } else if (joins_next) {
            xs[i].lo = pn;
        } else {
            try self.items.insert(alloc, i, .{ .lo = pn, .hi = pn });
        }
        return true;
    }

    const Ack = struct {
        largest: u64,
        first_range: u64,
        ranges: [64]conn_mod.AckRange = undefined,
        ranges_len: usize = 0,
    };

    /// ACK frame for the newest ranges (at most 1 + 64, as a receiver bounds
    /// the ranges it reports).
    fn ack(self: *const RxRanges) ?Ack {
        const xs = self.items.items;
        if (xs.len == 0) return null;
        const newest = xs[xs.len - 1];
        var out: Ack = .{ .largest = newest.hi, .first_range = newest.hi - newest.lo };
        var prev_lo = newest.lo;
        var i: usize = xs.len - 1;
        while (i > 0 and out.ranges_len < out.ranges.len) {
            i -= 1;
            const r = xs[i];
            out.ranges[out.ranges_len] = .{ .gap = prev_lo - r.hi - 2, .len = r.hi - r.lo };
            out.ranges_len += 1;
            prev_lo = r.lo;
        }
        return out;
    }
};

/// Deliver an ACK to the connection and assert the work it did is bounded by
/// the packets it newly acknowledged plus a constant.
fn deliverAck(conn: *conn_mod.Connection, a: RxRanges.Ack, newly_acked: u64, max_work: *u64) !void {
    const before = ackWork(conn);
    conn.onAckReceivedSpace(.Application, a.largest, a.first_range, a.ranges[0..a.ranges_len], null);
    const work = ackWork(conn) - before;
    if (work > max_work.*) max_work.* = work;
    if (work > newly_acked + per_ack_work_slack) {
        std.debug.print(
            "SONNY-6434: ACK largest={} newly_acked={} did {} units of work (tracked STREAM packets={}, recovery sent={})\n",
            .{ a.largest, newly_acked, work, conn.app_stream_retx.count(), conn.rec.sentLen(.Application) },
        );
        return error.AckWorkNotBounded;
    }
}

test "SONNY-6434 one ACK frame acknowledging more than 256 packets acknowledges all of them" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    initConn(&conn, &allocator);
    defer conn.deinit();
    var sender: CountingSender = .{};
    conn.setSender(&sender, CountingSender.send);

    const packets: u64 = 1000;
    var i: u64 = 0;
    while (i < packets) : (i += 1) {
        try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "DATA", false));
    }
    const in_flight = conn.rec.getBytesInFlight();
    const cwnd_before = conn.rec.getCwnd();
    try std.testing.expect(in_flight > 0);

    // One contiguous range [0, 999]: every packet was delivered.
    conn.onAckReceivedSpace(.Application, packets - 1, packets - 1, &.{}, null);

    // RFC 9002 §7.3.1 (slow start): every acknowledged byte grows cwnd, and
    // no packet may be declared lost (§6.1) when all of them were acked.
    try std.testing.expectEqual(@as(?u64, null), conn.rec.congestion_recovery_start_time);
    try std.testing.expectEqual(cwnd_before + in_flight, conn.rec.getCwnd());
    try std.testing.expectEqual(@as(usize, 0), conn.rec.getBytesInFlight());
    try std.testing.expectEqual(@as(usize, 0), conn.rec.sentLen(.Application));
    try std.testing.expectEqual(@as(usize, 0), conn.app_stream_retx.count());
    try std.testing.expectEqual(packets, conn.pn_app_tx); // nothing retransmitted
}

test "SONNY-6434 delivery-state lookup does not scan sent packets" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    initConn(&conn, &allocator);
    defer conn.deinit();
    var sender: CountingSender = .{};
    conn.setSender(&sender, CountingSender.send);

    var i: u64 = 0;
    while (i < 3000) : (i += 1) _ = try conn.writeStream(0, "DATA", false);
    try std.testing.expectEqual(@as(usize, 3000), conn.rec.sentLen(.Application));

    const before = conn.rec.deliveryLookupEntriesVisited();
    try std.testing.expectEqual(.in_flight, conn.rec.getPacketDeliveryState(.Application, 1234));
    // A packet number recovery does not track (never sent, or already acked
    // or declared lost and compacted away) must be answered without a scan.
    try std.testing.expectEqual(.unknown, conn.rec.getPacketDeliveryState(.Application, 1_000_000));
    try std.testing.expect(conn.rec.deliveryLookupEntriesVisited() - before <= 2);
}

// Past the 4096-packet tracking cap recovery stops tracking the oldest
// packets. Their STREAM data must stay recoverable: a lost one is
// retransmitted, delivered ones are released by ACK ranges, and the
// connection must not treat the untracked ones as a congestion event.
test "SONNY-6434 packets past the recovery tracking cap are acked and retransmitted with bounded work" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    initConn(&conn, &allocator);
    defer conn.deinit();
    var sender: CountingSender = .{};
    conn.setSender(&sender, CountingSender.send);

    const packets: u64 = 5000;
    const lost_pn: u64 = 100;
    var i: u64 = 0;
    while (i < packets) : (i += 1) {
        try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "DATA", false));
    }
    try std.testing.expect(conn.rec.sentLen(.Application) <= max_tracked_packets);
    try std.testing.expectEqual(@as(usize, packets), conn.app_stream_retx.count());

    // The peer receives everything except lost_pn and acknowledges in order,
    // one ACK per 32 packets.
    var rx: RxRanges = .{};
    defer rx.deinit(allocator);
    var max_work: u64 = 0;
    var since_ack: u64 = 0;
    var acks: u64 = 0;
    var pn: u64 = 0;
    while (pn < packets) : (pn += 1) {
        if (pn != lost_pn) {
            _ = try rx.insert(allocator, pn);
            since_ack += 1;
        }
        if (since_ack == 32 or pn == packets - 1) {
            try deliverAck(&conn, rx.ack().?, since_ack, &max_work);
            acks += 1;
            since_ack = 0;
        }
    }

    // Exactly the lost packet's data is left, retransmitted under a new PN.
    try std.testing.expectEqual(@as(usize, 1), conn.app_stream_retx.count());
    try std.testing.expect(!conn.app_stream_retx.contains(lost_pn));
    try std.testing.expectEqual(packets + 1, conn.pn_app_tx);
    const retx = conn.app_stream_retx.get(packets).?;
    try std.testing.expectEqual(lost_pn * 4, retx.offset);

    _ = try rx.insert(allocator, packets);
    try deliverAck(&conn, rx.ack().?, 1, &max_work);
    try std.testing.expectEqual(@as(usize, 0), conn.app_stream_retx.count());
    try std.testing.expectEqual(@as(usize, 0), conn.rec.sentLen(.Application));
    try std.testing.expectEqual(@as(usize, 0), conn.rec.getBytesInFlight());
    // Every tracked packet was acknowledged: no loss event (RFC 9002 §6.1).
    try std.testing.expectEqual(@as(?u64, null), conn.rec.congestion_recovery_start_time);
    const rec_work = conn.rec.entriesVisited(.Application);
    if (rec_work > recoveryWorkBound(conn.pn_app_tx, acks + 1)) {
        std.debug.print("SONNY-6434: recovery visited {} entries for {} packets and {} ACKs\n", .{ rec_work, conn.pn_app_tx, acks + 1 });
        return error.RecoveryWorkNotAmortized;
    }
}

// Recording a packet once recovery tracks its 4096-packet cap must cost
// amortized constant work: the writer holds the connection lock while it
// records each packet, so per-send work proportional to the tracked set
// starves ACK processing on the receive path.
test "SONNY-6434 recording packets past the tracking cap costs amortized constant work" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    const packets: u64 = 20_000;
    var pn: u64 = 0;
    while (pn < packets) : (pn += 1) try rec.onPacketSent(.Application, pn, 1200, true, pn);

    try std.testing.expect(rec.sentLen(.Application) <= max_tracked_packets);
    try std.testing.expectEqual(.in_flight, rec.getPacketDeliveryState(.Application, packets - 1));
    try std.testing.expectEqual(.unknown, rec.getPacketDeliveryState(.Application, 0));
    // Dropped packets leave bytes in flight; the retained ones remain.
    try std.testing.expectEqual(rec.sentLen(.Application) * 1200, rec.getBytesInFlight());
    const work = rec.entriesVisited(.Application);
    if (work > recoveryWorkBound(packets, 0)) {
        std.debug.print("SONNY-6434: recording {} packets visited {} entries\n", .{ packets, work });
        return error.RecoveryWorkNotAmortized;
    }
}

/// A STREAM payload two of which never fit one packet: each lost packet is
/// retransmitted alone (smaller contiguous ones are sent together, SONNY-6649).
const big_chunk = [_]u8{'D'} ** 1000;

// RFC 9002 §6.1.1: a packet is lost once kPacketThreshold (3) newer packets
// are acknowledged. Lost STREAM data is retransmitted oldest first; packets
// within the threshold, and packets above the largest acknowledged, are not.
test "SONNY-6434 ACK retransmits only packet-threshold losses, oldest first" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    initConn(&conn, &allocator);
    defer conn.deinit();
    var sender: CountingSender = .{};
    conn.setSender(&sender, CountingSender.send);
    // A long RTT keeps time-threshold loss (§6.1.2) out of this test.
    conn.rec.rtt.have_sample = true;
    conn.rec.rtt.smoothed_rtt_ns = 60 * std.time.ns_per_s;
    conn.rec.rtt.latest_rtt_ns = 60 * std.time.ns_per_s;
    conn.rec.refreshAtomicMirrors();

    var i: u64 = 0;
    while (i < 14) : (i += 1) try std.testing.expectEqual(big_chunk.len, try conn.writeStream(0, &big_chunk, false));

    // Peer acknowledges only PN 10. PNs 0..7 are lost (10 - pn >= 3); 8 and 9
    // are within the threshold; 11..13 were sent after the largest acked.
    conn.onAckReceivedSpace(.Application, 10, 0, &.{}, null);
    try std.testing.expectEqual(@as(u64, 16), conn.pn_app_tx); // two retransmissions
    try std.testing.expect(!conn.app_stream_retx.contains(0));
    try std.testing.expect(!conn.app_stream_retx.contains(1));
    try std.testing.expectEqual(@as(u64, 0), conn.app_stream_retx.get(14).?.offset);
    try std.testing.expectEqual(@as(u64, 1000), conn.app_stream_retx.get(15).?.offset);
    for ([_]u64{ 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13 }) |pn| {
        try std.testing.expect(conn.app_stream_retx.contains(pn));
    }

    // A repeated ACK continues with the next-oldest lost packets.
    conn.onAckReceivedSpace(.Application, 10, 0, &.{}, null);
    try std.testing.expectEqual(@as(u64, 18), conn.pn_app_tx);
    try std.testing.expectEqual(@as(u64, 2000), conn.app_stream_retx.get(16).?.offset);
    try std.testing.expectEqual(@as(u64, 3000), conn.app_stream_retx.get(17).?.offset);
    try std.testing.expect(conn.app_stream_retx.contains(8));
    try std.testing.expect(conn.app_stream_retx.contains(9));
    try std.testing.expect(conn.app_stream_retx.contains(13));
}

// A send that would block must not drop lost STREAM data or skip ahead: the
// walk stops, the entries stay tracked, and the next ACK retries them oldest
// first.
test "SONNY-6434 ACK-path retransmit send failure keeps lost data tracked" {
    var allocator = std.testing.allocator;
    const FlakySender = struct {
        fail: bool = false,
        sends: usize = 0,

        fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.fail) return error.WouldBlock;
            self.sends += 1;
            return bytes.len;
        }
    };
    var conn: conn_mod.Connection = undefined;
    initConn(&conn, &allocator);
    defer conn.deinit();
    var sender: FlakySender = .{};
    conn.setSender(&sender, FlakySender.send);
    conn.rec.rtt.have_sample = true;
    conn.rec.rtt.smoothed_rtt_ns = 60 * std.time.ns_per_s;
    conn.rec.rtt.latest_rtt_ns = 60 * std.time.ns_per_s;
    conn.rec.refreshAtomicMirrors();

    var i: u64 = 0;
    while (i < 8) : (i += 1) try std.testing.expectEqual(big_chunk.len, try conn.writeStream(0, &big_chunk, false));

    sender.fail = true;
    conn.onAckReceivedSpace(.Application, 7, 0, &.{}, null); // 0..4 lost
    try std.testing.expectEqual(@as(u64, 8), conn.pn_app_tx);
    try std.testing.expectEqual(@as(usize, 7), conn.app_stream_retx.count());

    sender.fail = false;
    conn.onAckReceivedSpace(.Application, 7, 0, &.{}, null);
    try std.testing.expectEqual(@as(u64, 10), conn.pn_app_tx);
    try std.testing.expectEqual(@as(u64, 0), conn.app_stream_retx.get(8).?.offset);
    try std.testing.expectEqual(@as(u64, 1000), conn.app_stream_retx.get(9).?.offset);
    for ([_]u64{ 2, 3, 4, 5, 6 }) |pn| try std.testing.expect(conn.app_stream_retx.contains(pn));
}

fn sendPackets(rec: *recovery.Recovery, count: u64) !void {
    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 60 * std.time.ns_per_s;
    rec.rtt.latest_rtt_ns = 60 * std.time.ns_per_s;
    const now: u64 = @intCast(compat.nanoTimestamp());
    var pn: u64 = 0;
    while (pn < count) : (pn += 1) try rec.onPacketSent(.Application, pn, 100, true, now);
}

// RFC 9002 §6.1.1 via the range API, on both marking strategies (probe each
// PN for narrow ranges, test each tracked packet for wide ones), against the
// packet-number-list API. Time threshold (§6.1.2) is held off by a long RTT.
// The packet-number-list API (loss_detection_scan benchmark, tests) must
// mark a run of acknowledged packets in amortized constant lookups, as the
// former hash index did: a binary search per packet number regressed the
// benchmark's N=1000 tail latency by ~50% on the CI runner.
test "SONNY-6434 packet-number list ACK marks runs without a search per packet" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    try sendPackets(&rec, 1000);
    var acked: [500]u64 = undefined;
    for (&acked, 0..) |*pn, i| pn.* = 250 + i;
    var descending: [100]u64 = undefined;
    for (&descending, 0..) |*pn, i| pn.* = 999 - i;

    const before = rec.searchProbes(.Application);
    const res = rec.onAckReceivedWithEcn(.Application, &acked, 0, @intCast(compat.nanoTimestamp()), null);
    try std.testing.expectEqual(@as(usize, 500 * 100), res.bytes_acked);
    const res2 = rec.onAckReceivedWithEcn(.Application, &descending, 0, @intCast(compat.nanoTimestamp()), null);
    try std.testing.expectEqual(@as(usize, 100 * 100), res2.bytes_acked);
    const probes = rec.searchProbes(.Application) - before;
    // A constant number of probes per listed packet (the old hash index
    // made one) plus one search per run and compaction's bounds; a binary
    // search per packet takes ~10 each.
    if (probes > 2 * 600 + 64) {
        std.debug.print("SONNY-6434: {} search probes to mark 600 listed packets\n", .{probes});
        return error.MarkingNotAmortized;
    }
}

test "SONNY-6434 recovery ACK ranges acknowledge exactly the covered packets" {
    const Case = struct { ranges: []const recovery.Recovery.AckedRange, pns: []const u64 };
    const narrow: Case = .{
        .ranges = &.{ .{ .lo = 15, .hi = 19 }, .{ .lo = 5, .hi = 9 } },
        .pns = &.{ 19, 18, 17, 16, 15, 9, 8, 7, 6, 5 },
    };
    // Same packets, but the ranges also span packet numbers never sent.
    const wide: Case = .{
        .ranges = &.{ .{ .lo = 15, .hi = 100_000 }, .{ .lo = 5, .hi = 9 } },
        .pns = narrow.pns,
    };
    for ([_]Case{ narrow, wide }) |case| {
        var by_range = recovery.Recovery.init(std.testing.allocator);
        defer by_range.deinit();
        var by_pn = recovery.Recovery.init(std.testing.allocator);
        defer by_pn.deinit();
        try sendPackets(&by_range, 20);
        try sendPackets(&by_pn, 20);
        const now: u64 = @intCast(compat.nanoTimestamp());

        const r = by_range.onAckRangesReceivedWithEcn(.Application, case.ranges, 0, now, null);
        const p = by_pn.onAckReceivedWithEcn(.Application, case.pns, 0, now, null);
        // 10 packets acked; 0..4 and 10..14 are >= 3 below largest (19): lost.
        try std.testing.expectEqual(@as(usize, 1000), r.bytes_acked);
        try std.testing.expectEqual(@as(usize, 1000), r.bytes_lost);
        try std.testing.expectEqual(p.bytes_acked, r.bytes_acked);
        try std.testing.expectEqual(p.bytes_lost, r.bytes_lost);
        try std.testing.expectEqual(@as(usize, 0), by_range.sentLen(.Application));
        try std.testing.expectEqual(@as(usize, 0), by_range.getBytesInFlight());
    }

    // Only the largest acknowledged: packets within kPacketThreshold of it
    // stay in flight, older ones are lost.
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    try sendPackets(&rec, 20);
    const res = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 19, .hi = 19 }}, 0, @intCast(compat.nanoTimestamp()), null);
    try std.testing.expectEqual(@as(usize, 100), res.bytes_acked);
    try std.testing.expectEqual(@as(usize, 1700), res.bytes_lost);
    try std.testing.expectEqual(.in_flight, rec.getPacketDeliveryState(.Application, 17));
    try std.testing.expectEqual(.in_flight, rec.getPacketDeliveryState(.Application, 18));
    try std.testing.expectEqual(.unknown, rec.getPacketDeliveryState(.Application, 16));
    try std.testing.expectEqual(@as(usize, 200), rec.getBytesInFlight());
}

// RFC 9002 Appendix A.10: after an ACK the loss timer is the earliest
// time-threshold deadline among packets not declared lost.
test "SONNY-6434 loss timer tracks the oldest packet not declared lost" {
    var rec = recovery.Recovery.init(std.testing.allocator);
    defer rec.deinit();
    rec.rtt.have_sample = true;
    rec.rtt.smoothed_rtt_ns = 60 * std.time.ns_per_s;
    rec.rtt.latest_rtt_ns = 60 * std.time.ns_per_s;
    var pn: u64 = 0;
    while (pn < 10) : (pn += 1) try rec.onPacketSent(.Application, pn, 100, true, 1_000_000 + pn * 1000);

    // Only PN 9 is acknowledged: 0..6 are lost by packet threshold, 7 and 8
    // stay in flight and the timer is PN 7's deadline.
    const res = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 9, .hi = 9 }}, 0, 2_000_000, null);
    try std.testing.expectEqual(@as(usize, 700), res.bytes_lost);
    const tt = recovery.LossDetector.timeThresholdNs(rec.rtt.smoothed_rtt_ns, rec.rtt.latest_rtt_ns);
    const app = @intFromEnum(recovery.PacketNumberSpace.Application);
    try std.testing.expectEqual(@as(?u64, 1_000_000 + 7 * 1000 + tt), rec.spaces[app].loss_time_ns);

    // Once 7 and 8 are lost too, no packet is left to time out.
    const later = rec.onAckRangesReceivedWithEcn(.Application, &.{.{ .lo = 9, .hi = 9 }}, 0, 1_000_000 + 8 * 1000 + tt, null);
    try std.testing.expectEqual(@as(usize, 200), later.bytes_lost);
    try std.testing.expectEqual(@as(?u64, null), rec.spaces[app].loss_time_ns);
    try std.testing.expectEqual(@as(usize, 0), rec.sentLen(.Application));
}

/// In-memory peer for the bulk-transfer test: captures every datagram the
/// connection sends, decrypts it with the real packet decoder, and
/// reassembles the stream.
const Peer = struct {
    allocator: std.mem.Allocator,
    outbox: std.ArrayList([]u8) = .empty,
    rx: RxRanges = .{},
    stream: []u8,
    chunks: std.AutoHashMap(u64, void),
    stream_bytes: u64 = 0,
    fin_at: ?u64 = null,
    dcid_len: usize = 0,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) anyerror!usize {
        const self: *Peer = @ptrCast(@alignCast(ctx));
        try self.outbox.append(self.allocator, try self.allocator.dupe(u8, bytes));
        return bytes.len;
    }

    fn deinit(self: *Peer) void {
        for (self.outbox.items) |p| self.allocator.free(p);
        self.outbox.deinit(self.allocator);
        self.rx.deinit(self.allocator);
        self.chunks.deinit();
    }

    /// Process one datagram; returns true if it carried a new packet number.
    fn receive(self: *Peer, bytes: []const u8) !bool {
        const largest = if (self.rx.items.items.len == 0) 0 else self.rx.items.items[self.rx.items.items.len - 1].hi;
        var payload: [2048]u8 = undefined;
        const dec = try packet.decodeShortProtectedInto(bytes, self.dcid_len, app_keys, largest, &payload);
        if (!try self.rx.insert(self.allocator, dec.packet_number)) return false;
        var rest: []const u8 = dec.payload;
        while (rest.len > 0) {
            const one = try frame.decodeOne(rest);
            rest = rest[one.n..];
            switch (one.f) {
                .stream => |s| {
                    const off = s.offset orelse 0;
                    @memcpy(self.stream[off..][0..s.data.len], s.data);
                    if (s.fin) self.fin_at = off + s.data.len;
                    const gop = try self.chunks.getOrPut(off);
                    if (!gop.found_existing) self.stream_bytes += s.data.len;
                },
                else => {},
            }
        }
        return true;
    }

    fn complete(self: *const Peer) bool {
        return self.fin_at != null and self.stream_bytes == self.fin_at.?;
    }
};

// Reproduces the geode remote-backup stall: a 24 MiB server->client stream
// with thousands of packets in flight (past the 4096-packet tracking cap),
// 0.25% packet loss, reordering, delayed and lost ACKs, and occasional
// stretch ACKs covering more than 256 packets. The transfer must complete
// with the exact bytes, leave no retransmission state behind, and no ACK may
// do work proportional to the packets in flight.
test "SONNY-6434 lossy 24 MiB stream transfer completes with bounded per-ACK work" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    initConn(&conn, &allocator);
    defer conn.deinit();

    const total_bytes: usize = 24 * 1024 * 1024;
    const window_packets: usize = 6144;
    const data = try allocator.alloc(u8, total_bytes);
    defer allocator.free(data);
    for (data, 0..) |*b, k| b.* = @truncate(k *% 31 +% (k >> 13));

    var peer: Peer = .{
        .allocator = allocator,
        .stream = try allocator.alloc(u8, total_bytes),
        .chunks = std.AutoHashMap(u64, void).init(allocator),
        .dcid_len = conn.shortHeaderDcid().len,
    };
    defer allocator.free(peer.stream);
    defer peer.deinit();
    conn.setSender(&peer, Peer.send);

    var prng = std.Random.DefaultPrng.init(0x6434);
    const rand = prng.random();
    var batch: std.ArrayList([]u8) = .empty;
    defer {
        for (batch.items) |bytes| allocator.free(bytes);
        batch.deinit(allocator);
    }

    const start_ns = compat.nanoTimestamp();
    var send_off: usize = 0;
    var max_work: u64 = 0;
    var acks: u64 = 0;
    var max_tracked: usize = 0;
    var unacked_rx: u64 = 0;
    var ack_after: u64 = 32;
    var rounds: usize = 0;
    while (!(peer.complete() and conn.app_stream_retx.count() == 0)) : (rounds += 1) {
        if (rounds == 20_000) return error.TransferDidNotComplete;

        // Sender: fill the application window with new stream data.
        while (send_off < total_bytes and conn.app_stream_retx.count() < window_packets) {
            const n = try conn.writeStream(0, data[send_off..], true);
            if (n == 0) break;
            send_off += n;
        }
        max_tracked = @max(max_tracked, conn.rec.sentLen(.Application));

        if (peer.outbox.items.len == 0) {
            // Tail loss with nothing left to elicit an ACK: PTO probe
            // (RFC 9002 §6.2.4) resends the oldest unacknowledged data.
            conn.sendPtoProbeApp();
            if (peer.outbox.items.len == 0) return error.StalledWithNothingInFlight;
        }

        // Network: take this flight, reorder adjacent pairs, drop some.
        std.mem.swap(std.ArrayList([]u8), &batch, &peer.outbox);
        var k: usize = 0;
        while (k + 1 < batch.items.len) : (k += 1) {
            if (rand.uintLessThan(u32, 16) == 0) std.mem.swap([]u8, &batch.items[k], &batch.items[k + 1]);
        }
        for (batch.items) |bytes| {
            if (rand.uintLessThan(u32, 400) == 0) continue; // lost datagram
            if (try peer.receive(bytes)) unacked_rx += 1;
            if (unacked_rx >= ack_after) {
                // Occasionally the peer's ACKs are lost or delayed long
                // enough that one ACK newly covers hundreds of packets.
                ack_after = if (rand.uintLessThan(u32, 40) == 0) 600 else 32;
                if (rand.uintLessThan(u32, 8) == 0) continue; // ACK lost
                try deliverAck(&conn, peer.rx.ack().?, unacked_rx, &max_work);
                acks += 1;
                unacked_rx = 0;
            }
        }
        for (batch.items) |bytes| allocator.free(bytes);
        batch.clearRetainingCapacity();
        // ACK-delay timer flush at the end of the flight (may also be lost).
        if (unacked_rx > 0 and rand.uintLessThan(u32, 8) != 0) {
            try deliverAck(&conn, peer.rx.ack().?, unacked_rx, &max_work);
            acks += 1;
            unacked_rx = 0;
        }
    }
    const elapsed_ns: u64 = @intCast(compat.nanoTimestamp() - start_ns);

    try std.testing.expectEqual(@as(?u64, total_bytes), peer.fin_at);
    try std.testing.expect(std.mem.eql(u8, data, peer.stream));
    try std.testing.expectEqual(@as(usize, 0), conn.app_stream_retx.count());
    try std.testing.expect(max_tracked <= max_tracked_packets);
    try std.testing.expect(acks > 100);
    const rec_work = conn.rec.entriesVisited(.Application);
    if (rec_work > recoveryWorkBound(conn.pn_app_tx, acks)) {
        std.debug.print("SONNY-6434: recovery visited {} entries for {} packets and {} ACKs\n", .{ rec_work, conn.pn_app_tx, acks });
        return error.RecoveryWorkNotAmortized;
    }
    // Sanity bound only (Debug build, shared CI host): the stall this test
    // reproduces takes far longer than this; a healthy run takes seconds.
    try std.testing.expect(elapsed_ns < 300 * std.time.ns_per_s);
}
