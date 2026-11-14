// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Opt-in diagnostic: STREAM data retransmitted although the peer had
//! already acknowledged it (SONNY-6478 follow-up).
//!
//! Disabled by default (one branch per send/ACK). When `enabled`, every
//! STREAM packet sent (original or retransmission) is recorded by packet
//! number with the byte range it carried; an ACK covering the packet marks
//! that range acknowledged for its stream, independently of the
//! retransmission bookkeeping. Each retransmission whose whole range was
//! already acknowledged at send time is counted. A FIN counts as one byte
//! past the stream's data so a resent, acknowledged FIN is caught too.
//! A retransmission of data whose ACK was simply still on its way is not
//! counted: that is a legitimate (spurious) retransmission, not this defect.

const std = @import("std");

const Sent = struct { stream_id: u64, lo: u64, hi: u64 };
const Range = struct { lo: u64, hi: u64 };

pub const Ledger = struct {
    enabled: bool = false,
    sent: std.AutoHashMapUnmanaged(u64, Sent) = .empty,
    acked: std.AutoHashMapUnmanaged(u64, std.ArrayList(Range)) = .empty,
    /// Retransmitted STREAM packets / bytes whose range was already
    /// acknowledged when they were sent.
    acked_resent_packets: u64 = 0,
    acked_resent_bytes: u64 = 0,

    pub fn deinit(self: *Ledger, alloc: std.mem.Allocator) void {
        self.sent.deinit(alloc);
        var it = self.acked.valueIterator();
        while (it.next()) |l| l.deinit(alloc);
        self.acked.deinit(alloc);
        self.* = .{};
    }

    fn span(offset: u64, len: usize, fin: bool) Range {
        const end = offset + @as(u64, len);
        return .{ .lo = offset, .hi = end + @intFromBool(fin) };
    }

    pub fn noteSent(self: *Ledger, alloc: std.mem.Allocator, pn: u64, stream_id: u64, offset: u64, len: usize, fin: bool) void {
        if (!self.enabled) return;
        const r = span(offset, len, fin);
        if (r.hi == r.lo) return;
        self.sent.put(alloc, pn, .{ .stream_id = stream_id, .lo = r.lo, .hi = r.hi }) catch {};
    }

    /// `intervals`: inclusive `.lo`/`.hi` acknowledged packet-number ranges.
    pub fn noteAck(self: *Ledger, alloc: std.mem.Allocator, intervals: anytype) void {
        if (!self.enabled or self.sent.count() == 0) return;
        var done: std.ArrayList(u64) = .empty;
        defer done.deinit(alloc);
        var it = self.sent.iterator();
        while (it.next()) |kv| {
            const pn = kv.key_ptr.*;
            for (intervals) |iv| {
                if (pn >= iv.lo and pn <= iv.hi) {
                    done.append(alloc, pn) catch return;
                    break;
                }
            }
        }
        for (done.items) |pn| {
            const s = self.sent.fetchRemove(pn).?.value;
            self.addAcked(alloc, s.stream_id, .{ .lo = s.lo, .hi = s.hi });
        }
    }

    fn addAcked(self: *Ledger, alloc: std.mem.Allocator, stream_id: u64, r: Range) void {
        const gop = self.acked.getOrPut(alloc, stream_id) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const list = gop.value_ptr;
        var merged = r;
        var i: usize = 0;
        while (i < list.items.len) {
            const x = list.items[i];
            if (x.hi < merged.lo or x.lo > merged.hi) {
                i += 1;
                continue;
            }
            merged = .{ .lo = @min(x.lo, merged.lo), .hi = @max(x.hi, merged.hi) };
            _ = list.swapRemove(i);
        }
        list.append(alloc, merged) catch {};
    }

    /// A retransmission of `offset..offset+len` (plus FIN) is being sent.
    pub fn noteRetransmit(self: *Ledger, stream_id: u64, offset: u64, len: usize, fin: bool) void {
        if (!self.enabled) return;
        const r = span(offset, len, fin);
        if (r.hi == r.lo) return;
        const list = self.acked.getPtr(stream_id) orelse return;
        for (list.items) |x| {
            if (x.lo <= r.lo and r.hi <= x.hi) {
                self.acked_resent_packets += 1;
                self.acked_resent_bytes += r.hi - r.lo;
                return;
            }
        }
    }
};
