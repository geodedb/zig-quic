// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Retransmission of lost control frames (RFC 9000 §13.3; SONNY-6486).
//!
//! MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS are sent again when the packet
//! carrying them is lost, with the CURRENT value, not the lost one;
//! MAX_STREAM_DATA only while the stream's receive side still needs credit
//! (before Size Known). RESET_STREAM is sent again as is until acknowledged.
//! NEW_CONNECTION_ID is sent again while the connection ID is not retired,
//! and RETIRE_CONNECTION_ID as is (SONNY-6655).
//! Each 1-RTT packet that carried one of these frames is recorded under its
//! packet number until an ACK covers it or it is found lost, by the rule
//! STREAM data uses (methods_b retransmitLostStreamPackets): below the largest
//! acknowledged, and either three packets older or reported lost by recovery.
//!
//! Callers hold `Connection.mu`.

const std = @import("std");
const frame = @import("quic_frame");
const logger = @import("quic_logger");

/// Control frames one packet carried.
pub const Entry = struct {
    max_data: bool = false,
    max_streams_bidi: bool = false,
    max_streams_uni: bool = false,
    /// Streams whose MAX_STREAM_DATA the packet carried (owned).
    msd_streams: []u64 = &.{},
    /// RESET_STREAM frames the packet carried (owned).
    resets: []frame.ResetStream = &.{},
    /// Sequence numbers of the NEW_CONNECTION_ID frames the packet carried
    /// (owned).
    new_cids: []u64 = &.{},
    /// Sequence numbers of the RETIRE_CONNECTION_ID frames the packet
    /// carried (owned).
    retire_cids: []u64 = &.{},

    pub fn deinit(self: *Entry, alloc: std.mem.Allocator) void {
        if (self.msd_streams.len > 0) alloc.free(self.msd_streams);
        if (self.resets.len > 0) alloc.free(self.resets);
        if (self.new_cids.len > 0) alloc.free(self.new_cids);
        if (self.retire_cids.len > 0) alloc.free(self.retire_cids);
        self.* = .{};
    }
};

pub fn bind(comptime Connection: type) type {
    return struct {
        /// Record the control frames in `frames_bytes`, sent in packet `pn`.
        pub fn noteControlPacket(self: *Connection, pn: u64, frames_bytes: []const u8) void {
            var entry: Entry = .{};
            var n_msd: usize = 0;
            var n_reset: usize = 0;
            var n_new_cid: usize = 0;
            var n_retire_cid: usize = 0;
            var off: usize = 0;
            while (off < frames_bytes.len) {
                const fr = frame.decodeOne(frames_bytes[off..]) catch break;
                if (fr.n == 0) break;
                off += fr.n;
                switch (fr.f) {
                    .max_data => entry.max_data = true,
                    .max_streams_bidi => entry.max_streams_bidi = true,
                    .max_streams_uni => entry.max_streams_uni = true,
                    .max_stream_data => n_msd += 1,
                    .reset_stream => n_reset += 1,
                    .new_connection_id => n_new_cid += 1,
                    .retire_connection_id => n_retire_cid += 1,
                    else => {},
                }
            }
            if (!entry.max_data and !entry.max_streams_bidi and !entry.max_streams_uni and n_msd == 0 and n_reset == 0 and
                n_new_cid == 0 and n_retire_cid == 0) return;
            const alloc = self.allocator.*;
            entry.msd_streams = alloc.alloc(u64, n_msd) catch &.{};
            entry.resets = alloc.alloc(frame.ResetStream, n_reset) catch &.{};
            entry.new_cids = alloc.alloc(u64, n_new_cid) catch &.{};
            entry.retire_cids = alloc.alloc(u64, n_retire_cid) catch &.{};
            var i_msd: usize = 0;
            var i_reset: usize = 0;
            var i_new_cid: usize = 0;
            var i_retire_cid: usize = 0;
            off = 0;
            while (off < frames_bytes.len) {
                const fr = frame.decodeOne(frames_bytes[off..]) catch break;
                if (fr.n == 0) break;
                off += fr.n;
                switch (fr.f) {
                    .max_stream_data => |m| if (i_msd < entry.msd_streams.len) {
                        entry.msd_streams[i_msd] = m.stream_id;
                        i_msd += 1;
                    },
                    .reset_stream => |r| if (i_reset < entry.resets.len) {
                        entry.resets[i_reset] = r;
                        i_reset += 1;
                    },
                    .new_connection_id => |n| if (i_new_cid < entry.new_cids.len) {
                        entry.new_cids[i_new_cid] = n.sequence;
                        i_new_cid += 1;
                    },
                    .retire_connection_id => |r| if (i_retire_cid < entry.retire_cids.len) {
                        entry.retire_cids[i_retire_cid] = r.sequence;
                        i_retire_cid += 1;
                    },
                    else => {},
                }
            }
            const gop = self.ctrl_retx.getOrPut(alloc, pn) catch {
                entry.deinit(alloc);
                logger.err("control frame tracking failed (OOM) for pn {d}", .{pn});
                return;
            };
            if (gop.found_existing) gop.value_ptr.deinit(alloc);
            gop.value_ptr.* = entry;
        }

        /// `intervals`: inclusive `.lo`/`.hi` packet-number ranges in
        /// descending order (Recovery.AckedRange).
        fn acked(intervals: anytype, pn: u64) bool {
            for (intervals) |iv| {
                if (pn > iv.hi) return false;
                if (pn >= iv.lo) return true;
            }
            return false;
        }

        /// Drop records an ACK covers and resend the frames of lost packets.
        pub fn onAckControlFrames(self: *Connection, intervals: anytype, largest_acked: u64, recovery_reported_loss: bool) void {
            onAckHandshakeDone(self, intervals, largest_acked, recovery_reported_loss);
            // Retirements not sent when they were queued (no packet went out).
            if (self.pending_retire_len > 0) flushPendingRetireConnectionIds(self);
            if (self.ctrl_retx.count() == 0) return;
            const alloc = self.allocator.*;
            var lost: std.ArrayList(Entry) = .empty;
            defer {
                for (lost.items) |*e| e.deinit(alloc);
                lost.deinit(alloc);
            }
            var done: std.ArrayList(u64) = .empty;
            defer done.deinit(alloc);
            var it = self.ctrl_retx.iterator();
            while (it.next()) |kv| {
                const pn = kv.key_ptr.*;
                if (acked(intervals, pn)) {
                    done.append(alloc, pn) catch return;
                } else if (pn < largest_acked and (largest_acked - pn >= 3 or recovery_reported_loss)) {
                    lost.ensureUnusedCapacity(alloc, 1) catch return;
                    done.append(alloc, pn) catch return;
                    lost.appendAssumeCapacity(kv.value_ptr.*);
                    kv.value_ptr.* = .{}; // ownership moved to `lost`
                }
            }
            for (done.items) |pn| {
                if (self.ctrl_retx.fetchRemove(pn)) |kv| {
                    var e = kv.value;
                    e.deinit(alloc);
                }
            }
            if (lost.items.len > 0) resendControl(self, lost.items);
        }

        /// RFC 9000 §13.3: "The HANDSHAKE_DONE frame MUST be retransmitted
        /// until it is acknowledged." Lost by the rule above, it is sent
        /// again in a new packet; a client that never receives it never
        /// confirms the handshake (RFC 9001 §4.1.2), and may then never
        /// initiate a key update (§6.1).
        fn onAckHandshakeDone(self: *Connection, intervals: anytype, largest_acked: u64, recovery_reported_loss: bool) void {
            const pn = self.handshake_done_pn orelse return;
            if (acked(intervals, pn)) {
                self.handshake_done_pn = null;
                return;
            }
            if (pn >= largest_acked or (largest_acked - pn < 3 and !recovery_reported_loss)) return;
            var buf: [8]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            _ = (frame.Frame{ .handshake_done = {} }).write(&w) catch return;
            const resend_pn = self.pn_app_tx;
            self.sendControlFrames(buf[0..w.end]);
            // Not sent (no keys, send failure): still lost, retried on the
            // next ACK.
            if (self.pn_app_tx != resend_pn) self.handshake_done_pn = resend_pn;
        }

        /// Send the frames of lost packets again: flow-control limits with
        /// their current value, RESET_STREAM unchanged.
        fn resendControl(self: *Connection, lost: []const Entry) void {
            var buf: [1024]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            var max_data = false;
            var bidi = false;
            var uni = false;
            for (lost) |e| {
                max_data = max_data or e.max_data;
                bidi = bidi or e.max_streams_bidi;
                uni = uni or e.max_streams_uni;
            }
            if (max_data) {
                put(self, &w, &buf, .{ .max_data = .{ .max = self.local_max_data } });
                self.last_sent_max_data = @max(self.last_sent_max_data, self.local_max_data);
            }
            if (bidi) {
                put(self, &w, &buf, .{ .max_streams_bidi = .{ .max = self.local_max_streams_bidi } });
                self.last_sent_max_streams_bidi = @max(self.last_sent_max_streams_bidi, self.local_max_streams_bidi);
            }
            if (uni) {
                put(self, &w, &buf, .{ .max_streams_uni = .{ .max = self.local_max_streams_uni } });
                self.last_sent_max_streams_uni = @max(self.last_sent_max_streams_uni, self.local_max_streams_uni);
            }
            for (lost) |e| {
                for (e.msd_streams) |sid| {
                    if (!self.streams_rx_init) break;
                    const rx = self.streams_rx.getPtr(sid) orelse continue;
                    // No more credit needed once the final size is known.
                    if (rx.state != .Recv) continue;
                    put(self, &w, &buf, .{ .max_stream_data = .{ .stream_id = sid, .max = rx.local_max_stream_data } });
                    rx.last_sent_max_stream_data = @max(rx.last_sent_max_stream_data, rx.local_max_stream_data);
                }
                for (e.resets) |r| put(self, &w, &buf, .{ .reset_stream = r });
                for (e.new_cids) |seq| {
                    // Not once the peer retired it (RFC 9000 §13.3).
                    for (self.local_cids) |lc| {
                        if (!lc.in_use or lc.sequence != seq or seq == 0) continue;
                        put(self, &w, &buf, .{ .new_connection_id = .{
                            .sequence = seq,
                            .retire_prior_to = self.retired_prior_to,
                            .connection_id = lc.cid.bytes[0..lc.cid.len],
                            .stateless_reset_token = lc.reset_token,
                        } });
                        break;
                    }
                }
                for (e.retire_cids) |seq| put(self, &w, &buf, .{ .retire_connection_id = .{ .sequence = seq } });
            }
            if (w.end > 0) self.sendControlFrames(buf[0..w.end]);
        }

        /// Send the pending RETIRE_CONNECTION_ID frames (RFC 9000 §5.1.2) in
        /// one packet, recorded for retransmission like the other control
        /// frames. They stay pending when no packet goes out (no 1-RTT keys,
        /// encoding failure) and are sent with the next ACK.
        pub fn flushPendingRetireConnectionIds(self: *Connection) void {
            if (self.pending_retire_len == 0) return;
            var buf: [1024]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            for (self.pending_retire_cids[0..self.pending_retire_len]) |seq| {
                _ = (frame.Frame{ .retire_connection_id = .{ .sequence = seq } }).write(&w) catch return;
            }
            const pn = self.pn_app_tx;
            self.sendControlFrames(buf[0..w.end]);
            if (self.pn_app_tx != pn) self.pending_retire_len = 0;
        }

        /// Append `f`, first sending the frames gathered so far if it would
        /// not fit in one packet.
        fn put(self: *Connection, w: *std.Io.Writer, buf: *[1024]u8, f: frame.Frame) void {
            const mark = w.end;
            _ = f.write(w) catch {
                w.end = mark;
                if (mark > 0) self.sendControlFrames(buf[0..mark]);
                w.end = 0;
                _ = f.write(w) catch {};
                return;
            };
        }

        /// RFC 9000 §4.1/§19.13: the peer is blocked on stream `stream_id`
        /// at `limit`. If more credit exists than it saw (the update may
        /// have been lost or not yet sent), send the current limit now
        /// (SONNY-6486).
        pub fn onStreamDataBlocked(self: *Connection, stream_id: u64, limit: u64) void {
            if (!self.streams_rx_init) return;
            const rx = self.streams_rx.getPtr(stream_id) orelse return;
            if (rx.state != .Recv or rx.local_max_stream_data <= limit) return;
            var buf: [32]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            _ = (frame.Frame{ .max_stream_data = .{ .stream_id = stream_id, .max = rx.local_max_stream_data } }).write(&w) catch return;
            self.sendControlFrames(buf[0..w.end]);
            rx.last_sent_max_stream_data = @max(rx.last_sent_max_stream_data, rx.local_max_stream_data);
        }

        pub fn deinitControlTracking(self: *Connection) void {
            const alloc = self.allocator.*;
            var it = self.ctrl_retx.valueIterator();
            while (it.next()) |e| e.deinit(alloc);
            self.ctrl_retx.deinit(alloc);
            self.ctrl_retx = .empty;
        }
    };
}
