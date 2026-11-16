// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Stream management for QUIC connections.
//!
//! RFC 9000 §2: Streams (bidirectional and unidirectional)
//! RFC 9000 §3: Stream States
//! RFC 9000 §4: Flow Control

const std = @import("std");
const logger = @import("quic_logger");

/// RFC 9000 §3.1 send-side states.
pub const SendState = enum {
    Ready,
    Send,
    DataSent,
    ResetSent,

    pub fn canWrite(self: SendState) bool {
        return switch (self) {
            .Ready, .Send => true,
            .DataSent, .ResetSent => false,
        };
    }
};

/// RFC 9000 §3.2 receive-side states.
pub const ReceiveState = enum {
    Recv,
    SizeKnown,
    DataRead,
    ResetRead,

    pub fn terminal(self: ReceiveState) bool {
        return switch (self) {
            .DataRead, .ResetRead => true,
            .Recv, .SizeKnown => false,
        };
    }
};

/// Data segment for stream reassembly.
pub const Segment = struct {
    off: u64,
    data: []u8,
    /// Length of the allocation `data` starts, when larger than `data.len`
    /// (data contiguous with the segment is appended in place, SONNY-6649);
    /// 0 when the allocation is exactly `data`. Free with freeSegment().
    cap: usize = 0,

    /// The whole allocation behind `data`.
    pub fn allocation(self: Segment) []u8 {
        return if (self.cap > self.data.len) self.data.ptr[0..self.cap] else self.data;
    }
};

/// Free a segment's buffer, including capacity beyond `data.len`.
pub fn freeSegment(alloc: std.mem.Allocator, seg: Segment) void {
    alloc.free(seg.allocation());
}

/// Stream receive state - handles out-of-order delivery and reassembly.
/// RFC 9000 §3: Stream States
pub const StreamRx = struct {
    state: ReceiveState = .Recv,
    recv_off: u64 = 0,
    inbox: std.ArrayList(u8),
    inbox_read_off: usize = 0,
    bufs: std.ArrayList(Segment),
    fin_off: ?u64 = null,
    // PHASE 42 PART 9: Per-stream flow control tracking (RFC 9000 §4.2)
    local_max_stream_data: u64 = 0, // Current receive window limit for this stream
    last_sent_max_stream_data: u64 = 0, // Last MAX_STREAM_DATA value sent to peer
    // PHASE 42 PART 18: RTT-based autotuning (RFC 9000 §4.3, quiche flowcontrol.rs)
    last_window_update_time_us: u64 = 0, // Timestamp of last window expansion (microseconds)
    // PHASE 46: Quinn-style flow control tracking
    initial_window_size: u64 = 0, // Initial window size for threshold calculation
    // PHASE 57 PART 11: Track bytes consumed by application (like quinn's assembler.bytes_read())
    bytes_consumed_total: u64 = 0, // Total bytes consumed by application via readStream()
    // Flow-control bookkeeping: stream needs MAX_STREAM_DATA emission.
    fc_dirty: bool = false,
    // RFC 9000 §4: receive-side flow control accounting (QC-01).
    // `buffered_bytes` is the number of bytes currently held in `bufs` (i.e.
    // received out-of-order and not yet drained into `inbox`), used to bound
    // out-of-order buffering. `highest_off` is the highest absolute byte offset
    // ever received on this stream (max of offset+len seen), used to compute the
    // per-stream contribution to connection-level flow control.
    buffered_bytes: u64 = 0,
    highest_off: u64 = 0,
    /// Diagnostic counter (SONNY-6475): buffered segments examined by
    /// insert() and tryDrain(). Lets tests bound the reassembly work per
    /// received packet.
    reassembly_steps: u64 = 0,

    pub fn init() StreamRx {
        return .{
            .state = .Recv,
            .recv_off = 0,
            .inbox = .empty,
            .inbox_read_off = 0,
            .bufs = .empty,
            .fin_off = null,
            .local_max_stream_data = 0,
            .last_sent_max_stream_data = 0,
            .last_window_update_time_us = 0,
            .initial_window_size = 0,
            .bytes_consumed_total = 0,
            .fc_dirty = false,
            .buffered_bytes = 0,
            .highest_off = 0,
            .reassembly_steps = 0,
        };
    }

    pub fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
        for (self.bufs.items) |seg| freeSegment(alloc.*, seg);
        self.bufs.deinit(alloc.*);
        self.inbox.deinit(alloc.*);
    }

    pub fn available(self: *const StreamRx) usize {
        return self.inbox.items.len - self.inbox_read_off;
    }

    pub fn readInto(self: *StreamRx, out: []u8) usize {
        const readable = self.available();
        const n = @min(out.len, readable);
        if (n == 0) return 0;

        const start = self.inbox_read_off;
        const end = start + n;
        @memcpy(out[0..n], self.inbox.items[start..end]);
        self.inbox_read_off = end;

        if (self.inbox_read_off == self.inbox.items.len) {
            self.inbox.clearRetainingCapacity();
            self.inbox_read_off = 0;
        } else if (self.inbox_read_off >= 4096 and self.inbox_read_off * 2 >= self.inbox.items.len) {
            const rem = self.inbox.items.len - self.inbox_read_off;
            std.mem.copyForwards(u8, self.inbox.items[0..rem], self.inbox.items[self.inbox_read_off..]);
            self.inbox.shrinkRetainingCapacity(rem);
            self.inbox_read_off = 0;
        }

        self.refreshState();
        return n;
    }

    /// Record a FIN offset and reject conflicting final sizes.
    pub fn recordFin(self: *StreamRx, final_off: u64) !void {
        if (self.state == .ResetRead or self.state == .DataRead) return error.StreamStopped;
        if (self.fin_off) |known| {
            if (known != final_off) return error.FinalSizeError;
        }
        if (final_off < self.recv_off) return error.FinalSizeError;
        // RFC 9000 §4.5: below data already received (SONNY-6486).
        if (final_off < self.highest_off) return error.FinalSizeError;
        self.fin_off = final_off;
        self.refreshState();
    }

    /// Mark the receive side reset by the peer and cap the known final size.
    ///
    /// RFC 9000 §4.5 (NEW-SEC-02): the reset's final size MUST be consistent with
    /// any final size already established (e.g. from a FIN) and MUST NOT be
    /// smaller than data already received; otherwise it is a FINAL_SIZE_ERROR.
    /// Previously this overwrote fin_off unconditionally, allowing a peer to
    /// corrupt receive-state bookkeeping.
    pub fn recordReset(self: *StreamRx, final_size: u64) !void {
        if (self.fin_off) |known| {
            if (known != final_size) return error.FinalSizeError;
        }
        if (final_size < self.recv_off) return error.FinalSizeError;
        // Below data already received, buffered or not (SONNY-6486: a final
        // size cutting through a buffered segment was accepted).
        if (final_size < self.highest_off) return error.FinalSizeError;
        self.fin_off = final_size;
        self.state = .ResetRead;
    }

    /// Refresh the explicit receive state from offset/final-size bookkeeping.
    pub fn refreshState(self: *StreamRx) void {
        if (self.state == .ResetRead) return;
        if (self.fin_off) |f| {
            self.state = if (self.recv_off >= f and self.available() == 0) .DataRead else .SizeKnown;
        } else {
            self.state = .Recv;
        }
    }

    /// Index of the first buffered segment starting at or after `off`.
    /// `bufs` is kept sorted by offset.
    fn segmentLowerBound(self: *StreamRx, off: u64) usize {
        var lo: usize = 0;
        var hi: usize = self.bufs.items.len;
        while (lo < hi) {
            self.reassembly_steps +%= 1;
            const mid = lo + (hi - lo) / 2;
            if (self.bufs.items[mid].off < off) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Buffer a data segment for reassembly, keeping `bufs` sorted by
    /// offset. Bytes already delivered are dropped and an exact
    /// retransmission of a buffered segment is ignored. Data that starts
    /// where the preceding segment ends is appended to it (SONNY-6649): a
    /// run of contiguous data is one segment however many STREAM frames
    /// carried it, so the segment count bounds the gaps (holes) in the
    /// received data, not the frames, and a sender of small frames behind
    /// one lost packet stays at one segment.
    ///
    /// SONNY-6475: segments used to be appended and the whole list sorted
    /// and walked on every received packet. After one early loss in a large
    /// window (thousands of segments buffered behind the hole) each packet
    /// cost a full sort, the receiver fell behind, its socket overflowed, and
    /// a transfer beyond the initial window slowed to a crawl. Insertion is
    /// now a binary search and draining touches only the contiguous prefix.
    pub fn insert(self: *StreamRx, alloc: *std.mem.Allocator, off: u64, data: []const u8) void {
        if (self.state == .ResetRead or self.state == .DataRead) return;
        var seg_off = off;
        var bytes = data;
        if (seg_off < self.recv_off) {
            const delivered = self.recv_off - seg_off;
            if (delivered >= bytes.len) return;
            bytes = bytes[@intCast(delivered)..];
            seg_off = self.recv_off;
        }
        if (bytes.len == 0) return;
        var at = self.segmentLowerBound(seg_off);
        // Bytes the preceding segment already holds are not buffered twice
        // (a retransmission into a coalesced run, SONNY-6649): drop them, and
        // the rest, if any, starts where that segment ends.
        if (at > 0) {
            const prev = self.bufs.items[at - 1];
            const prev_end = prev.off + @as(u64, prev.data.len);
            if (prev_end > seg_off) {
                const covered = prev_end - seg_off;
                if (covered >= bytes.len) return;
                bytes = bytes[@intCast(covered)..];
                seg_off = prev_end;
                at = self.segmentLowerBound(seg_off);
            }
        }
        if (at < self.bufs.items.len) {
            const next = self.bufs.items[at];
            if (next.off == seg_off and next.data.len >= bytes.len) return;
        }
        if (at > 0) {
            const prev = &self.bufs.items[at - 1];
            if (prev.off + @as(u64, prev.data.len) == seg_off) {
                if (appendToSegment(alloc.*, prev, bytes)) {
                    self.buffered_bytes += bytes.len;
                    return;
                } else |_| {}
            }
        }
        // store a copy of segment
        const owned = alloc.alloc(u8, bytes.len) catch return;
        @memcpy(owned, bytes);
        self.bufs.insert(alloc.*, at, .{ .off = seg_off, .data = owned }) catch {
            alloc.free(owned);
            return;
        };
        self.buffered_bytes += bytes.len;
    }

    /// Append `bytes` to `seg` in place, growing its allocation by at least
    /// its current size (at most 1 MiB at a time), so that a run built from
    /// many small frames costs amortized O(bytes).
    fn appendToSegment(alloc: std.mem.Allocator, seg: *Segment, bytes: []const u8) !void {
        const used = seg.data.len;
        const cap = seg.allocation().len;
        if (used + bytes.len > cap) {
            const step = @max(bytes.len, @min(@max(cap, 1024), 1 << 20));
            const grown = try alloc.realloc(seg.allocation(), used + step);
            seg.data = grown[0..used];
            seg.cap = grown.len;
        }
        @memcpy(seg.data.ptr[used .. used + bytes.len], bytes);
        seg.data = seg.data.ptr[0 .. used + bytes.len];
    }

    /// Try to drain contiguous segments into the inbox. Only the sorted
    /// prefix that starts at or before `recv_off` is examined; overlapping
    /// segments contribute just their bytes past `recv_off`.
    pub fn tryDrain(self: *StreamRx, alloc: *std.mem.Allocator) void {
        var consumed: usize = 0;
        for (self.bufs.items) |seg| {
            self.reassembly_steps +%= 1;
            if (seg.off > self.recv_off) break;
            const seg_end = seg.off + @as(u64, seg.data.len);
            if (seg_end > self.recv_off) {
                const fresh = seg.data[@intCast(self.recv_off - seg.off)..];
                self.inbox.appendSlice(alloc.*, fresh) catch |err| {
                    logger.err("stream inbox appendSlice failed (OOM): {s}", .{@errorName(err)});
                    break;
                };
                self.recv_off = seg_end;
            }
            self.buffered_bytes -|= seg.data.len;
            freeSegment(alloc.*, seg);
            consumed += 1;
        }
        if (consumed > 0) {
            const items = self.bufs.items;
            std.mem.copyForwards(Segment, items[0 .. items.len - consumed], items[consumed..]);
            self.bufs.items.len -= consumed;
        }
        self.refreshState();
    }

    /// Check if stream is finished (FIN received and all data delivered).
    pub fn isFinished(self: *const StreamRx) bool {
        if (self.state.terminal()) return true;
        return if (self.fin_off) |f| self.recv_off >= f else false;
    }
};

/// Stream transmit state - tracks send offset and FIN flag.
/// RFC 9000 §3: Stream States
pub const StreamTx = struct {
    state: SendState = .Ready,
    off: u64 = 0,
    fin_sent: bool = false,
    aborted: bool = false,
    // PHASE 42 PART 10: Per-stream send-side flow control (RFC 9000 §4.2)
    peer_max_stream_data: u64 = 0, // Peer's receive window limit for this stream
    /// Packets carrying this stream's STREAM frames that are tracked for
    /// retransmission and not yet acknowledged. With the FIN sent, zero means
    /// the peer has everything: RFC 9000 §3.1 "Data Recvd" (SONNY-6478).
    retx_outstanding: u32 = 0,

    /// RFC 9000 §3.1: the send side needs no more state once all data and
    /// the FIN are acknowledged ("Data Recvd") or the stream was reset.
    /// RESET_STREAM is not tracked for acknowledgement, so "Reset Sent"
    /// counts as terminal.
    pub fn sendTerminal(self: *const StreamTx) bool {
        if (self.aborted) return true;
        return self.fin_sent and self.retx_outstanding == 0;
    }

    pub fn canWrite(self: *const StreamTx) !void {
        if (!self.state.canWrite()) return error.StreamStopped;
        if (self.fin_sent or self.aborted) return error.StreamStopped;
    }

    pub fn recordDataSent(self: *StreamTx, bytes: u64, fin: bool) !void {
        try self.canWrite();
        self.off +%= bytes;
        if (fin) {
            self.fin_sent = true;
            self.state = .DataSent;
        } else if (bytes > 0) {
            self.state = .Send;
        }
    }

    pub fn recordFinSent(self: *StreamTx) !void {
        try self.canWrite();
        self.fin_sent = true;
        self.state = .DataSent;
    }

    pub fn recordResetSent(self: *StreamTx) !void {
        try self.canWrite();
        self.aborted = true;
        self.state = .ResetSent;
    }
};
