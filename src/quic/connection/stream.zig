// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Stream management for QUIC connections.
//!
//! RFC 9000 §2: Streams (bidirectional and unidirectional)
//! RFC 9000 §3: Stream States
//! RFC 9000 §4: Flow Control

const std = @import("std");
const logger = @import("quic_logger");

/// Data segment for stream reassembly.
pub const Segment = struct {
    off: u64,
    data: []u8,
};

fn segmentLessThan(_: void, lhs: Segment, rhs: Segment) bool {
    return lhs.off < rhs.off;
}

/// Stream receive state - handles out-of-order delivery and reassembly.
/// RFC 9000 §3: Stream States
pub const StreamRx = struct {
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

    pub fn init() StreamRx {
        return .{
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
        };
    }

    pub fn deinit(self: *StreamRx, alloc: *std.mem.Allocator) void {
        for (self.bufs.items) |seg| alloc.free(seg.data);
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

        return n;
    }

    /// Insert a data segment for potential reassembly.
    pub fn insert(self: *StreamRx, alloc: *std.mem.Allocator, off: u64, data: []const u8) void {
        // store a copy of segment
        const owned = alloc.alloc(u8, data.len) catch return;
        @memcpy(owned, data);
        self.bufs.append(alloc.*, .{ .off = off, .data = owned }) catch {
            alloc.free(owned);
            return;
        };
    }

    /// Try to drain contiguous segments into the inbox.
    pub fn tryDrain(self: *StreamRx, alloc: *std.mem.Allocator) void {
        if (self.bufs.items.len > 1) {
            std.mem.sort(Segment, self.bufs.items, {}, segmentLessThan);
        }

        var write_i: usize = 0;
        for (self.bufs.items) |seg| {
            if (seg.off < self.recv_off) {
                alloc.free(seg.data);
            } else if (seg.off == self.recv_off) {
                self.inbox.appendSlice(alloc.*, seg.data) catch |err| {
                    logger.err("stream inbox appendSlice failed (OOM): {s}", .{@errorName(err)});
                    self.bufs.items[write_i] = seg;
                    write_i += 1;
                    continue;
                };
                self.recv_off +%= seg.data.len;
                alloc.free(seg.data);
            } else {
                self.bufs.items[write_i] = seg;
                write_i += 1;
            }
        }
        self.bufs.items.len = write_i;
    }

    /// Check if stream is finished (FIN received and all data delivered).
    pub fn isFinished(self: *const StreamRx) bool {
        return if (self.fin_off) |f| self.recv_off >= f else false;
    }
};

/// Stream transmit state - tracks send offset and FIN flag.
/// RFC 9000 §3: Stream States
pub const StreamTx = struct {
    off: u64 = 0,
    fin_sent: bool = false,
    aborted: bool = false,
    // PHASE 42 PART 10: Per-stream send-side flow control (RFC 9000 §4.2)
    peer_max_stream_data: u64 = 0, // Peer's receive window limit for this stream
};
