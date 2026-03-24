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

/// Stream receive state - handles out-of-order delivery and reassembly.
/// RFC 9000 §3: Stream States
pub const StreamRx = struct {
    recv_off: u64 = 0,
    inbox: std.ArrayList(u8),
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
            .inbox = std.ArrayList(u8){},
            .bufs = std.ArrayList(Segment){},
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
        // Single forward pass using swapRemove to avoid O(n^2) shifting.
        // Repeat until no progress is made (handles out-of-order segments
        // that become contiguous after earlier drains).
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < self.bufs.items.len) {
                const seg = self.bufs.items[i];
                if (seg.off == self.recv_off) {
                    // append to inbox and advance
                    _ = self.inbox.appendSlice(alloc.*, seg.data) catch |err| {
                        logger.err("stream inbox appendSlice failed (OOM): {s}", .{@errorName(err)});
                    };
                    self.recv_off +%= seg.data.len;
                    alloc.free(seg.data);
                    _ = self.bufs.swapRemove(i);
                    progressed = true;
                    // Don't increment i; swapRemove moved the last element here
                } else if (seg.off < self.recv_off) {
                    // Overlapping or duplicate segment already consumed; discard
                    alloc.free(seg.data);
                    _ = self.bufs.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
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
