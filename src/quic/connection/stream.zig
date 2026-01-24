// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Stream management for QUIC connections.
//!
//! RFC 9000 §2: Streams (bidirectional and unidirectional)
//! RFC 9000 §3: Stream States
//! RFC 9000 §4: Flow Control

const std = @import("std");

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

    pub fn init() StreamRx {
        return .{
            .recv_off = 0,
            .inbox = std.ArrayList(u8){},
            .bufs = std.ArrayList(Segment){},
            .fin_off = null,
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
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < self.bufs.items.len) {
                const seg = self.bufs.items[i];
                if (seg.off == self.recv_off) {
                    // append to inbox and advance
                    _ = self.inbox.appendSlice(alloc.*, seg.data) catch {};
                    self.recv_off +%= seg.data.len;
                    alloc.free(seg.data);
                    _ = self.bufs.orderedRemove(i);
                    progressed = true;
                    // restart scan
                    i = 0;
                    continue;
                }
                i += 1;
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
};
