// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Timer management for endpoint scheduling.
//!
//! RFC 9002 §6.2: Probe Timeout (PTO)
//! RFC 9000 §14.2: Path MTU Discovery timers

const std = @import("std");
const types = @import("types");

/// Timer management state for the endpoint.
/// Maintains a min-heap of timers sorted by deadline.
pub const TimerManager = struct {
    timers: std.ArrayList(types.Timer),
    allocator: std.mem.Allocator,
    next_timer_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) TimerManager {
        return .{
            .timers = std.ArrayList(types.Timer){},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TimerManager) void {
        // Free any paced payloads
        for (self.timers.items) |t| {
            if (t.paced and t.payload != null) {
                // Payload cleanup handled by caller
            }
        }
        self.timers.deinit(self.allocator);
    }

    /// Schedule a new timer and return its ID.
    pub fn schedule(self: *TimerManager, delay_ms: u32, kind: types.TimerKind, conn: ?*anyopaque) !u64 {
        const now = nowMsMonotonic();
        const deadline = now + @as(i64, delay_ms);
        const id = self.next_timer_id;
        self.next_timer_id += 1;

        try self.timers.append(self.allocator, .{
            .deadline_ms = deadline,
            .id = id,
            .kind = kind,
            .conn = @ptrCast(@alignCast(conn)),
        });

        // Maintain heap property
        self.bubbleUp(self.timers.items.len - 1);
        return id;
    }

    /// Cancel a timer by ID.
    pub fn cancel(self: *TimerManager, id: u64) bool {
        var idx: usize = 0;
        while (idx < self.timers.items.len) : (idx += 1) {
            if (self.timers.items[idx].id == id) {
                _ = self.timers.swapRemove(idx);
                if (idx < self.timers.items.len) {
                    self.heapify(idx);
                }
                return true;
            }
        }
        return false;
    }

    /// Get the next timer expiry time, or null if no timers.
    pub fn nextDeadline(self: *const TimerManager) ?i64 {
        if (self.timers.items.len == 0) return null;
        return self.timers.items[0].deadline_ms;
    }

    /// Flush expired timers and return them.
    pub fn flush(self: *TimerManager, allocator: std.mem.Allocator) !std.ArrayList(types.Timer) {
        const now = nowMsMonotonic();
        var expired = std.ArrayList(types.Timer){};

        while (self.timers.items.len > 0 and self.timers.items[0].deadline_ms <= now) {
            try expired.append(allocator, self.timers.items[0]);
            _ = self.timers.swapRemove(0);
            if (self.timers.items.len > 0) {
                self.heapify(0);
            }
        }

        return expired;
    }

    fn bubbleUp(self: *TimerManager, idx: usize) void {
        if (idx == 0) return;
        const parent = (idx - 1) / 2;
        if (self.timers.items[idx].deadline_ms < self.timers.items[parent].deadline_ms) {
            std.mem.swap(types.Timer, &self.timers.items[idx], &self.timers.items[parent]);
            self.bubbleUp(parent);
        }
    }

    fn heapify(self: *TimerManager, idx: usize) void {
        const len = self.timers.items.len;
        const left = 2 * idx + 1;
        const right = 2 * idx + 2;
        var smallest = idx;

        if (left < len and self.timers.items[left].deadline_ms < self.timers.items[smallest].deadline_ms) {
            smallest = left;
        }
        if (right < len and self.timers.items[right].deadline_ms < self.timers.items[smallest].deadline_ms) {
            smallest = right;
        }
        if (smallest != idx) {
            std.mem.swap(types.Timer, &self.timers.items[idx], &self.timers.items[smallest]);
            self.heapify(smallest);
        }
    }
};

fn nowMsMonotonic() i64 {
    const ns: i128 = std.time.nanoTimestamp();
    const ms: i128 = @divTrunc(ns, std.time.ns_per_ms);
    return @as(i64, @intCast(ms));
}
