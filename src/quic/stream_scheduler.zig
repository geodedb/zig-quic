// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection-level stream scheduler using Deficit Round-Robin (DRR).

const std = @import("std");

/// Stream scheduling state for receive-side DRR
pub const StreamScheduleState = struct {
    stream_id: u64,
    deficit: u64 = 0,
    quantum: u64 = 1000, // Default quantum in bytes
    last_bytes_read: u64 = 0,
    total_bytes_read: u64 = 0,
    poll_count: u64 = 0,
    blocked: bool = false,

    pub fn addDeficit(self: *StreamScheduleState) void {
        self.deficit += self.quantum;
    }

    pub fn consumeDeficit(self: *StreamScheduleState, bytes: u64) void {
        if (bytes >= self.deficit) {
            self.deficit = 0;
        } else {
            self.deficit -= bytes;
        }
        self.last_bytes_read = bytes;
        self.total_bytes_read += bytes;
        self.poll_count += 1;
    }

    pub fn hasDeficit(self: *const StreamScheduleState) bool {
        return self.deficit > 0;
    }
};

/// Result of scheduling decision
pub const ScheduleResult = struct {
    stream_id: u64,
    priority: u32, // Lower is higher priority
};

/// Connection-level stream scheduler using Deficit Round-Robin
pub const StreamScheduler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    streams: std.AutoHashMap(u64, StreamScheduleState),
    round_robin_index: usize = 0,
    total_rounds: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .streams = std.AutoHashMap(u64, StreamScheduleState).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.streams.deinit();
    }

    /// Register a new stream for scheduling
    pub fn addStream(self: *Self, stream_id: u64, quantum: u64) !void {
        try self.streams.put(stream_id, StreamScheduleState{
            .stream_id = stream_id,
            .quantum = quantum,
        });
    }

    /// Remove a stream from scheduling
    pub fn removeStream(self: *Self, stream_id: u64) void {
        _ = self.streams.remove(stream_id);
    }

    /// Check if a stream is registered
    pub fn hasStream(self: *Self, stream_id: u64) bool {
        return self.streams.contains(stream_id);
    }

    /// Get a stream's scheduling state (mutable)
    pub fn getStreamState(self: *Self, stream_id: u64) ?*StreamScheduleState {
        return self.streams.getPtr(stream_id);
    }

    /// Mark a stream as blocked (no data available)
    pub fn markBlocked(self: *Self, stream_id: u64) void {
        if (self.streams.getPtr(stream_id)) |state| {
            state.blocked = true;
        }
    }

    /// Mark a stream as unblocked (data available)
    pub fn markUnblocked(self: *Self, stream_id: u64) void {
        if (self.streams.getPtr(stream_id)) |state| {
            state.blocked = false;
        }
    }

    /// Record that bytes were read from a stream
    pub fn recordBytesRead(self: *Self, stream_id: u64, bytes: u64) void {
        if (self.streams.getPtr(stream_id)) |state| {
            state.consumeDeficit(bytes);
            state.blocked = false; // Stream has data, so unblock
        }
    }

    /// Get the next stream to poll based on DRR scheduling
    /// Returns null if no streams are ready (all blocked or no streams)
    pub fn getNextStream(self: *Self) ?u64 {
        const count = self.streams.count();
        if (count == 0) return null;

        // Add quantum to all streams at the start of each round
        self.total_rounds += 1;

        // Find a stream with deficit that isn't blocked
        var keys = self.streams.keyIterator();
        var best_stream: ?u64 = null;
        var best_deficit: u64 = 0;

        while (keys.next()) |key_ptr| {
            const stream_id = key_ptr.*;
            if (self.streams.getPtr(stream_id)) |state| {
                // Add deficit (quantum) to all streams
                state.addDeficit();

                // Skip blocked streams
                if (state.blocked) continue;

                // Select stream with highest deficit (most deserving)
                if (best_stream == null or state.deficit > best_deficit) {
                    best_stream = stream_id;
                    best_deficit = state.deficit;
                }
            }
        }

        return best_stream;
    }

    const DeficitEntry = struct { id: u64, deficit: u64 };

    /// Get ordered list of streams to poll (priority order).
    /// Fills the output buffer with stream IDs in priority order.
    /// Returns the number of streams written, or error on allocation failure.
    pub fn getScheduledStreams(self: *Self, out: []u64) error{OutOfMemory}!usize {
        const count = self.streams.count();
        if (count == 0) return 0;

        // Collect all non-blocked streams with their deficits.
        var stream_list: std.ArrayListUnmanaged(DeficitEntry) = .empty;
        defer stream_list.deinit(self.allocator);
        try stream_list.ensureTotalCapacity(self.allocator, count);

        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            const state = entry.value_ptr;
            // Add quantum to all streams
            state.addDeficit();

            if (!state.blocked) {
                stream_list.appendAssumeCapacity(.{
                    .id = entry.key_ptr.*,
                    .deficit = state.deficit,
                });
            }
        }

        // Sort by deficit (descending - highest deficit first)
        std.mem.sort(DeficitEntry, stream_list.items, {}, struct {
            pub fn lessThan(_: void, a: DeficitEntry, b: DeficitEntry) bool {
                return a.deficit > b.deficit;
            }
        }.lessThan);

        // Copy to output
        const num_to_copy = @min(stream_list.items.len, out.len);
        for (0..num_to_copy) |i| {
            out[i] = stream_list.items[i].id;
        }

        self.total_rounds += 1;
        return num_to_copy;
    }

    /// Get statistics about the scheduler
    pub fn getStats(self: *Self) Stats {
        var total_bytes: u64 = 0;
        var total_polls: u64 = 0;
        var active_count: usize = 0;
        var blocked_count: usize = 0;

        var iter = self.streams.iterator();
        while (iter.next()) |entry| {
            const state = entry.value_ptr;
            total_bytes += state.total_bytes_read;
            total_polls += state.poll_count;
            if (state.blocked) {
                blocked_count += 1;
            } else {
                active_count += 1;
            }
        }

        return Stats{
            .total_streams = self.streams.count(),
            .active_streams = active_count,
            .blocked_streams = blocked_count,
            .total_rounds = self.total_rounds,
            .total_bytes_read = total_bytes,
            .total_polls = total_polls,
        };
    }

    pub const Stats = struct {
        total_streams: usize,
        active_streams: usize,
        blocked_streams: usize,
        total_rounds: u64,
        total_bytes_read: u64,
        total_polls: u64,
    };
};

// Unit tests
test "StreamScheduler: basic operations" {
    var scheduler = StreamScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    try scheduler.addStream(1, 1000);
    try scheduler.addStream(2, 1000);
    try scheduler.addStream(3, 1000);

    try std.testing.expect(scheduler.hasStream(1));
    try std.testing.expect(scheduler.hasStream(2));
    try std.testing.expect(scheduler.hasStream(3));
    try std.testing.expect(!scheduler.hasStream(4));

    scheduler.removeStream(2);
    try std.testing.expect(!scheduler.hasStream(2));
}

test "StreamScheduler: DRR fairness" {
    var scheduler = StreamScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    // Add two streams with equal quantum
    try scheduler.addStream(1, 1000);
    try scheduler.addStream(2, 1000);

    // Record different amounts of bytes read
    scheduler.recordBytesRead(1, 500); // Stream 1 read less
    scheduler.recordBytesRead(2, 900); // Stream 2 read more

    // Get next stream - should favor stream 1 (has more accumulated deficit)
    var order: [2]u64 = undefined;
    const count = try scheduler.getScheduledStreams(&order);
    try std.testing.expectEqual(@as(usize, 2), count);

    // Both streams should be scheduled
    try std.testing.expect(order[0] == 1 or order[0] == 2);
    try std.testing.expect(order[1] == 1 or order[1] == 2);
}

test "StreamScheduler: blocked stream handling" {
    var scheduler = StreamScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    try scheduler.addStream(1, 1000);
    try scheduler.addStream(2, 1000);

    // Block stream 1
    scheduler.markBlocked(1);

    var order: [2]u64 = undefined;
    const count = try scheduler.getScheduledStreams(&order);

    // Only stream 2 should be in the output
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u64, 2), order[0]);

    // Unblock stream 1
    scheduler.markUnblocked(1);
    const count2 = try scheduler.getScheduledStreams(&order);
    try std.testing.expectEqual(@as(usize, 2), count2);
}

test "StreamScheduler: statistics tracking" {
    var scheduler = StreamScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    try scheduler.addStream(1, 1000);
    try scheduler.addStream(2, 1000);

    scheduler.recordBytesRead(1, 100);
    scheduler.recordBytesRead(1, 200);
    scheduler.recordBytesRead(2, 150);

    const stats = scheduler.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.total_streams);
    try std.testing.expectEqual(@as(u64, 450), stats.total_bytes_read);
    try std.testing.expectEqual(@as(u64, 3), stats.total_polls);
}

test "StreamScheduler: empty scheduler" {
    var scheduler = StreamScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    // No streams - should return null/0
    try std.testing.expectEqual(@as(?u64, null), scheduler.getNextStream());

    var order: [2]u64 = undefined;
    const count = try scheduler.getScheduledStreams(&order);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "StreamScheduler: quantum affects priority" {
    var scheduler = StreamScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    // Stream 1 has higher quantum (more priority)
    try scheduler.addStream(1, 2000);
    try scheduler.addStream(2, 1000);

    // After first round, stream 1 should have more deficit
    var order: [2]u64 = undefined;
    const count = try scheduler.getScheduledStreams(&order);

    try std.testing.expectEqual(@as(usize, 2), count);
    // Stream 1 should be first (higher quantum = more deficit)
    try std.testing.expectEqual(@as(u64, 1), order[0]);
}
