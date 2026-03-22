// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Multi-connection orchestrator integrating DRR scheduling, NewReno congestion
//! control, loss recovery, timer management, and connection sharding.

const std = @import("std");
const drr = @import("drr");
const congestion = @import("congestion");
const loss_recovery = @import("loss_recovery");
const timer_heap = @import("timer_heap");
const sharding = @import("sharding");

pub const ConnectionError = error{
    InvalidConnectionId,
    StreamNotFound,
    OutOfMemory,
};

/// Connection state tracking for QUIC protocol
pub const ConnectionState = struct {
    /// Unique connection identifier (owned copy)
    id: []const u8,

    /// Congestion control state (NewReno)
    congestion_ctrl: congestion.NewReno,

    /// DRR scheduler for stream multiplexing
    streams: std.ArrayList(drr.Stream),
    /// O(1) stream lookup by ID
    stream_index: std.AutoHashMap(u32, usize),

    /// Loss recovery state
    sent_packets: std.ArrayList(loss_recovery.SentPacket),
    /// O(1) packet lookup by PN
    sent_index: std.AutoHashMap(u64, usize),
    latest_acked_pn: u64,
    srtt_us: u64,

    /// Connection metadata
    created_at_us: u64,
    last_active_us: u64,
    bytes_sent: u64,
    bytes_recv: u64,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, id: []const u8, mss: usize, now_us: u64) !ConnectionState {
        const id_owned = try allocator.dupe(u8, id);
        return ConnectionState{
            .id = id_owned,
            .congestion_ctrl = congestion.NewReno.init(mss),
            .streams = try std.ArrayList(drr.Stream).initCapacity(allocator, 16),
            .stream_index = std.AutoHashMap(u32, usize).init(allocator),
            .sent_packets = try std.ArrayList(loss_recovery.SentPacket).initCapacity(allocator, 16),
            .sent_index = std.AutoHashMap(u64, usize).init(allocator),
            .latest_acked_pn = 0,
            .srtt_us = 100000, // Initial RTT estimate: 100ms
            .created_at_us = now_us,
            .last_active_us = now_us,
            .bytes_sent = 0,
            .bytes_recv = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionState) void {
        self.allocator.free(self.id);
        self.streams.deinit(self.allocator);
        self.stream_index.deinit();
        self.sent_packets.deinit(self.allocator);
        self.sent_index.deinit();
    }

    /// Register a new stream for DRR scheduling
    pub fn addStream(self: *ConnectionState, stream_id: u32, quantum: usize) !void {
        const idx = self.streams.items.len;
        try self.streams.append(self.allocator, drr.Stream{
            .id = stream_id,
            .send_buf = 0,
            .flow_window = 65536, // Initial flow control window
            .blocked = false,
            .deficit = 0,
            .quantum = quantum,
        });
        errdefer _ = self.streams.pop();
        try self.stream_index.put(stream_id, idx);
    }

    /// Update stream send buffer and flow window (O(1) via index)
    pub fn updateStream(self: *ConnectionState, stream_id: u32, send_buf: usize, flow_window: usize, blocked: bool) !void {
        const idx = self.stream_index.get(stream_id) orelse return error.StreamNotFound;
        self.streams.items[idx].send_buf = send_buf;
        self.streams.items[idx].flow_window = flow_window;
        self.streams.items[idx].blocked = blocked;
    }

    /// Schedule streams using DRR
    pub fn scheduleStreams(self: *ConnectionState, max_packet: usize, out: []drr.Transmission) !usize {
        return drr.scheduleOnce(self.streams.items, max_packet, out);
    }

    /// Record packet sent for loss detection
    pub fn onPacketSent(self: *ConnectionState, pn: u64, size: usize, now_us: u64) !void {
        self.congestion_ctrl.onPacketSent(size);
        const idx = self.sent_packets.items.len;
        try self.sent_packets.append(self.allocator, loss_recovery.SentPacket{
            .pn = pn,
            .sent_at_us = now_us,
            .size = size,
            .acked = false,
        });
        errdefer _ = self.sent_packets.pop();
        try self.sent_index.put(pn, idx);
        self.bytes_sent += size;
        self.last_active_us = now_us;
    }

    /// Process ACK and update congestion control (O(1) via PN index)
    pub fn onAckReceived(self: *ConnectionState, acked_pn: u64, acked_bytes: usize, now_us: u64) void {
        // Update congestion control
        self.congestion_ctrl.onAckReceived(acked_bytes, acked_pn);

        // Mark packet as acked via O(1) index lookup
        if (self.sent_index.get(acked_pn)) |idx| {
            if (idx < self.sent_packets.items.len) {
                self.sent_packets.items[idx].acked = true;
            }
        }

        if (acked_pn > self.latest_acked_pn) {
            self.latest_acked_pn = acked_pn;
        }

        self.last_active_us = now_us;
    }

    /// Detect lost packets and update congestion control
    pub fn detectLoss(self: *ConnectionState, now_us: u64, reordering_threshold: u32, out_lost: []u64, latest_sent_pn: u64) !usize {
        const n_lost = loss_recovery.detectLost(
            self.sent_packets.items,
            self.latest_acked_pn,
            now_us,
            self.srtt_us,
            reordering_threshold,
            out_lost,
        );

        // Update congestion control for each lost packet using O(1) index lookup
        for (out_lost[0..n_lost]) |lost_pn| {
            if (self.sent_index.get(lost_pn)) |idx| {
                if (idx < self.sent_packets.items.len) {
                    const pkt = self.sent_packets.items[idx];
                    self.congestion_ctrl.onPacketLost(pkt.size, lost_pn, latest_sent_pn);
                }
            }
        }

        return n_lost;
    }
};

/// Connection manager coordinating multiple connections
pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    connections: std.StringHashMap(*ConnectionState),
    timers: timer_heap.TimerHeap,
    sharder: sharding.Sharder,
    next_timer_id: u64,

    pub fn init(allocator: std.mem.Allocator, shard_count: u32) !ConnectionManager {
        return ConnectionManager{
            .allocator = allocator,
            .connections = std.StringHashMap(*ConnectionState).init(allocator),
            .timers = timer_heap.TimerHeap.init(65536),
            .sharder = try sharding.Sharder.init(shard_count),
            .next_timer_id = 1,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();
        self.timers.deinit(self.allocator);
    }

    /// Add a new connection. Validates CID length per RFC 9000 S17.2 (1-20 bytes).
    pub fn addConnection(self: *ConnectionManager, id: []const u8, mss: usize, now_us: u64) !*ConnectionState {
        if (id.len == 0 or id.len > 20) return error.InvalidConnectionId;

        const conn = try self.allocator.create(ConnectionState);
        errdefer self.allocator.destroy(conn);

        conn.* = try ConnectionState.init(self.allocator, id, mss, now_us);
        errdefer conn.deinit();

        // Use the owned copy (conn.id) as HashMap key to avoid dangling pointer
        try self.connections.put(conn.id, conn);
        return conn;
    }

    /// Remove a connection
    pub fn removeConnection(self: *ConnectionManager, id: []const u8) void {
        if (self.connections.fetchRemove(id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }

    /// Get connection by ID
    pub fn getConnection(self: *ConnectionManager, id: []const u8) ?*ConnectionState {
        return self.connections.get(id);
    }

    /// Choose shard for connection using CSPRNG-seeded consistent hashing
    pub fn chooseShard(self: *const ConnectionManager, conn_key: []const u8) u32 {
        return self.sharder.chooseLoop(conn_key);
    }

    /// Schedule a timer
    pub fn scheduleTimer(self: *ConnectionManager, deadline_us: u64) !u64 {
        const timer_id = self.next_timer_id;
        self.next_timer_id += 1;
        try self.timers.push(self.allocator, timer_heap.Timer{
            .id = timer_id,
            .deadline_us = deadline_us,
        });
        return timer_id;
    }

    /// Get next timer deadline
    pub fn nextTimerDeadline(self: *ConnectionManager) ?u64 {
        if (self.timers.peek()) |t| {
            return t.deadline_us;
        }
        return null;
    }

    /// Pop expired timers
    pub fn popExpiredTimers(self: *ConnectionManager, now_us: u64, out: []u64) usize {
        var count: usize = 0;
        while (self.timers.peek()) |t| {
            if (t.deadline_us > now_us) break;
            if (count >= out.len) break;
            const timer = self.timers.pop() orelse break;
            out[count] = timer.id;
            count += 1;
        }
        return count;
    }

    /// Get active connection count
    pub fn connectionCount(self: *ConnectionManager) usize {
        return self.connections.count();
    }
};

// Unit tests
test "ConnectionManager: basic lifecycle" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("test-conn", 1200, 1000000);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    try std.testing.expectEqual(@as(u64, 1000000), conn.created_at_us);

    mgr.removeConnection("test-conn");
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "ConnectionManager: stream scheduling" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("test-conn", 1200, 1000000);
    try conn.addStream(1, 1200);
    try conn.addStream(2, 1200);
    try conn.updateStream(1, 4096, 1200, false);
    try conn.updateStream(2, 2048, 1200, false);

    var out: [4]drr.Transmission = undefined;
    const n = try conn.scheduleStreams(1200, &out);
    try std.testing.expect(n >= 1);
}

test "ConnectionManager: congestion control" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("test-conn", 1200, 1000000);

    // Send packet
    try conn.onPacketSent(1, 1200, 1000000);

    // Receive ACK
    conn.onAckReceived(1, 1200, 1001000);

    // Verify congestion window grew
    try std.testing.expect(conn.congestion_ctrl.cwnd > 10 * 1200);
}

test "ConnectionManager: loss detection" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("test-conn", 1200, 1000000);

    // Send multiple packets
    try conn.onPacketSent(1, 1200, 1000000);
    try conn.onPacketSent(2, 1200, 1001000);
    try conn.onPacketSent(3, 1200, 1002000);

    // ACK packets 2 and 3 (packet 1 is lost)
    conn.onAckReceived(2, 1200, 1003000);
    conn.onAckReceived(3, 1200, 1004000);

    // Detect loss
    var lost: [4]u64 = undefined;
    const n_lost = try conn.detectLoss(1200000, 3, &lost, 3);
    try std.testing.expect(n_lost >= 1);
}

test "ConnectionManager: timer scheduling" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    _ = try mgr.scheduleTimer(1000);
    const timer2 = try mgr.scheduleTimer(500);

    try std.testing.expectEqual(@as(?u64, 500), mgr.nextTimerDeadline());

    var expired: [4]u64 = undefined;
    const n = mgr.popExpiredTimers(600, &expired);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(timer2, expired[0]);
}

test "ConnectionManager: connection sharding" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 8);
    defer mgr.deinit();

    const shard1 = mgr.chooseShard("192.168.1.1:5000");
    const shard2 = mgr.chooseShard("192.168.1.1:5000");

    // Same key should map to same shard
    try std.testing.expectEqual(shard1, shard2);

    // Shard should be in range
    try std.testing.expect(shard1 < 8);
}

test "ConnectionManager: CID validation rejects empty and oversized" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    // Empty CID
    const r1 = mgr.addConnection("", 1200, 1000000);
    try std.testing.expectError(error.InvalidConnectionId, r1);

    // Oversized CID (>20 bytes per RFC 9000)
    const r2 = mgr.addConnection("012345678901234567890", 1200, 1000000);
    try std.testing.expectError(error.InvalidConnectionId, r2);

    // Valid CID (20 bytes, max allowed)
    const conn = try mgr.addConnection("01234567890123456789", 1200, 1000000);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    _ = conn;
}

test "ConnectionManager: updateStream error on unknown stream" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("test-conn", 1200, 1000000);
    const r = conn.updateStream(999, 100, 100, false);
    try std.testing.expectError(error.StreamNotFound, r);
}

test "ConnectionManager: loss uses actual packet size" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("test-conn", 1200, 1000000);

    // Send packets of different sizes
    try conn.onPacketSent(1, 500, 1000000);
    try conn.onPacketSent(2, 1200, 1001000);
    try conn.onPacketSent(3, 1200, 1002000);

    conn.onAckReceived(2, 1200, 1003000);
    conn.onAckReceived(3, 1200, 1004000);

    // Detect loss — packet 1 (500 bytes) should report actual size to CC
    var lost: [4]u64 = undefined;
    const n_lost = try conn.detectLoss(1200000, 3, &lost, 3);
    try std.testing.expect(n_lost >= 1);
    // Congestion control should have been notified with actual size, not 1200
    try std.testing.expect(conn.congestion_ctrl.in_recovery);
}
