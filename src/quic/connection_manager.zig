const std = @import("std");
const drr = @import("drr");
const congestion = @import("congestion");
const loss_recovery = @import("loss_recovery");
const timer_heap = @import("timer_heap");
const sharding = @import("sharding");

/// Connection state tracking for QUIC protocol
pub const ConnectionState = struct {
    /// Unique connection identifier (5-tuple or CID)
    id: []const u8,

    /// Congestion control state (NewReno)
    congestion_ctrl: congestion.NewReno,

    /// DRR scheduler for stream multiplexing
    streams: std.ArrayList(drr.Stream),

    /// Loss recovery state
    sent_packets: std.ArrayList(loss_recovery.SentPacket),
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
            .streams = try std.ArrayList(drr.Stream).initCapacity(allocator, 0),
            .sent_packets = try std.ArrayList(loss_recovery.SentPacket).initCapacity(allocator, 0),
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
        self.sent_packets.deinit(self.allocator);
    }

    /// Register a new stream for DRR scheduling
    pub fn addStream(self: *ConnectionState, stream_id: u32, quantum: usize) !void {
        try self.streams.append(self.allocator, drr.Stream{
            .id = stream_id,
            .send_buf = 0,
            .flow_window = 65536, // Initial flow control window
            .blocked = false,
            .deficit = 0,
            .quantum = quantum,
        });
    }

    /// Update stream send buffer and flow window
    pub fn updateStream(self: *ConnectionState, stream_id: u32, send_buf: usize, flow_window: usize, blocked: bool) !void {
        for (self.streams.items) |*stream| {
            if (stream.id == stream_id) {
                stream.send_buf = send_buf;
                stream.flow_window = flow_window;
                stream.blocked = blocked;
                return;
            }
        }
        return error.StreamNotFound;
    }

    /// Schedule streams using DRR
    pub fn scheduleStreams(self: *ConnectionState, max_packet: usize, out: []drr.Transmission) !usize {
        return drr.scheduleOnce(self.streams.items, max_packet, out);
    }

    /// Record packet sent for loss detection
    pub fn onPacketSent(self: *ConnectionState, pn: u64, size: usize, now_us: u64) !void {
        self.congestion_ctrl.onPacketSent(size);
        try self.sent_packets.append(self.allocator, loss_recovery.SentPacket{
            .pn = pn,
            .sent_at_us = now_us,
            .acked = false,
        });
        self.bytes_sent += size;
        self.last_active_us = now_us;
    }

    /// Process ACK and update congestion control
    pub fn onAckReceived(self: *ConnectionState, acked_pn: u64, acked_bytes: usize, now_us: u64) void {
        // Update congestion control
        self.congestion_ctrl.onAckReceived(acked_bytes, acked_pn);

        // Mark packet as acked
        for (self.sent_packets.items) |*pkt| {
            if (pkt.pn == acked_pn) {
                pkt.acked = true;
                break;
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

        // Update congestion control for each lost packet
        for (out_lost[0..n_lost]) |lost_pn| {
            // Find packet size
            for (self.sent_packets.items) |pkt| {
                if (pkt.pn == lost_pn) {
                    self.congestion_ctrl.onPacketLost(1200, lost_pn, latest_sent_pn); // Assume MSS
                    break;
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
    shard_count: u32,
    next_timer_id: u64,

    pub fn init(allocator: std.mem.Allocator, shard_count: u32) !ConnectionManager {
        return ConnectionManager{
            .allocator = allocator,
            .connections = std.StringHashMap(*ConnectionState).init(allocator),
            .timers = try timer_heap.TimerHeap.init(allocator),
            .shard_count = shard_count,
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

    /// Add a new connection
    pub fn addConnection(self: *ConnectionManager, id: []const u8, mss: usize, now_us: u64) !*ConnectionState {
        const conn = try self.allocator.create(ConnectionState);
        errdefer self.allocator.destroy(conn);

        conn.* = try ConnectionState.init(self.allocator, id, mss, now_us);
        errdefer conn.deinit();

        try self.connections.put(id, conn);
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

    /// Choose shard for connection using consistent hashing
    pub fn chooseShard(self: *ConnectionManager, conn_key: []const u8) !u32 {
        return sharding.chooseLoop(conn_key, self.shard_count);
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

    const shard1 = try mgr.chooseShard("192.168.1.1:5000");
    const shard2 = try mgr.chooseShard("192.168.1.1:5000");

    // Same key should map to same shard
    try std.testing.expectEqual(shard1, shard2);

    // Shard should be in range
    try std.testing.expect(shard1 < 8);
}
