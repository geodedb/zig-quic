// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for QUIC algorithms: DRR, NewReno, loss recovery, timers, sharding.

const std = @import("std");
const drr = @import("drr");
const congestion = @import("congestion");
const loss_recovery = @import("loss_recovery");
const timer_heap = @import("timer_heap");
const sharding = @import("sharding");
const connection_manager = @import("connection_manager");
const ConnectionManager = connection_manager.ConnectionManager;
const ConnectionState = connection_manager.ConnectionState;

// Integration tests for QUIC algorithms: DRR, NewReno, loss recovery, timers, sharding

test "QUIC algorithms: DRR scheduler basic" {
    var streams = [_]drr.Stream{
        .{ .id = 1, .send_buf = 4096, .flow_window = 1200, .blocked = false, .deficit = 0, .quantum = 1200 },
        .{ .id = 2, .send_buf = 300, .flow_window = 300, .blocked = false, .deficit = 0, .quantum = 1200 },
    };

    var out: [4]drr.Transmission = undefined;
    const n = try drr.scheduleOnce(&streams, 1200, &out);

    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u32, 1), out[0].stream_id);
    try std.testing.expectEqual(@as(u32, 2), out[1].stream_id);
}

test "QUIC algorithms: NewReno congestion control" {
    var nr = congestion.NewReno.init(1200);

    // Slow start phase
    nr.onPacketSent(1200);
    const initial_cwnd = nr.cwnd;
    nr.onAckReceived(1200, 1);
    try std.testing.expect(nr.cwnd > initial_cwnd);

    // Loss triggers recovery
    nr.onPacketLost(1200, 2, 3);
    try std.testing.expect(nr.in_recovery);
    try std.testing.expect(nr.cwnd < initial_cwnd + 1200);
}

test "QUIC algorithms: Loss recovery with thresholds" {
    var pkts = [_]loss_recovery.SentPacket{
        .{ .pn = 1, .sent_at_us = 1000, .size = 1200, .acked = false },
        .{ .pn = 2, .sent_at_us = 1010, .size = 1200, .acked = true },
        .{ .pn = 3, .sent_at_us = 1020, .size = 1200, .acked = true },
    };

    var lost: [4]u64 = undefined;
    const n = loss_recovery.detectLost(&pkts, 3, 200000, 100000, 3, &lost);

    // Packet 1 should be detected as lost (time threshold exceeded)
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 1), lost[0]);
}

test "QUIC algorithms: Timer heap ordering" {
    var heap = timer_heap.TimerHeap.init(65536);
    defer heap.deinit(std.testing.allocator);

    try heap.push(std.testing.allocator, .{ .id = 1, .deadline_us = 1000 });
    try heap.push(std.testing.allocator, .{ .id = 2, .deadline_us = 500 });
    try heap.push(std.testing.allocator, .{ .id = 3, .deadline_us = 750 });

    // Should pop in deadline order
    try std.testing.expectEqual(@as(u64, 2), heap.pop().?.id);
    try std.testing.expectEqual(@as(u64, 3), heap.pop().?.id);
    try std.testing.expectEqual(@as(u64, 1), heap.pop().?.id);
}

test "QUIC algorithms: Connection sharding" {
    const shard1 = try sharding.chooseLoop("192.168.1.1:5000", 8);
    const shard2 = try sharding.chooseLoop("192.168.1.1:5000", 8);
    const shard3 = try sharding.chooseLoop("192.168.1.2:5000", 8);

    // Same key maps to same shard
    try std.testing.expectEqual(shard1, shard2);

    // Different keys may map to different shards
    try std.testing.expect(shard1 < 8);
    try std.testing.expect(shard3 < 8);
}

test "ConnectionManager: full lifecycle" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    // Add connection
    const conn = try mgr.addConnection("conn-1", 1200, 1000000);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());

    // Add streams
    try conn.addStream(1, 1200);
    try conn.addStream(2, 1200);

    // Update stream state
    try conn.updateStream(1, 4096, 2000, false);
    try conn.updateStream(2, 2048, 1500, false);

    // Schedule streams
    var transmissions: [4]drr.Transmission = undefined;
    const n_tx = try conn.scheduleStreams(1200, &transmissions);
    try std.testing.expect(n_tx > 0);

    // Send packet
    try conn.onPacketSent(1, 1200, 1001000);

    // Receive ACK
    conn.onAckReceived(1, 1200, 1002000);

    // Verify congestion control updated
    try std.testing.expect(conn.congestion_ctrl.cwnd > 10 * 1200);

    // Remove connection
    mgr.removeConnection("conn-1");
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "ConnectionManager: multi-connection scenario" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    // Add multiple connections
    _ = try mgr.addConnection("conn-1", 1200, 1000000);
    _ = try mgr.addConnection("conn-2", 1200, 1000000);
    _ = try mgr.addConnection("conn-3", 1200, 1000000);

    try std.testing.expectEqual(@as(usize, 3), mgr.connectionCount());

    // Schedule timers
    _ = try mgr.scheduleTimer(1500);
    _ = try mgr.scheduleTimer(1000);
    _ = try mgr.scheduleTimer(2000);

    // Check next deadline
    try std.testing.expectEqual(@as(?u64, 1000), mgr.nextTimerDeadline());

    // Pop expired timers
    var expired: [5]u64 = undefined;
    const n_expired = mgr.popExpiredTimers(1600, &expired);
    try std.testing.expectEqual(@as(usize, 2), n_expired);

    // Clean up
    mgr.removeConnection("conn-1");
    mgr.removeConnection("conn-2");
    mgr.removeConnection("conn-3");
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "ConnectionManager: loss detection and recovery" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 4);
    defer mgr.deinit();

    const conn = try mgr.addConnection("conn-1", 1200, 1000000);

    // Send multiple packets
    try conn.onPacketSent(1, 1200, 1000000);
    try conn.onPacketSent(2, 1200, 1001000);
    try conn.onPacketSent(3, 1200, 1002000);
    try conn.onPacketSent(4, 1200, 1003000);

    // ACK packets 2, 3, 4 (packet 1 is reordered/lost)
    conn.onAckReceived(2, 1200, 1004000);
    conn.onAckReceived(3, 1200, 1005000);
    conn.onAckReceived(4, 1200, 1006000);

    // Detect lost packets
    var lost: [8]u64 = undefined;
    const n_lost = try conn.detectLoss(1500000, 3, &lost, 4);

    // Packet 1 should be detected as lost
    try std.testing.expect(n_lost >= 1);

    // Verify congestion control entered recovery
    try std.testing.expect(conn.congestion_ctrl.in_recovery);
}

test "ConnectionManager: shard assignment consistency" {
    var mgr = try ConnectionManager.init(std.testing.allocator, 8);
    defer mgr.deinit();

    // Test same connection key maps to same shard
    const shard1a = mgr.chooseShard("192.168.1.100:50000");
    const shard1b = mgr.chooseShard("192.168.1.100:50000");
    try std.testing.expectEqual(shard1a, shard1b);

    // Test distribution across shards
    var shard_counts = [_]usize{0} ** 8;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "192.168.1.{d}:5000", .{i});
        const shard_val = mgr.chooseShard(key);
        shard_counts[shard_val] += 1;
    }

    // Verify reasonable distribution (at least 4 shards used out of 8)
    var shards_used: usize = 0;
    for (shard_counts) |count| {
        if (count > 0) shards_used += 1;
    }
    try std.testing.expect(shards_used >= 4);
}
