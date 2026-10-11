// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros

const std = @import("std");
const conn_mod = @import("quic_conn");
const packet = @import("quic_packet");

const Operation = enum { close, reset };

const Capture = struct {
    packets: [2][512]u8 = undefined,
    lengths: [2]usize = undefined,
    count: usize = 0,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) !usize {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (self.count == self.packets.len or bytes.len > self.packets[0].len) return error.UnexpectedPacket;
        @memcpy(self.packets[self.count][0..bytes.len], bytes);
        self.lengths[self.count] = bytes.len;
        self.count += 1;
        return bytes.len;
    }
};

const Worker = struct {
    conn: *conn_mod.Connection,
    operation: Operation,
    stream_id: u64,
    done: std.atomic.Value(bool) = .init(false),
    result: ?anyerror = null,

    fn run(self: *Worker) void {
        const result = switch (self.operation) {
            .close => self.conn.closeStream(self.stream_id, 0),
            .reset => self.conn.resetStream(self.stream_id, 7),
        };
        result catch |err| {
            self.result = err;
        };
        self.done.store(true, .release);
    }
};

// Observe the attempted acquisition rather than assume the worker ran after
// an arbitrary sleep. The bound diagnoses a stalled worker; it is not a
// performance assertion. Always unlock and join, including on test failures.
fn sendWhileLifecycleWaits(worker: *Worker) !bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    const conn = worker.conn;
    conn.mu.lockUncancelable(io);
    const thread = std.Thread.spawn(.{}, Worker.run, .{worker}) catch |err| {
        conn.mu.unlock(io);
        return err;
    };
    defer thread.join();
    defer conn.mu.unlock(io);

    var waited: usize = 0;
    while (!worker.done.load(.acquire) and conn.mu.state.load(.acquire) != .contended) {
        if (waited == 5000) return error.LifecycleWorkerDidNotRun;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
        waited += 1;
    }
    const blocked = !worker.done.load(.acquire);
    // This is the writer's critical section, so the explicitly unlocked
    // primitive is intentional. The other stream cannot consume its PN.
    try std.testing.expectEqual(@as(usize, 5), try conn.writeStreamUnlocked(8, "reply", false));
    return blocked;
}

fn checkLifecycle(operation: Operation, stream_id: u64) !void {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.stream_opened = true;
    conn.stream_send_off = 7;
    conn.ensureStreamTxInit();
    try conn.stream_txs.put(4, .{ .off = 7, .peer_max_stream_data = 1024 });
    try conn.stream_txs.put(8, .{ .peer_max_stream_data = 1024 });
    var capture: Capture = .{};
    conn.setSender(&capture, Capture.send);
    var worker: Worker = .{ .conn = &conn, .operation = operation, .stream_id = stream_id };
    const first_pn = conn.pn_app_tx;
    const blocked = try sendWhileLifecycleWaits(&worker);
    try std.testing.expect(blocked);
    if (worker.result) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), capture.count);
    for (0..capture.count) |i| {
        const decoded = try packet.decodeShortProtected(allocator, capture.packets[i][0..capture.lengths[i]], conn.shortHeaderDcid().len, conn.app_tx_keys.?, first_pn);
        defer allocator.free(decoded.payload);
        try std.testing.expectEqual(first_pn + i, decoded.packet_number);
    }
    try std.testing.expectEqual(first_pn + 2, conn.pn_app_tx);
    if (stream_id == 0) {
        try std.testing.expectEqual(operation == .close, conn.stream_send_fin_sent);
        try std.testing.expectEqual(operation == .reset, conn.stream_send_aborted);
    } else {
        const tx = conn.stream_txs.get(stream_id).?;
        try std.testing.expectEqual(operation == .close, tx.fin_sent);
        try std.testing.expectEqual(operation == .reset, tx.aborted);
    }
}

test "SONNY-4776 close stream zero waits for the active writer and uses a distinct packet number" {
    try checkLifecycle(.close, 0);
}

test "SONNY-4776 close sibling stream waits for the active writer and uses a distinct packet number" {
    try checkLifecycle(.close, 4);
}

test "SONNY-4776 reset stream zero waits for the active writer and uses a distinct packet number" {
    try checkLifecycle(.reset, 0);
}

test "SONNY-4776 reset sibling stream waits for the active writer and uses a distinct packet number" {
    try checkLifecycle(.reset, 4);
}

test "SONNY-4776 lifecycle error paths release the connection mutex" {
    var allocator = std.testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    const io = std.Io.Threaded.global_single_threaded.io();
    for ([_]Operation{ .close, .reset }) |operation| {
        const result = switch (operation) {
            .close => conn.closeStream(4, 0),
            .reset => conn.resetStream(4, 7),
        };
        try std.testing.expectError(error.InvalidStream, result);
        try std.testing.expect(conn.mu.tryLock());
        conn.mu.unlock(io);
    }
}
