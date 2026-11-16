const std = @import("std");
const compat = @import("compat");
const testlog = @import("testlog");
const api = @import("quic_api");
const conn_mod = @import("quic_conn");

const Endpoint = api.QuicEndpoint;
const Transport = @TypeOf(@as(Endpoint, undefined).transport);
const SockAddr = conn_mod.SockAddr;
const RecvFnType = @TypeOf(@as(Transport, undefined).recvFn);
const RecvFnPtrInfo = @typeInfo(RecvFnType);
const RecvFnActualType = RecvFnPtrInfo.pointer.child;
const RecvFnTypeInfo = @typeInfo(RecvFnActualType);
const RecvFnReturnType = RecvFnTypeInfo.@"fn".return_type.?;
const RecvResult = @typeInfo(RecvFnReturnType).error_union.payload;

const NoopTransport = struct {
    fn sendFn(_: *anyopaque, _: SockAddr, data: []const u8) !usize {
        return data.len;
    }

    fn recvFn(_: *anyopaque, _: []u8) !RecvResult {
        return error.WouldBlock;
    }

    fn pollFn(_: *anyopaque, _: i32) !void {}

    fn closeFn(_: *anyopaque) void {}

    fn getLocalAddrFn(_: *anyopaque) !SockAddr {
        return error.Unsupported;
    }

    pub fn init() Transport {
        return .{
            .sendFn = sendFn,
            .recvFn = recvFn,
            .pollFn = pollFn,
            .closeFn = closeFn,
            .getLocalAddrFn = getLocalAddrFn,
            .context = undefined,
        };
    }
};

// Basic timing tests for endpoint timers.

test "endpoint_timer_fire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 20);
    const t0 = compat.milliTimestamp();
    try api.poll(ep, 200);
    const dt = compat.milliTimestamp() - t0;

    // Should have waited at least a few milliseconds, but much less than the full poll timeout.
    try std.testing.expect(dt >= 5);
    try std.testing.expect(dt < 500);

    // Timer should be consumed.
    try std.testing.expect(ep.timers.items.len == 0);
}

test "endpoint_timer_cancel" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 200);
    const id2 = try api.scheduleTimer(ep, 200);
    try std.testing.expect(ep.timers.items.len == 2);

    try std.testing.expect(api.cancelTimer(ep, id2));
    try std.testing.expect(ep.timers.items.len == 1);

    // Poll briefly to let the remaining timer not fire yet; count stays 1.
    try api.poll(ep, 10);
    try std.testing.expect(ep.timers.items.len == 1);

    // Now poll long enough for it to expire and be removed.
    try api.poll(ep, 300);
    try std.testing.expect(ep.timers.items.len == 0);
}

test "endpoint_timer_heap_root_survives_insert_and_cancel" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    _ = try api.scheduleTimer(ep, 200);
    const fast = try api.scheduleTimer(ep, 20);
    const mid = try api.scheduleTimer(ep, 100);

    try std.testing.expectEqual(fast, ep.timers.items[0].id);
    try std.testing.expect(api.cancelTimer(ep, fast));
    try std.testing.expectEqual(mid, ep.timers.items[0].id);
}

test "endpoint_pto_schedule_and_expire_flag" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    // Build a minimal connection object and set a non-zero smoothed RTT so PTO computes
    var conn: @import("quic_conn").Connection = undefined;
    // Phase 8c: Pass -1 for sock_fd (I/O now via transport abstraction)
    conn.init(&gpa, .Server, -1, @import("quic_conn").SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    // Seed RTT so PTO > 0
    conn.rtt_app.have_sample = true;
    conn.rtt_app.smoothed_rtt_ns = 50 * std.time.ns_per_ms;
    conn.rtt_app.rttvar_ns = 10 * std.time.ns_per_ms;

    // With Recovery-based PTO, timers are only armed when there is an outstanding
    // ack-eliciting packet. Record one such send now.
    const now_ns_i128 = compat.nanoTimestamp();
    const now_ns_u64: u64 = @intCast(@max(@as(i128, 0), now_ns_i128));
    try conn.rec.onPacketSent(.Application, 1, 1200, true, now_ns_u64);

    // Arm PTO and ensure a timer is created
    conn.computeAndMaybeArmPto(ep);
    testlog.print("DEBUG app: active={any} timers={d} pto_count={d}\n", .{ conn.pto_app_active, ep.timers.items.len, conn.pto_app_count });
    try std.testing.expect(conn.pto_app_active);
    try std.testing.expect(ep.timers.items.len >= 1);

    // Deterministically expire all timers and verify PTO flag clears
    try ep.retired.append(gpa, &conn);
    ep.forceExpireAllTimers();
    ep.retired.clearRetainingCapacity();
    testlog.print("DEBUG app after expire: active={any} timers={d} pto_count={d}\n", .{ conn.pto_app_active, ep.timers.items.len, conn.pto_app_count });
    try std.testing.expect(!conn.pto_app_active);
    try std.testing.expect(ep.timers.items.len == 0);
}

test "pto dirty notifier is seeded when installed on already-dirty connection" {
    var gpa = std.heap.page_allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&gpa, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    const Ctx = struct {
        count: std.atomic.Value(u32) = .init(0),

        fn notify(ctx: *anyopaque, c: *conn_mod.Connection) void {
            _ = c;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.count.fetchAdd(1, .seq_cst);
        }
    };

    var ctx = Ctx{};
    try std.testing.expect(conn.pto_dirty.load(.seq_cst));
    conn.setPtoDirtyNotifier(@ptrCast(&ctx), Ctx.notify);
    try std.testing.expectEqual(@as(u32, 1), ctx.count.load(.seq_cst));
}

test "short-header sends mark PTO dirty without arming connection shim timer" {
    var gpa = std.heap.page_allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&gpa, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    const Ctx = struct {
        count: std.atomic.Value(u32) = .init(0),

        fn notify(ctx: *anyopaque, c: *conn_mod.Connection) void {
            _ = c;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.count.fetchAdd(1, .seq_cst);
        }
    };

    var ctx = Ctx{};
    conn.pto_dirty.store(false, .seq_cst);
    conn.pto_app_active = false;
    conn.pto_app_id = 0;
    conn.setPtoDirtyNotifier(@ptrCast(&ctx), Ctx.notify);

    conn.onShortHeaderPacketSent(1200, true);

    try std.testing.expect(conn.pto_dirty.load(.seq_cst));
    try std.testing.expectEqual(@as(u32, 1), ctx.count.load(.seq_cst));
    try std.testing.expect(!conn.pto_app_active);
    try std.testing.expectEqual(@as(u64, 0), conn.pto_app_id);
}

test "endpoint app PTO retransmits outstanding STREAM data" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    cfg.enable_pacing = false;
    cfg.initial_congestion_window_packets = 64;
    var ep = try api.QuicEndpoint.initWithTransport(&allocator, NoopTransport.init(), &cfg, .Client);
    defer ep.deinit();
    ep.test_capture_enabled = true;

    const conn = try ep.connectClient("127.0.0.1:4433");
    _ = try ep.pollWithStats(0);

    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    std.mem.copyForwards(u8, conn.peer_initial_scid.bytes[0..4], "PEER");
    ep.captureClear();

    const written = try conn.writeStream(0, "EXECUTE", false);
    try std.testing.expectEqual(@as(usize, 7), written);
    try std.testing.expectEqual(@as(usize, 1), conn.app_stream_retx.count());
    try std.testing.expectEqual(@as(u64, 1), conn.pn_app_tx);

    _ = try ep.pollWithStats(0);
    try std.testing.expect(conn.pto_app_active);
    try std.testing.expect(ep.timers.items.len >= 1);

    ep.forceExpireAllTimers();

    try std.testing.expectEqual(@as(u32, 1), conn.pto_app_count);
    try std.testing.expectEqual(@as(u64, 2), conn.pn_app_tx);
    try std.testing.expectEqual(@as(usize, 1), conn.app_stream_retx.count());
    try std.testing.expect(conn.app_stream_retx.contains(1));
    try std.testing.expect(ep.captureLen() >= 2);
}

test "app ack time-threshold loss retransmits retained STREAM data" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    cfg.enable_pacing = false;
    cfg.initial_congestion_window_packets = 64;
    var ep = try api.QuicEndpoint.initWithTransport(&allocator, NoopTransport.init(), &cfg, .Client);
    defer ep.deinit();
    ep.test_capture_enabled = true;

    const conn = try ep.connectClient("127.0.0.1:4433");
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    std.mem.copyForwards(u8, conn.peer_initial_scid.bytes[0..4], "PEER");
    conn.rec.rtt.have_sample = true;
    conn.rec.rtt.smoothed_rtt_ns = std.time.ns_per_ms;
    conn.rec.rtt.latest_rtt_ns = std.time.ns_per_ms;
    conn.rec.rtt.rttvar_ns = 0;
    conn.rec.refreshAtomicMirrors();
    ep.captureClear();

    try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "AAAA", false));
    try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "BBBB", false));
    compat.threadSleep(8 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "CCCC", false));
    try std.testing.expectEqual(@as(u64, 3), conn.pn_app_tx);
    try std.testing.expectEqual(@as(usize, 3), conn.app_stream_retx.count());

    conn.onAckReceivedSpace(.Application, 2, 0, &.{}, null);

    try std.testing.expect(conn.pn_app_tx > 3);
    // AAAA and BBBB stay tracked, retransmitted (together, SONNY-6649) or
    // not; the acknowledged CCCC does not.
    try expectTrackedCoversOnce(conn, 0, 8);
    try std.testing.expect(ep.captureLen() > 3);
}

fn setupAppStreamConn(ep: anytype) !*conn_mod.Connection {
    const conn = try ep.connectClient("127.0.0.1:4433");
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    std.mem.copyForwards(u8, conn.peer_initial_scid.bytes[0..4], "PEER");
    return conn;
}

// Regression (geode `backup create` stall on small SO_RCVBUF hosts): a burst
// of lost STREAM packets larger than the per-ACK retransmit budget must stay
// tracked until it is retransmitted. Recovery compacts lost packets away, so
// they read as `.unknown`; the old cumulative prune freed them as if acked and
// left a permanent hole in the stream.
test "app ack burst loss retains every unretransmitted STREAM packet" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    cfg.enable_pacing = false;
    cfg.initial_congestion_window_packets = 64;
    var ep = try api.QuicEndpoint.initWithTransport(&allocator, NoopTransport.init(), &cfg, .Client);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    const conn = try setupAppStreamConn(&ep);

    const sent_packets: u64 = 40;
    var i: u64 = 0;
    while (i < sent_packets) : (i += 1) {
        try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "DATA", false));
    }
    try std.testing.expectEqual(sent_packets, conn.pn_app_tx);
    try std.testing.expectEqual(@as(usize, sent_packets), conn.app_stream_retx.count());

    // Peer received only the newest packet: PNs 0..38 are lost.
    conn.onAckReceivedSpace(.Application, sent_packets - 1, 0, &.{}, null);

    // The acked packet is dropped; the data of every lost packet is either
    // retransmitted (re-tracked under a new PN, possibly together with the
    // data of other lost packets) or still waiting, never freed.
    try expectTrackedCoversOnce(conn, 0, (sent_packets - 1) * 4);
    try std.testing.expectEqual(sent_packets + conn.stream_retx_packets, conn.pn_app_tx);
}

/// Every byte of stream 0 in [0, end) is tracked for retransmission by
/// exactly one entry, and no other byte is.
fn expectTrackedCoversOnce(conn: *conn_mod.Connection, start: u64, end: u64) !void {
    var covered = try std.testing.allocator.alloc(u8, @intCast(end - start));
    defer std.testing.allocator.free(covered);
    @memset(covered, 0);
    var it = conn.app_stream_retx.iterator();
    while (it.next()) |entry| {
        const e = entry.value_ptr;
        try std.testing.expectEqual(@as(u64, 0), e.stream_id);
        try std.testing.expect(e.offset >= start and e.offset + e.data.len <= end);
        for (0..e.data.len) |k| covered[@intCast(e.offset - start + @as(u64, k))] += 1;
    }
    for (covered) |c| try std.testing.expectEqual(@as(u8, 1), c);
}

// SONNY-6649: one small STREAM frame per packet, then a burst loss. The lost
// frames go out again together, a full packet at a time (RFC 9000 §13.3),
// not one packet each: a 33000-packet blackout used to take 33000
// retransmission packets, over a minute on a loaded runner.
test "app ack burst loss of small STREAM packets is retransmitted in full packets" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    cfg.enable_pacing = false;
    cfg.initial_congestion_window_packets = 1024;
    var ep = try api.QuicEndpoint.initWithTransport(&allocator, NoopTransport.init(), &cfg, .Client);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    const conn = try setupAppStreamConn(&ep);

    const chunk = "0123456789abcdef";
    const sent_packets: u64 = 1000;
    var i: u64 = 0;
    while (i < sent_packets) : (i += 1) {
        try std.testing.expectEqual(@as(usize, chunk.len), try conn.writeStream(0, chunk, false));
    }
    try std.testing.expectEqual(@as(usize, sent_packets), conn.app_stream_retx.count());

    // Peer received only the newest packet: PNs 0..998 are lost.
    conn.onAckReceivedSpace(.Application, sent_packets - 1, 0, &.{}, null);

    // Two retransmission packets (the per-ACK budget), each carrying as
    // many whole lost frames as fit in max(path_mtu - 50, 1350) bytes.
    const frames_per_packet: usize = 1350 / chunk.len;
    const per_packet: u64 = frames_per_packet * chunk.len;
    try std.testing.expectEqual(@as(u64, 2), conn.stream_retx_packets);
    try std.testing.expectEqual(sent_packets + 2, conn.pn_app_tx);
    const first = conn.app_stream_retx.getPtr(sent_packets).?;
    try std.testing.expectEqual(@as(u64, 0), first.offset);
    try std.testing.expectEqual(per_packet, first.data.len);
    const second = conn.app_stream_retx.getPtr(sent_packets + 1).?;
    try std.testing.expectEqual(per_packet, second.offset);
    try std.testing.expectEqual(per_packet, second.data.len);
    for (0..frames_per_packet) |k| {
        try std.testing.expectEqualStrings(chunk, first.data[k * chunk.len ..][0..chunk.len]);
    }
    // Nothing lost was freed, and the stream counts one outstanding packet
    // per tracked entry (it retires when they are all acknowledged).
    try expectTrackedCoversOnce(conn, 0, (sent_packets - 1) * chunk.len);
    const tracked_left: usize = @intCast(sent_packets - 1 - 2 * frames_per_packet + 2);
    try std.testing.expectEqual(tracked_left, conn.app_stream_retx.count());
    try std.testing.expectEqual(@as(u32, @intCast(tracked_left)), conn.stream_txs.getPtr(0).?.retx_outstanding);

    // Acknowledging both retransmissions releases their data, and the next
    // lost frames go out the same way.
    const ranges = [_]conn_mod.AckRange{};
    conn.onAckReceivedSpace(.Application, sent_packets + 1, 1, &ranges, null);
    try std.testing.expectEqual(@as(u64, 4), conn.stream_retx_packets);
    try expectTrackedCoversOnce(conn, 2 * per_packet, (sent_packets - 1) * chunk.len);
    try std.testing.expectEqual(@as(u32, @intCast(conn.app_stream_retx.count())), conn.stream_txs.getPtr(0).?.retx_outstanding);
}

// Lost packets of different streams are not merged: each retransmission
// carries one stream's data at its own offsets.
test "app ack burst loss does not merge STREAM data of different streams" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    cfg.enable_pacing = false;
    cfg.initial_congestion_window_packets = 1024;
    var ep = try api.QuicEndpoint.initWithTransport(&allocator, NoopTransport.init(), &cfg, .Client);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    const conn = try setupAppStreamConn(&ep);

    const s0 = try conn.openStream(true);
    const s1 = try conn.openStream(true);
    try std.testing.expect(s0 != s1);
    const rounds: u64 = 10;
    var i: u64 = 0;
    while (i < rounds) : (i += 1) {
        try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(s0, "AAAA", false));
        try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(s1, "BBBB", false));
    }
    const sent_packets = 2 * rounds;
    conn.onAckReceivedSpace(.Application, sent_packets - 1, 0, &.{}, null);

    try std.testing.expectEqual(@as(u64, 2), conn.stream_retx_packets);
    try std.testing.expectEqual(@as(usize, sent_packets - 1), conn.app_stream_retx.count());
    const a = conn.app_stream_retx.getPtr(sent_packets).?;
    try std.testing.expectEqual(s0, a.stream_id);
    try std.testing.expectEqual(@as(u64, 0), a.offset);
    try std.testing.expectEqualStrings("AAAA", a.data);
    const b = conn.app_stream_retx.getPtr(sent_packets + 1).?;
    try std.testing.expectEqual(s1, b.stream_id);
    try std.testing.expectEqual(@as(u64, 0), b.offset);
    try std.testing.expectEqualStrings("BBBB", b.data);
}

// Wide ACK ranges (more PNs than the 256-entry enumeration handed to
// recovery) must still release every acknowledged STREAM packet.
test "app ack wide range drops all acknowledged STREAM tracking" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    cfg.enable_pacing = false;
    cfg.initial_congestion_window_packets = 1024;
    var ep = try api.QuicEndpoint.initWithTransport(&allocator, NoopTransport.init(), &cfg, .Client);
    defer ep.deinit();
    ep.test_capture_enabled = true;
    const conn = try setupAppStreamConn(&ep);

    const sent_packets: u64 = 300;
    var i: u64 = 0;
    while (i < sent_packets) : (i += 1) {
        try std.testing.expectEqual(@as(usize, 4), try conn.writeStream(0, "DATA", false));
    }
    try std.testing.expectEqual(@as(usize, sent_packets), conn.app_stream_retx.count());

    // Two ranges: [150, 299] and [0, 147]; gap=1 skips PNs 148..149
    // (RFC 9000 §19.3.1: largest = previous_smallest - gap - 2).
    const ranges = [_]conn_mod.AckRange{.{ .gap = 1, .len = 147 }};
    conn.onAckReceivedSpace(.Application, sent_packets - 1, 149, &ranges, null);

    // Only the data of the two unacknowledged packets (148, 149) remains
    // tracked, under its original PN or as a retransmission (one, since
    // their data is contiguous, SONNY-6649). Acknowledged packets must not
    // be retransmitted spuriously.
    try expectTrackedCoversOnce(conn, 148 * 4, 150 * 4);
}

test "app PTO send failure rearms retransmission timer" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    const Sender = struct {
        fail: bool = false,
        sends: usize = 0,

        fn send(ctx: *anyopaque, _: *conn_mod.Connection, data: []const u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.fail) return error.WouldBlock;
            self.sends += 1;
            return data.len;
        }
    };

    var sender = Sender{};
    var conn: conn_mod.Connection = undefined;
    conn.init(&allocator, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.setSender(@ptrCast(&sender), Sender.send);
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    std.mem.copyForwards(u8, conn.peer_initial_scid.bytes[0..4], "PEER");

    try std.testing.expectEqual(@as(usize, 7), try conn.writeStream(0, "EXECUTE", false));
    try std.testing.expectEqual(@as(usize, 1), sender.sends);
    try std.testing.expectEqual(@as(u64, 1), conn.pn_app_tx);
    try std.testing.expectEqual(@as(usize, 1), conn.app_stream_retx.count());

    conn.pto_dirty.store(false, .seq_cst);
    conn.pto_app_active = true;
    sender.fail = true;
    conn.setPtoExpiredApp();

    try std.testing.expectEqual(@as(u32, 1), conn.pto_app_count);
    try std.testing.expectEqual(@as(u64, 1), conn.pn_app_tx);
    try std.testing.expectEqual(@as(usize, 1), conn.app_stream_retx.count());
    try std.testing.expect(conn.pto_dirty.load(.seq_cst));
}

test "PTO arming skips spaces with no ack-eliciting packet in flight" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    var conn: conn_mod.Connection = undefined;
    conn.init(&gpa, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    conn.computeAndMaybeArmPtoInitial(ep);
    conn.computeAndMaybeArmPtoHandshake(ep);
    conn.computeAndMaybeArmPto(ep);

    try std.testing.expect(!conn.pto_initial_active);
    try std.testing.expect(!conn.pto_handshake_active);
    try std.testing.expect(!conn.pto_app_active);
    try std.testing.expectEqual(@as(usize, 0), ep.timers.items.len);

    const now_ns_i128 = compat.nanoTimestamp();
    const now_ns_u64: u64 = @intCast(@max(@as(i128, 0), now_ns_i128));
    try conn.rec.onPacketSent(.Application, 1, 1200, false, now_ns_u64);
    conn.computeAndMaybeArmPto(ep);

    try std.testing.expect(!conn.pto_app_active);
    try std.testing.expectEqual(@as(usize, 0), ep.timers.items.len);
}

test "closed connection notification prunes only closed connections" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    const closed_conn = try ep.connectClient("127.0.0.1:10000");
    const live_conn = try ep.connectClient("127.0.0.1:10001");
    _ = try ep.pollWithStats(0);

    closed_conn.markClosed();
    try std.testing.expectEqual(@as(u32, 1), ep.closed_conn_count.load(.acquire));

    _ = try ep.pollWithStats(0);
    try std.testing.expectEqual(@as(u32, 0), ep.closed_conn_count.load(.acquire));

    var found_closed = false;
    var found_live = false;
    var it = ep.conns.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == closed_conn) found_closed = true;
        if (entry.value_ptr.* == live_conn) found_live = true;
    }
    try std.testing.expect(!found_closed);
    try std.testing.expect(found_live);
}

// New: per-space PTO arming/cancel and probe generation tests

test "initial_space_pto_arm_and_probe_on_expire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    // Create a server-side Connection and seed Initial RTT so PTO can be armed
    var conn: @import("quic_conn").Connection = undefined;
    // Phase 8c: Pass -1 for sock_fd (I/O now via transport abstraction)
    conn.init(&gpa, .Server, -1, @import("quic_conn").SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.rtt_initial.have_sample = true;
    conn.rtt_initial.smoothed_rtt_ns = 30 * std.time.ns_per_ms;
    conn.rtt_initial.rttvar_ns = 5 * std.time.ns_per_ms;

    // Populate peer initial DCID/SCID and our SCID for building Initial probes
    conn.peer_initial_dcid.len = 8;
    @memcpy(conn.peer_initial_dcid.bytes[0..8], "12345678");
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "ABCD");
    conn.our_scid.len = 4;
    @memcpy(conn.our_scid.bytes[0..4], "WXYZ");
    conn.initial_version = 0x00000001;

    // Recovery-driven PTO requires at least one in-flight ack-eliciting packet.
    // Record a synthetic Initial send and advance PN so the probe uses the next PN.
    conn.onPacketSent(.Initial, conn.pn_initial_tx, 1200, true);
    conn.pn_initial_tx +%= 1;

    // Arm Initial PTO
    conn.computeAndMaybeArmPtoInitial(ep);
    testlog.print("DEBUG init: active={any} timers={d} pn_tx={d} count={d}\n", .{ conn.pto_initial_active, ep.timers.items.len, conn.pn_initial_tx, conn.pto_initial_count });
    try std.testing.expect(conn.pto_initial_active);

    // Expire timers deterministically; this should send a PING probe
    const pn_before = conn.pn_initial_tx;
    const count_before = conn.pto_initial_count;
    try ep.retired.append(gpa, &conn);
    ep.forceExpireAllTimers();
    ep.retired.clearRetainingCapacity();
    testlog.print("DEBUG init after expire: active={any} timers={d} pn_tx={d}->{d} count={d}->{d}\n", .{ conn.pto_initial_active, ep.timers.items.len, pn_before, conn.pn_initial_tx, count_before, conn.pto_initial_count });
    try std.testing.expect(!conn.pto_initial_active);
    try std.testing.expect(conn.pn_initial_tx > pn_before);
    try std.testing.expect(conn.pto_initial_count > count_before);
}

test "handshake_space_pto_arm_cancel_on_ack_and_probe_on_expire" {
    var gpa = std.heap.page_allocator;
    const cfg = api.QuicConfig{ .alpn = &[_][]const u8{"h3"} };
    const ep = try api.endpointInit(&gpa, "127.0.0.1:0", &cfg);
    defer api.endpointDeinit(ep);

    var conn: @import("quic_conn").Connection = undefined;
    // Phase 8c: Pass -1 for sock_fd (I/O now via transport abstraction)
    conn.init(&gpa, .Server, -1, @import("quic_conn").SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();

    // Seed Handshake RTT
    conn.rtt_handshake.have_sample = true;
    conn.rtt_handshake.smoothed_rtt_ns = 40 * std.time.ns_per_ms;
    conn.rtt_handshake.rttvar_ns = 5 * std.time.ns_per_ms;

    // Seed hs_tx_keys minimally so we can build probes without deriving real keys
    conn.hs_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

    // Required CIDs for header construction
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "ABCD");
    conn.our_scid.len = 4;
    @memcpy(conn.our_scid.bytes[0..4], "WXYZ");
    conn.initial_version = 0x00000001;

    // Recovery-driven PTO requires an outstanding ack-eliciting packet in Handshake space
    conn.onPacketSent(.Handshake, conn.pn_handshake_tx, 1200, true);
    conn.pn_handshake_tx +%= 1;

    // Arm Handshake PTO
    conn.computeAndMaybeArmPtoHandshake(ep);
    testlog.print("DEBUG hs: active={any} timers={d} pn_tx={d} count={d}\n", .{ conn.pto_handshake_active, ep.timers.items.len, conn.pn_handshake_tx, conn.pto_handshake_count });
    try std.testing.expect(conn.pto_handshake_active);

    // Expire timers deterministically; should send a PING probe
    const pn_before = conn.pn_handshake_tx;
    const count_before = conn.pto_handshake_count;
    try ep.retired.append(gpa, &conn);
    ep.forceExpireAllTimers();
    ep.retired.clearRetainingCapacity();
    testlog.print("DEBUG hs after expire: active={any} timers={d} pn_tx={d}->{d} count={d}->{d}\n", .{ conn.pto_handshake_active, ep.timers.items.len, pn_before, conn.pn_handshake_tx, count_before, conn.pto_handshake_count });
    try std.testing.expect(!conn.pto_handshake_active);
    try std.testing.expect(conn.pn_handshake_tx > pn_before);
    try std.testing.expect(conn.pto_handshake_count > count_before);
}
