// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression tests (SONNY-6486 item 2): RFC 9000 §13.3 requires MAX_DATA,
// MAX_STREAM_DATA, MAX_STREAMS and RESET_STREAM to be sent again when the
// packet carrying them is lost; the flow-control frames carry the CURRENT
// value, not the lost one. They used to be sent once: a lost MAX_STREAMS
// stalled a long-lived connection at its stream limit and a lost
// MAX_STREAM_DATA stalled a transfer larger than the stream window.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const conn_mod = @import("quic_conn");
const frame = @import("quic_frame");
const packet = @import("quic_packet");
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");

const keys = packet.AeadKeys{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };

const Capture = struct {
    alloc: std.mem.Allocator,
    sent: std.ArrayList([]u8) = .empty,

    fn send(ctx: *anyopaque, _: *conn_mod.Connection, bytes: []const u8) !usize {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        try self.sent.append(self.alloc, try self.alloc.dupe(u8, bytes));
        return bytes.len;
    }

    fn deinit(self: *Capture) void {
        for (self.sent.items) |p| self.alloc.free(p);
        self.sent.deinit(self.alloc);
    }

    /// Calls `visit` for every frame of every packet sent from index `from`.
    fn frames(self: *Capture, from: usize, ctx: anytype, comptime visit: fn (@TypeOf(ctx), frame.Frame) void) void {
        for (self.sent.items[from..]) |p| {
            const dec = packet.decodeShortProtected(self.alloc, p, 4, keys, 0) catch continue;
            defer self.alloc.free(dec.payload);
            var off: usize = 0;
            while (off < dec.payload.len) {
                const fr = frame.decodeOne(dec.payload[off..]) catch break;
                off += fr.n;
                visit(ctx, fr.f);
            }
        }
    }
};

const Fixture = struct {
    alloc: std.mem.Allocator,
    conn: *conn_mod.Connection,
    capture: Capture,

    fn create(alloc: std.mem.Allocator) !*Fixture {
        const f = try alloc.create(Fixture);
        f.* = .{ .alloc = alloc, .conn = try alloc.create(conn_mod.Connection), .capture = .{ .alloc = alloc } };
        f.conn.init(&f.alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
        f.conn.app_tx_keys = keys;
        f.conn.peer_finished_verified = true;
        f.conn.address_validated = true;
        f.conn.peer_initial_scid.len = 4;
        @memcpy(f.conn.peer_initial_scid.bytes[0..4], "PEER");
        f.conn.setSender(@ptrCast(&f.capture), Capture.send);
        return f;
    }

    fn destroy(self: *Fixture) void {
        self.conn.deinit();
        self.alloc.destroy(self.conn);
        self.capture.deinit();
        self.alloc.destroy(self);
    }

    /// Send three PINGs and acknowledge only them: every earlier packet is
    /// then lost by packet threshold (RFC 9002 §6.1.1).
    fn loseEarlierPackets(self: *Fixture) void {
        const first = self.conn.pn_app_tx;
        for (0..3) |_| self.conn.sendControlFrames(&[_]u8{0x01});
        self.conn.onAckReceived(first + 2, 2, &.{});
    }
};

const Seen = struct {
    max_data: ?u64 = null,
    max_streams_bidi: ?u64 = null,
    msd: ?u64 = null,
    reset_final: ?u64 = null,

    fn visit(self: *Seen, f: frame.Frame) void {
        switch (f) {
            .max_data => |m| self.max_data = m.max,
            .max_streams_bidi => |m| self.max_streams_bidi = m.max,
            .max_stream_data => |m| if (m.stream_id == 4) {
                self.msd = m.max;
            },
            .reset_stream => |r| if (r.stream_id == 4) {
                self.reset_final = r.final_size;
            },
            else => {},
        }
    }
};

test "SONNY-6486 a lost MAX_STREAMS is sent again with the current limit" {
    const f = try Fixture.create(testing.allocator);
    defer f.destroy();
    f.conn.local_max_streams_bidi = 1600;
    f.conn.maybeSendMaxStreams(true);
    var first: Seen = .{};
    f.capture.frames(0, &first, Seen.visit);
    try testing.expectEqual(@as(?u64, 1600), first.max_streams_bidi);

    // More streams retire before the loss is noticed.
    f.conn.local_max_streams_bidi = 1700;
    const mark = f.capture.sent.items.len;
    f.loseEarlierPackets();
    var again: Seen = .{};
    f.capture.frames(mark, &again, Seen.visit);
    try testing.expectEqual(@as(?u64, 1700), again.max_streams_bidi);
}

test "SONNY-6486 a lost MAX_STREAM_DATA is sent again with the current limit" {
    const f = try Fixture.create(testing.allocator);
    defer f.destroy();
    // First data on peer stream 4 advertises its window.
    try f.conn.pushStreamFrame(4, 0, "hello", false);
    var first: Seen = .{};
    f.capture.frames(0, &first, Seen.visit);
    try testing.expect(first.msd != null);

    // The application consumed more; the new limit is not yet sent.
    const rx = f.conn.streams_rx.getPtr(4).?;
    rx.local_max_stream_data += 100_000;
    const mark = f.capture.sent.items.len;
    f.loseEarlierPackets();
    var again: Seen = .{};
    f.capture.frames(mark, &again, Seen.visit);
    try testing.expectEqual(@as(?u64, rx.local_max_stream_data), again.msd);
}

test "SONNY-6486 a lost MAX_DATA is sent again with the current limit" {
    const f = try Fixture.create(testing.allocator);
    defer f.destroy();
    f.conn.local_max_data += 1;
    f.conn.advertiseInitialFlowControl();
    var first: Seen = .{};
    f.capture.frames(0, &first, Seen.visit);
    try testing.expectEqual(@as(?u64, f.conn.local_max_data), first.max_data);

    f.conn.local_max_data += 4096;
    const mark = f.capture.sent.items.len;
    f.loseEarlierPackets();
    var again: Seen = .{};
    f.capture.frames(mark, &again, Seen.visit);
    try testing.expectEqual(@as(?u64, f.conn.local_max_data), again.max_data);
}

test "SONNY-6486 a lost RESET_STREAM is sent again" {
    const f = try Fixture.create(testing.allocator);
    defer f.destroy();
    try f.conn.pushStreamFrame(4, 0, "req", false);
    _ = try f.conn.writeStream(4, "x", false);
    try f.conn.resetStream(4, 7);
    const mark = f.capture.sent.items.len;
    f.loseEarlierPackets();
    var again: Seen = .{};
    f.capture.frames(mark, &again, Seen.visit);
    try testing.expectEqual(@as(?u64, 1), again.reset_final);
}

test "SONNY-6486 an acknowledged MAX_DATA is not sent again" {
    const f = try Fixture.create(testing.allocator);
    defer f.destroy();
    f.conn.local_max_data += 1;
    f.conn.advertiseInitialFlowControl();
    const pn = f.conn.pn_app_tx - 1;
    f.conn.onAckReceived(pn, 0, &.{});
    const mark = f.capture.sent.items.len;
    f.loseEarlierPackets();
    var again: Seen = .{};
    f.capture.frames(mark, &again, Seen.visit);
    try testing.expectEqual(@as(?u64, null), again.max_data);
}

// ---------------------------------------------------------------------------
// Lossy loopback: real endpoints, chosen datagrams dropped on the way out.
// ---------------------------------------------------------------------------

const skip_under_fips = build_options.fips;
const test_alpn = [_][]const u8{"h3"};
const MiB: usize = 1024 * 1024;
// Wall-clock budget for the lossy-loopback tests. They finish in ~5-7 s on
// an idle machine. Recovery from the dropped frames waits for a PTO, and
// RFC 9002 backs the PTO off exponentially from the smoothed RTT: under
// 2-CPU contention RTT samples reached 1.5 s and the third probe came ~12 s
// later, so a 45 s budget failed 2 of 20 runs without any stall. A real
// stall (frames never resent) never finishes.
const LOSSY_BUDGET_MS: i64 = 240_000;
var next_port = std.atomic.Value(u16).init(20900);

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn sleepUs(us: u64) void {
    const ts = std.os.linux.timespec{ .sec = 0, .nsec = @intCast(us * 1000) };
    _ = std.os.linux.nanosleep(&ts, null);
}

/// Wraps a connection's sender and drops the datagrams `rule` selects,
/// as a lossy network would. Runs under the connection's mutex.
const Dropper = struct {
    orig_ctx: *anyopaque,
    orig_fn: conn_mod.SendFn,
    rule: *const fn (*conn_mod.Connection, frame.Frame) bool,
    dropped: std.atomic.Value(u32) = .init(0),

    fn install(self: *Dropper, c: *conn_mod.Connection) void {
        self.orig_ctx = c.sender_ctx.?;
        self.orig_fn = c.sender_fn.?;
        c.setSender(@ptrCast(self), send);
    }

    fn send(ctx: *anyopaque, c: *conn_mod.Connection, bytes: []const u8) anyerror!usize {
        const self: *Dropper = @ptrCast(@alignCast(ctx));
        if (c.app_tx_keys) |k| {
            const alloc = std.heap.page_allocator;
            if (packet.decodeShortProtected(alloc, bytes, c.shortHeaderDcid().len, k, c.pn_app_tx)) |dec| {
                defer alloc.free(dec.payload);
                var off: usize = 0;
                while (off < dec.payload.len) {
                    const fr = frame.decodeOne(dec.payload[off..]) catch break;
                    off += fr.n;
                    if (self.rule(c, fr.f)) {
                        _ = self.dropped.fetchAdd(1, .monotonic);
                        return bytes.len;
                    }
                }
            } else |_| {}
        }
        return self.orig_fn(self.orig_ctx, c, bytes);
    }
};

const Server = struct {
    ep: *endpoint_mod.Endpoint,
    done: std.atomic.Value(bool) = .init(false),
    dropper: Dropper,
    response: []const u8,
    conn_out: std.atomic.Value(?*api.Connection) = .init(null),

    fn run(self: *Server) void {
        var conn: ?*api.Connection = null;
        var active: [64]api.QuicStreamId = undefined;
        var n_active: usize = 0;
        var scratch: [64 * 1024]u8 = undefined;
        while (!self.done.load(.acquire)) {
            _ = self.ep.pollWithStats(1) catch {};
            if (conn == null) {
                if (api.tryAccept(self.ep)) |c| {
                    c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                    self.dropper.install(c);
                    c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    conn = c;
                    self.conn_out.store(c, .release);
                }
            }
            const c = conn orelse continue;
            while (api.hasIncomingStreams(c)) {
                const sid = api.acceptStream(c) catch break;
                var known = false;
                for (active[0..n_active]) |a| known = known or a == sid;
                if (!known and n_active < active.len) {
                    active[n_active] = sid;
                    n_active += 1;
                }
            }
            var i: usize = 0;
            while (i < n_active) {
                const sid = active[i];
                var finished = false;
                while (true) {
                    const n = api.readStream(c, sid, &scratch) catch break;
                    if (n == 0) {
                        finished = api.isStreamFinished(c, sid);
                        break;
                    }
                }
                if (finished) {
                    _ = api.writeStream(c, sid, self.response, true) catch {};
                    n_active -= 1;
                    active[i] = active[n_active];
                    continue;
                }
                i += 1;
            }
        }
    }
};

fn startServer(alloc: std.mem.Allocator, port: u16, server_cfg: *cfg.QuicConfig) !*endpoint_mod.Endpoint {
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});
    const ep = try alloc.create(endpoint_mod.Endpoint);
    ep.* = try endpoint_mod.Endpoint.init(alloc, bind_addr, server_cfg);
    return ep;
}

fn connectClient(ep: *endpoint_mod.Endpoint, port: u16) !*api.Connection {
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});
    const conn = try api.connect(ep, target, "localhost");
    const deadline = nowMs() + 5_000;
    while (nowMs() < deadline and !api.isHandshakeConfirmed(conn)) _ = ep.pollWithStats(1) catch {};
    if (!api.isHandshakeConfirmed(conn)) return error.HandshakeTimeout;
    return conn;
}

/// Drop every MAX_STREAM_DATA for the client's stream until the server has
/// consumed a full initial stream window (16 MiB): the client has then
/// used up the window and only a retransmission can unblock it.
fn dropEarlyMaxStreamData(c: *conn_mod.Connection, f: frame.Frame) bool {
    if (f != .max_stream_data or f.max_stream_data.stream_id != 0) return false;
    const rx = c.streams_rx.getPtr(0) orelse return false;
    return rx.bytes_consumed_total < c.local_max_stream_data;
}

test "SONNY-6486 lossy loopback: a transfer past the stream window survives lost MAX_STREAM_DATA" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const alloc = testing.allocator;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .inline_server_cert_der = test_certs.server_cert_der, .inline_server_priv_p256 = test_certs.server_key_der, .allow_insecure = true };
    const server_ep = try startServer(alloc, port, &server_cfg);
    defer {
        server_ep.deinit();
        alloc.destroy(server_ep);
    }
    var server = Server{ .ep = server_ep, .dropper = .{ .orig_ctx = undefined, .orig_fn = undefined, .rule = dropEarlyMaxStreamData }, .response = "OK" };
    const st = try std.Thread.spawn(.{}, Server.run, .{&server});
    defer {
        server.done.store(true, .release);
        st.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(alloc, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    const conn = try connectClient(&client_ep, port);
    var cli_done = std.atomic.Value(bool).init(false);
    const ct = try std.Thread.spawn(.{}, struct {
        fn run(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
            while (!done.load(.acquire)) _ = ep.pollWithStats(1) catch {};
        }
    }.run, .{ &client_ep, &cli_done });
    defer {
        cli_done.store(true, .release);
        ct.join();
    }

    const size = 17 * MiB;
    const payload = try alloc.alloc(u8, size);
    defer alloc.free(payload);
    @memset(payload, 0x5a);
    const sid = try api.openStream(conn, true);
    var sent: usize = 0;
    var reply: [8]u8 = undefined;
    var fin = false;
    const deadline = nowMs() + LOSSY_BUDGET_MS;
    while (nowMs() < deadline and !fin) {
        if (sent < size) {
            const n = api.writeStream(conn, sid, payload[sent..], true) catch |err| switch (err) {
                error.FlowControlBlocked => 0,
                else => return err,
            };
            sent += n;
            if (n != 0) continue;
        }
        sleepUs(100);
        const r = api.readStream(conn, sid, &reply) catch continue;
        if (r == 0 and api.isStreamFinished(conn, sid)) fin = true;
    }
    if (!fin) {
        std.debug.print("\n  SONNY-6486: MAX_STREAM_DATA dropped={d}, client wrote {d} of {d} bytes, no reply\n", .{ server.dropper.dropped.load(.monotonic), sent, size });
        if (server.conn_out.load(.acquire)) |sc| {
            const io = std.Io.Threaded.global_single_threaded.io();
            sc.mu.lockUncancelable(io);
            defer sc.mu.unlock(io);
            if (sc.streams_rx.getPtr(0)) |rx| std.debug.print("  server: consumed={d} recv_off={d} lmsd={d} last_sent={d} state={s}\n", .{ rx.bytes_consumed_total, rx.recv_off, rx.local_max_stream_data, rx.last_sent_max_stream_data, @tagName(rx.state) });
            std.debug.print("  server: ctrl tracked={d} pto_active={} pto_count={d} inflight={d} pn_tx={d} srtt_us={d}\n", .{ sc.ctrl_retx.count(), sc.pto_app_active, sc.rec.pto_count, sc.rec.cc.bytes_in_flight, sc.pn_app_tx, sc.rec.rtt.smoothed_rtt_ns / 1000 });
        }
        conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        std.debug.print("  client: peer limit={d} retx tracked={d} retx sent={d} pto_active={} pto_count={d} inflight={d} largest_acked={?d} pn_tx={d} srtt_us={d}\n", .{ conn.peer_max_stream_data, conn.app_stream_retx.count(), conn.stream_retx_packets, conn.pto_app_active, conn.rec.pto_count, conn.rec.cc.bytes_in_flight, conn.rec.spaces[2].largest_acked, conn.pn_app_tx, conn.rec.rtt.smoothed_rtt_ns / 1000 });
        var it = conn.app_stream_retx.iterator();
        var shown: usize = 0;
        while (it.next()) |kv| : (shown += 1) {
            if (shown >= 4) break;
            std.debug.print("  client retx pn={d} off={d} len={d} attempts={d}\n", .{ kv.key_ptr.*, kv.value_ptr.offset, kv.value_ptr.data.len, kv.value_ptr.retransmit_count });
        }
        conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
    }
    try testing.expect(server.dropper.dropped.load(.monotonic) > 0);
    try testing.expectEqual(size, sent);
    try testing.expect(fin);
}

/// Drop every MAX_STREAMS until the client has opened as many streams as
/// the initial limit allows: it is then blocked, and the STREAMS_BLOCKED it
/// sends is dropped too (dropStreamsBlocked), so only a retransmission of
/// the lost credit can unblock it.
fn dropEarlyMaxStreams(c: *conn_mod.Connection, f: frame.Frame) bool {
    return f == .max_streams_bidi and c.peer_stream_next[0] < 1000;
}

fn dropStreamsBlocked(_: *conn_mod.Connection, f: frame.Frame) bool {
    return f == .streams_blocked_bidi;
}

test "SONNY-6486 lossy loopback: more streams than the initial limit despite lost MAX_STREAMS" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;
    const alloc = testing.allocator;
    const port = next_port.fetchAdd(1, .seq_cst);
    var server_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .inline_server_cert_der = test_certs.server_cert_der, .inline_server_priv_p256 = test_certs.server_key_der, .allow_insecure = true };
    const server_ep = try startServer(alloc, port, &server_cfg);
    defer {
        server_ep.deinit();
        alloc.destroy(server_ep);
    }
    var server = Server{ .ep = server_ep, .dropper = .{ .orig_ctx = undefined, .orig_fn = undefined, .rule = dropEarlyMaxStreams }, .response = "resp" };
    const st = try std.Thread.spawn(.{}, Server.run, .{&server});
    defer {
        server.done.store(true, .release);
        st.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(alloc, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    const conn = try connectClient(&client_ep, port);
    var client_drop = Dropper{ .orig_ctx = undefined, .orig_fn = undefined, .rule = dropStreamsBlocked };
    conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    client_drop.install(conn);
    conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());

    const exchanges: usize = 1300;
    var done: usize = 0;
    var buf: [16]u8 = undefined;
    const deadline = nowMs() + LOSSY_BUDGET_MS;
    outer: while (done < exchanges) {
        const sid = while (true) {
            if (nowMs() >= deadline) break :outer;
            break api.openStream(conn, true) catch |err| switch (err) {
                error.OutOfStreams => {
                    _ = client_ep.pollWithStats(1) catch {};
                    continue;
                },
                else => return err,
            };
        };
        while (true) {
            if (nowMs() >= deadline) break :outer;
            const n = api.writeStream(conn, sid, "req", true) catch return error.WriteFailed;
            if (n != 0) break;
            _ = client_ep.pollWithStats(1) catch {};
        }
        while (true) {
            if (nowMs() >= deadline) break :outer;
            _ = client_ep.pollWithStats(1) catch {};
            const n = api.readStream(conn, sid, &buf) catch continue;
            if (n == 0 and api.isStreamFinished(conn, sid)) break;
        }
        done += 1;
    }
    if (done != exchanges) std.debug.print("\n  SONNY-6486: MAX_STREAMS dropped={d}, STREAMS_BLOCKED dropped={d}, exchanges {d} of {d}\n", .{ server.dropper.dropped.load(.monotonic), client_drop.dropped.load(.monotonic), done, exchanges });
    try testing.expect(server.dropper.dropped.load(.monotonic) > 0);
    try testing.expectEqual(exchanges, done);
}
