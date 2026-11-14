// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Tail-loss liveness (RFC 9002 §6.2): when the last ack-eliciting packets of
// a flight are lost, no later packet can be acknowledged, so ACK-based loss
// detection never fires; only the PTO probe recovers them. Real endpoints
// over loopback, chosen datagrams dropped on the way out. A missing or
// mis-armed PTO never completes; a working one completes within a few PTOs
// (tens of milliseconds on loopback). The budgets below are generous so
// that only a stall, not a slow scheduler, fails them.

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

const test_alpn = [_][]const u8{"h3"};
const BUDGET_MS: i64 = 20_000;
var next_port = std.atomic.Value(u16).init(21900);

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// Drops the datagrams `rule` selects; runs under the connection's mutex.
const Dropper = struct {
    orig_ctx: *anyopaque = undefined,
    orig_fn: conn_mod.SendFn = undefined,
    /// How many more datagrams matching `want` to drop.
    budget: u32,
    want: enum { stream_fin, any_stream },
    dropped: std.atomic.Value(u32) = .init(0),

    fn install(self: *Dropper, c: *conn_mod.Connection) void {
        self.orig_ctx = c.sender_ctx.?;
        self.orig_fn = c.sender_fn.?;
        c.setSender(@ptrCast(self), send);
    }

    fn matches(self: *Dropper, f: frame.Frame) bool {
        if (f != .stream) return false;
        return switch (self.want) {
            .stream_fin => f.stream.fin,
            .any_stream => true,
        };
    }

    fn send(ctx: *anyopaque, c: *conn_mod.Connection, bytes: []const u8) anyerror!usize {
        const self: *Dropper = @ptrCast(@alignCast(ctx));
        if (self.budget > 0) if (c.app_tx_keys) |k| {
            const alloc = std.heap.page_allocator;
            if (packet.decodeShortProtected(alloc, bytes, c.shortHeaderDcid().len, k, c.pn_app_tx)) |dec| {
                defer alloc.free(dec.payload);
                var off: usize = 0;
                while (off < dec.payload.len) {
                    const fr = frame.decodeOne(dec.payload[off..]) catch break;
                    off += fr.n;
                    if (self.matches(fr.f)) {
                        self.budget -= 1;
                        _ = self.dropped.fetchAdd(1, .monotonic);
                        return bytes.len;
                    }
                }
            } else |_| {}
        };
        return self.orig_fn(self.orig_ctx, c, bytes);
    }
};

/// Answers "OK" with FIN once the request stream is finished.
const Server = struct {
    ep: *endpoint_mod.Endpoint,
    dropper: ?*Dropper,
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *Server) void {
        var conn: ?*api.Connection = null;
        var sid: ?api.QuicStreamId = null;
        var answered = false;
        var scratch: [4096]u8 = undefined;
        while (!self.done.load(.acquire)) {
            _ = self.ep.pollWithStats(1) catch {};
            if (conn == null) {
                if (api.tryAccept(self.ep)) |c| {
                    if (self.dropper) |d| {
                        c.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
                        d.install(c);
                        c.mu.unlock(std.Io.Threaded.global_single_threaded.io());
                    }
                    conn = c;
                }
            }
            const c = conn orelse continue;
            if (sid == null and api.hasIncomingStreams(c)) sid = api.acceptStream(c) catch null;
            const s = sid orelse continue;
            if (answered) continue;
            while (true) {
                const n = api.readStream(c, s, &scratch) catch break;
                if (n == 0) break;
            }
            if (api.isStreamFinished(c, s)) {
                _ = api.writeStream(c, s, "OK", true) catch continue;
                answered = true;
            }
        }
    }
};

/// Client recovery state once HANDSHAKE_DONE was processed (Initial and
/// Handshake keys gone), before any application data is written.
const Confirmed = struct {
    initial_tracked: usize,
    handshake_tracked: usize,
    pto_count: u32,
    bytes_in_flight: usize,
    app_tracked_bytes: usize,
};

const Outcome = struct { ms: i64, completed: bool, client_pto: u32, rtt_sample: bool, srtt_us: u64, rec_pto: u32, retx: u64, confirmed: Confirmed };

fn exchange(server_drop: ?*Dropper, client_drop: ?*Dropper) !Outcome {
    const alloc = testing.allocator;
    const port = next_port.fetchAdd(1, .seq_cst);
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});
    var server_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .inline_server_cert_der = test_certs.server_cert_der, .inline_server_priv_p256 = test_certs.server_key_der, .allow_insecure = true };
    var server_ep = try endpoint_mod.Endpoint.init(alloc, bind_addr, &server_cfg);
    defer server_ep.deinit();
    var server = Server{ .ep = &server_ep, .dropper = server_drop };
    const th = try std.Thread.spawn(.{}, Server.run, .{&server});
    defer {
        server.done.store(true, .release);
        th.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(alloc, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});
    const conn = try api.connect(&client_ep, target, "localhost");
    const hs_deadline = nowMs() + BUDGET_MS;
    while (nowMs() < hs_deadline and !api.isHandshakeConfirmed(conn)) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(api.isHandshakeConfirmed(conn));
    if (client_drop) |d| {
        conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        d.install(conn);
        conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
    }

    // HANDSHAKE_DONE confirms the handshake for the client (RFC 9001 §4.1.2).
    while (nowMs() < hs_deadline and !conn.handshake_done_seen) _ = client_ep.pollWithStats(1) catch {};
    try testing.expect(conn.handshake_done_seen);
    conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    var app_bytes: usize = 0;
    for (conn.rec.spaces[2].sent.items) |sp| {
        if (sp.ack_eliciting and !sp.acked and !sp.declared_lost) app_bytes += sp.size;
    }
    const confirmed = Confirmed{
        .initial_tracked = conn.rec.spaces[0].sent.items.len,
        .handshake_tracked = conn.rec.spaces[1].sent.items.len,
        .pto_count = conn.rec.pto_count,
        .bytes_in_flight = conn.rec.cc.bytes_in_flight,
        .app_tracked_bytes = app_bytes,
    };
    conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
    const t0 = nowMs();
    const sid = try api.openStream(conn, true);
    _ = try api.writeStream(conn, sid, "request", true);
    var reply: [8]u8 = undefined;
    var got: usize = 0;
    var completed = false;
    while (nowMs() - t0 < BUDGET_MS) {
        _ = client_ep.pollWithStats(1) catch {};
        const n = api.readStream(conn, sid, reply[got..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        got += n;
        if (n == 0 and api.isStreamFinished(conn, sid)) {
            completed = true;
            break;
        }
    }
    const out = Outcome{
        .ms = nowMs() - t0,
        .completed = completed,
        .client_pto = conn.pto_app_count,
        .rtt_sample = conn.rec.rtt.have_sample,
        .srtt_us = conn.rec.rtt.smoothed_rtt_ns / 1000,
        .rec_pto = conn.rec.pto_count,
        .retx = conn.stream_retx_packets,
        .confirmed = confirmed,
    };
    if (completed) try testing.expectEqualStrings("OK", reply[0..got]);
    _ = api.close(conn, 0, "done") catch {};
    return out;
}

fn report(name: []const u8, o: Outcome, dropped: u32) void {
    std.debug.print("\n  tail-loss {s}: completed={} in {d} ms, dropped={d}, client pto_app_count={d} rtt_sample={} srtt_us={d} rec.pto_count={d} stream_retx={d}\n", .{ name, o.completed, o.ms, dropped, o.client_pto, o.rtt_sample, o.srtt_us, o.rec_pto, o.retx });
}

test "a confirmed client has discarded its Initial and Handshake recovery state" {
    // RFC 9001 §4.9 and RFC 9002 §6.4 / A.11: once keys for a space are
    // discarded, its packets leave bytes_in_flight and the PTO backoff is
    // reset. They used to stay: on a starved machine Initial and Handshake
    // PTO probes during a slow handshake left hundreds of packets "in
    // flight" for ever and raised the shared PTO backoff past 300, so the
    // application PTO deadline was effectively infinite and a lost request
    // was never probed for (high-parallel test, SONNY-6478 v0.1.51 CI).
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (build_options.fips) return error.SkipZigTest;
    const o = try exchange(null, null);
    const c = o.confirmed;
    std.debug.print("\n  confirmed client: initial tracked={d} handshake tracked={d} pto_count={d} bytes_in_flight={d} (app {d})\n", .{ c.initial_tracked, c.handshake_tracked, c.pto_count, c.bytes_in_flight, c.app_tracked_bytes });
    try testing.expect(o.completed);
    try testing.expectEqual(@as(usize, 0), c.initial_tracked);
    try testing.expectEqual(@as(usize, 0), c.handshake_tracked);
    try testing.expectEqual(@as(u32, 0), c.pto_count);
    try testing.expectEqual(c.app_tracked_bytes, c.bytes_in_flight);
}

test "a lost final reply packet (the FIN) is recovered by the PTO probe" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (build_options.fips) return error.SkipZigTest;
    var d = Dropper{ .budget = 1, .want = .stream_fin };
    const o = try exchange(&d, null);
    report("server FIN", o, d.dropped.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), d.dropped.load(.monotonic));
    try testing.expect(o.completed);
}

test "a lost request (all of its STREAM packets) is recovered by the PTO probe" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (build_options.fips) return error.SkipZigTest;
    var d = Dropper{ .budget = 1, .want = .any_stream };
    const o = try exchange(null, &d);
    report("client request", o, d.dropped.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), d.dropped.load(.monotonic));
    try testing.expect(o.completed);
}

test "repeated tail loss is recovered by backed-off PTO probes" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (build_options.fips) return error.SkipZigTest;
    // The reply and its first two retransmissions are lost.
    var d = Dropper{ .budget = 3, .want = .stream_fin };
    const o = try exchange(&d, null);
    report("server FIN x3", o, d.dropped.load(.monotonic));
    try testing.expectEqual(@as(u32, 3), d.dropped.load(.monotonic));
    try testing.expect(o.completed);
}

test "Initial PTO probes follow the backed-off RFC 9002 deadline, not every timer wake-up" {
    // NEWGAP-10: the Initial and Handshake PTO timers wake at least every
    // 100 ms and used to send a probe, raising the backoff shared with
    // application data, on every wake-up. A slow handshake on a starved
    // runner then pushed pto_count above 240 and left the application PTO
    // deadline effectively infinite (high-parallel test, v0.1.51 CI).
    // With no RTT sample the first PTO is about 1 s (RFC 9002 §6.2.2), so
    // in 1.5 s a client with no reachable server sends its Initial and at
    // most one round of probes. A slower scheduler only lowers the count.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (build_options.fips) return error.SkipZigTest;
    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var ep = try endpoint_mod.Endpoint.init(testing.allocator, "127.0.0.1:0", &cli_cfg);
    defer ep.deinit();
    const conn = try api.connect(&ep, "127.0.0.1:9", "localhost");
    const t0 = nowMs();
    while (nowMs() - t0 < 1_500) _ = ep.pollWithStats(1) catch {};
    conn.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    const initials = conn.pn_initial_tx;
    const pto_count = conn.rec.pto_count;
    conn.mu.unlock(std.Io.Threaded.global_single_threaded.io());
    std.debug.print("\n  black-hole dial: {d} Initial packets and pto_count={d} in 1.5 s\n", .{ initials, pto_count });
    try testing.expect(pto_count <= 2);
    try testing.expect(initials <= 4);
    api.destroy(&ep, conn);
}
