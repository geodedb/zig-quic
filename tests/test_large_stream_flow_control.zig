// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-6475): a single stream carrying more than the
// receive window must keep flowing.
//
// Geode sent a 16 MiB request on one stream (quic v0.1.49). Once the
// receiver's initial stream window was used up the transfer crawled: about
// 168 s in ReleaseSafe, and it did not finish in 300 s in Debug.
//
// This test drives a real client and server endpoint over loopback through
// the public API: the client writes N MiB on one bidi stream with FIN, the
// server reads it all (verifying content) and answers "OK" with FIN. These
// end-to-end transfers assert completion and content within a generous
// wall-clock budget; the rate is printed but not asserted, because it is
// set by how much CPU the runner gives the three threads (under 2-CPU
// contention even a fixed ReleaseSafe build ran at 1.2-1.6 MiB/s). The
// regression guard for the crawl itself is the deterministic
// reassembly-work test below, which does not depend on timing.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const testlog = @import("testlog");
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");

// The loopback handshake with the embedded Ed25519 test certificate does not
// complete under -Dfips; flow control is crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";
const HANDSHAKE_TIMEOUT_MS: i64 = 5_000;
const MiB: usize = 1024 * 1024;
// Wall-clock budget: 0.25 MiB/s plus slow start. A healthy Debug run takes
// ~4 s for 16 MiB; geode saw the crawl at ~0.1 MiB/s, which still fails.
const BUDGET_MIB_PER_S: f64 = 0.25;

var next_port = std.atomic.Value(u16).init(20700);

fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

fn nowNs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * std.time.ns_per_s + @as(i64, ts.nsec);
}

fn nowMs() i64 {
    return @divTrunc(nowNs(), std.time.ns_per_ms);
}

/// Linux UDP RcvbufErrors counter (datagrams dropped for a full receive
/// buffer), for the report.
fn udpRcvbufErrors() u64 {
    var buf: [4096]u8 = undefined;
    const fd = std.os.linux.open("/proc/net/snmp", .{ .ACCMODE = .RDONLY }, 0);
    if (@as(isize, @bitCast(fd)) < 0) return 0;
    defer _ = std.os.linux.close(@intCast(fd));
    const n = std.os.linux.read(@intCast(fd), &buf, buf.len);
    if (@as(isize, @bitCast(n)) <= 0) return 0;
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    var header: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "Udp: ")) continue;
        const h = header orelse {
            header = line;
            continue;
        };
        var names = std.mem.tokenizeScalar(u8, h, ' ');
        var vals = std.mem.tokenizeScalar(u8, line, ' ');
        while (names.next()) |name| {
            const v = vals.next() orelse break;
            if (std.mem.eql(u8, name, "RcvbufErrors")) return std.fmt.parseInt(u64, v, 10) catch 0;
        }
        return 0;
    }
    return 0;
}

fn patternByte(i: usize) u8 {
    return @truncate((i *% 131) ^ (i >> 13));
}

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    expected: usize,
    received: *std.atomic.Value(u64),
    corrupt: *std.atomic.Value(bool),
    finished: *std.atomic.Value(bool),
    /// The accepted connection, for the failure report.
    conn_out: *std.atomic.Value(?*api.Connection),
    /// Server loop heartbeat for the failure report.
    polls: *std.atomic.Value(u64),
    last_poll_ms: *std.atomic.Value(i64),
    processed: *std.atomic.Value(u64),
    max_poll_ms: *std.atomic.Value(i64),
};

fn serverThread(ctx: ServerCtx) void {
    var conn: ?*api.Connection = null;
    var sid: ?api.QuicStreamId = null;
    var got: usize = 0;
    var responded = false;
    var scratch: [64 * 1024]u8 = undefined;

    while (!ctx.done.load(.acquire)) {
        const p0 = nowMs();
        if (ctx.ep.pollWithStats(1)) |st| {
            _ = ctx.processed.fetchAdd(st.packets_processed, .monotonic);
        } else |_| {}
        const p1 = nowMs();
        if (p1 - p0 > ctx.max_poll_ms.load(.monotonic)) ctx.max_poll_ms.store(p1 - p0, .monotonic);
        _ = ctx.polls.fetchAdd(1, .monotonic);
        ctx.last_poll_ms.store(p1, .monotonic);
        if (conn == null) {
            conn = api.tryAccept(ctx.ep);
            if (conn) |c| ctx.conn_out.store(c, .release);
        }
        const c = conn orelse continue;
        if (sid == null and api.hasIncomingStreams(c)) sid = api.acceptStream(c) catch null;
        const s = sid orelse continue;
        while (!responded) {
            const n = api.readStream(c, s, &scratch) catch break;
            if (n == 0) {
                if (api.isStreamFinished(c, s) and got == ctx.expected) {
                    // Record it before replying: once the reply is written
                    // the client can see its FIN and check `finished` while
                    // this thread is still preempted.
                    ctx.finished.store(true, .release);
                    _ = api.writeStream(c, s, "OK", true) catch break;
                    responded = true;
                }
                break;
            }
            for (scratch[0..n], got..) |b, i| {
                if (b != patternByte(i)) ctx.corrupt.store(true, .release);
            }
            got += n;
            ctx.received.store(got, .release);
        }
    }
}

/// Polls the client endpoint, as an application's network thread does, so
/// ACKs and flow-control updates are processed while the writer writes.
fn clientPollThread(ep: *endpoint_mod.Endpoint, done: *std.atomic.Value(bool)) void {
    while (!done.load(.acquire)) _ = ep.pollWithStats(1) catch {};
}

fn sleepUs(us: u64) void {
    const ts = std.os.linux.timespec{ .sec = 0, .nsec = @intCast(us * 1000) };
    _ = std.os.linux.nanosleep(&ts, null);
}

/// Both ends' recovery and stream state, to tell where a stalled transfer
/// is stuck (lost data never resent, a lost window update, a lost FIN).
fn reportStall(conn: *api.Connection, sid: api.QuicStreamId, server: ?*api.Connection) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (server) |sc| {
        sc.mu.lockUncancelable(io);
        defer sc.mu.unlock(io);
        if (sc.streams_rx.getPtr(sid)) |rx| std.debug.print("  server rx: consumed={d} recv_off={d} lmsd={d} last_sent={d} state={s}\n", .{ rx.bytes_consumed_total, rx.recv_off, rx.local_max_stream_data, rx.last_sent_max_stream_data, @tagName(rx.state) });
        if (sc.stream_txs.getPtr(sid)) |tx| std.debug.print("  server tx: state={s}\n", .{@tagName(tx.state)});
        std.debug.print("  server keys: rx_phase={} tx_phase={} tx_update_in_progress={} rx_prev_keys={} largest_rx_pn={d}\n", .{ sc.rx_key_phase, sc.tx_key_phase, sc.tx_update_in_progress, sc.rx_prev_keys != null, sc.pn_app.max });
        std.debug.print("  server: ctrl tracked={d} stream retx tracked={d} retx sent={d} pto_active={} pto_count={d} pto_app_count={d} inflight={d} cwnd={d} largest_acked={?d} pn_tx={d} srtt_us={d} rtt_sample={}\n", .{ sc.ctrl_retx.count(), sc.app_stream_retx.count(), sc.stream_retx_packets, sc.pto_app_active, sc.rec.pto_count, sc.pto_app_count, sc.rec.cc.bytes_in_flight, sc.rec.cc.cwnd, sc.rec.spaces[2].largest_acked, sc.pn_app_tx, sc.rec.rtt.smoothed_rtt_ns / 1000, sc.rec.rtt.have_sample });
    }
    conn.mu.lockUncancelable(io);
    defer conn.mu.unlock(io);
    std.debug.print("  client keys: rx_phase={} tx_phase={} tx_update_in_progress={} rx_prev_keys={} largest_rx_pn={d}\n", .{ conn.rx_key_phase, conn.tx_key_phase, conn.tx_update_in_progress, conn.rx_prev_keys != null, conn.pn_app.max });
    if (conn.stream_txs.getPtr(sid)) |tx| std.debug.print("  client tx: peer limit={d} state={s}\n", .{ tx.peer_max_stream_data, @tagName(tx.state) });
    std.debug.print("  client: conn peer limit={d} retx tracked={d} retx sent={d} pto_active={} pto_count={d} pto_app_count={d} inflight={d} cwnd={d} largest_acked={?d} pn_tx={d} srtt_us={d}\n", .{ conn.peer_max_stream_data, conn.app_stream_retx.count(), conn.stream_retx_packets, conn.pto_app_active, conn.rec.pto_count, conn.pto_app_count, conn.rec.cc.bytes_in_flight, conn.rec.cc.cwnd, conn.rec.spaces[2].largest_acked, conn.pn_app_tx, conn.rec.rtt.smoothed_rtt_ns / 1000 });
    const now_i = @import("compat").nanoTimestamp();
    const now_ns: u64 = @intCast(@max(0, now_i));
    if (conn.rec.ptoDeadlineNs(.Application)) |d| std.debug.print("  client: app PTO due in {d} ms\n", .{if (d > now_ns) (d - now_ns) / 1_000_000 else 0}) else std.debug.print("  client: no app PTO deadline\n", .{});
    var it = conn.app_stream_retx.iterator();
    var shown: usize = 0;
    while (it.next()) |kv| : (shown += 1) {
        if (shown >= 4) break;
        std.debug.print("  client retx pn={d} off={d} len={d} attempts={d}\n", .{ kv.key_ptr.*, kv.value_ptr.offset, kv.value_ptr.data.len, kv.value_ptr.retransmit_count });
    }
}

fn transfer(size: usize) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;

    const allocator = testing.allocator;
    const port = allocatePort();
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});
    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
        .allow_insecure = true,
    };
    var server_ep = try endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg);
    defer server_ep.deinit();

    var server_done = std.atomic.Value(bool).init(false);
    var received = std.atomic.Value(u64).init(0);
    var corrupt = std.atomic.Value(bool).init(false);
    var finished = std.atomic.Value(bool).init(false);
    var server_conn = std.atomic.Value(?*api.Connection).init(null);
    var server_polls = std.atomic.Value(u64).init(0);
    var server_last_poll = std.atomic.Value(i64).init(0);
    var server_processed = std.atomic.Value(u64).init(0);
    var server_max_poll = std.atomic.Value(i64).init(0);
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{ServerCtx{
        .ep = &server_ep,
        .done = &server_done,
        .expected = size,
        .received = &received,
        .corrupt = &corrupt,
        .finished = &finished,
        .conn_out = &server_conn,
        .polls = &server_polls,
        .last_poll_ms = &server_last_poll,
        .processed = &server_processed,
        .max_poll_ms = &server_max_poll,
    }});
    defer {
        server_done.store(true, .release);
        srv_thread.join();
    }

    var cli_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client_ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});
    const conn = try api.connect(&client_ep, target, SERVER_SNI);
    const hs_deadline = nowMs() + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = client_ep.pollWithStats(1) catch {};
    }
    try testing.expect(api.isHandshakeConfirmed(conn));

    const payload = try allocator.alloc(u8, size);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = patternByte(i);

    const budget_ms: i64 = @intFromFloat(@as(f64, @floatFromInt(size / MiB)) / BUDGET_MIB_PER_S * 1000.0 + 5000.0);
    var client_done = std.atomic.Value(bool).init(false);
    const cli_thread = try std.Thread.spawn(.{}, clientPollThread, .{ &client_ep, &client_done });
    defer {
        client_done.store(true, .release);
        cli_thread.join();
    }

    const drops_before = udpRcvbufErrors();
    const t0 = nowNs();
    const deadline = nowMs() + budget_ms;
    const sid = try api.openStream(conn, true);
    var sent: usize = 0;
    var blocked_writes: usize = 0;
    var reply: [16]u8 = undefined;
    var reply_len: usize = 0;
    var reply_fin = false;
    while (nowMs() < deadline and !reply_fin) {
        if (sent < size) {
            const n = api.writeStream(conn, sid, payload[sent..], true) catch |err| switch (err) {
                error.FlowControlBlocked => 0,
                else => return err,
            };
            sent += n;
            if (n != 0) continue;
            blocked_writes += 1;
        }
        sleepUs(100);
        const r = api.readStream(conn, sid, reply[reply_len..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        reply_len += r;
        if (r == 0 and api.isStreamFinished(conn, sid)) reply_fin = true;
    }
    const elapsed_ns: u64 = @intCast(nowNs() - t0);
    const secs = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const delivered = received.load(.acquire);
    const rate = @as(f64, @floatFromInt(delivered)) / @as(f64, MiB) / @max(secs, 1e-9);

    const drops = udpRcvbufErrors() -| drops_before;
    const retx = conn.stream_retx_packets;
    const ok = reply_fin and delivered == size and !corrupt.load(.acquire);
    const report_fmt = "\n  SONNY-6475: {d} MiB on one stream: sent={d} delivered={d} in {d:.2}s = {d:.2} MiB/s, blocked writes={d}, reply_fin={}, host UDP rcvbuf drops={d}, client STREAM retransmissions={d}\n";
    const report_args = .{ size / MiB, sent, delivered, secs, rate, blocked_writes, reply_fin, drops, retx };
    if (ok) testlog.print(report_fmt, report_args) else {
        std.debug.print(report_fmt, report_args);
        std.debug.print("  server loop: {d} polls, {d} packets processed, longest poll {d} ms, last poll {d} ms ago\n", .{ server_polls.load(.monotonic), server_processed.load(.monotonic), server_max_poll.load(.monotonic), nowMs() - server_last_poll.load(.monotonic) });
        reportStall(conn, sid, server_conn.load(.acquire));
    }

    try testing.expect(!corrupt.load(.acquire));
    try testing.expectEqual(@as(u64, size), delivered);
    try testing.expect(finished.load(.acquire));
    try testing.expect(reply_fin);
    try testing.expectEqualStrings("OK", reply[0..reply_len]);

    _ = api.close(conn, 0, "done") catch {};
}

test "SONNY-6475 16 MiB on one stream is not throttled by the receive window" {
    try transfer(16 * MiB);
}

test "SONNY-6475 64 MiB on one stream is not throttled by the receive window" {
    try transfer(64 * MiB);
}

const conn_mod = @import("quic_conn");

test "SONNY-6475 reassembly work per packet does not grow with the data buffered behind a hole" {
    var alloc = testing.allocator;
    var rx = conn_mod.StreamRx.init();
    defer rx.deinit(&alloc);

    // The first packet of a 16 MiB window is lost; the other ~12k arrive
    // in order and wait behind the hole, as pushStreamFrame delivers them.
    const seg_len = 1350;
    const segments: usize = 12_000;
    var data: [seg_len]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    for (1..segments + 1) |k| {
        rx.insert(&alloc, k * seg_len, &data);
        rx.tryDrain(&alloc);
    }
    try testing.expectEqual(@as(u64, 0), rx.recv_off);
    // Contiguous data behind the hole is one segment (SONNY-6649).
    try testing.expectEqual(@as(usize, 1), rx.bufs.items.len);
    try testing.expectEqual(@as(u64, segments * seg_len), rx.buffered_bytes);

    // The retransmission fills the hole and everything drains.
    rx.insert(&alloc, 0, &data);
    rx.tryDrain(&alloc);
    try testing.expectEqual(@as(u64, (segments + 1) * seg_len), rx.recv_off);
    try testing.expectEqual(@as(usize, 0), rx.bufs.items.len);
    try testing.expectEqual(@as(u64, 0), rx.buffered_bytes);

    // A binary search per insert plus one visit per segment drained, about
    // 17 steps per packet here. Sorting and walking every buffered segment on
    // each packet, as v0.1.49 did, is ~72 million.
    try testing.expect(rx.reassembly_steps <= 32 * (segments + 1));
}

test "SONNY-6475 retransmissions re-chunked across buffered segments reassemble exactly" {
    var alloc = testing.allocator;
    var rx = conn_mod.StreamRx.init();
    defer rx.deinit(&alloc);

    var src: [300]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);

    // [100, 200) and [250, 300) arrive; [0, 100) and [200, 250) are lost.
    rx.insert(&alloc, 100, src[100..200]);
    rx.insert(&alloc, 250, src[250..300]);
    rx.tryDrain(&alloc);
    try testing.expectEqual(@as(u64, 0), rx.recv_off);
    // An exact duplicate is not buffered twice.
    rx.insert(&alloc, 100, src[100..200]);
    try testing.expectEqual(@as(usize, 2), rx.bufs.items.len);

    // The peer resends with different boundaries: [0, 150) overlaps the
    // buffered [100, 200), then [180, 260) overlaps both neighbours.
    rx.insert(&alloc, 0, src[0..150]);
    rx.tryDrain(&alloc);
    try testing.expectEqual(@as(u64, 200), rx.recv_off);
    rx.insert(&alloc, 180, src[180..260]);
    rx.tryDrain(&alloc);
    try testing.expectEqual(@as(u64, 300), rx.recv_off);
    try testing.expectEqualSlices(u8, &src, rx.inbox.items);
    try testing.expectEqual(@as(usize, 0), rx.bufs.items.len);

    // Data already delivered is dropped, not buffered.
    rx.insert(&alloc, 0, src[0..300]);
    try testing.expectEqual(@as(usize, 0), rx.bufs.items.len);
}
