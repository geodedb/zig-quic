// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test (SONNY-6478): completed request/response streams on one
// long-lived connection.
//
// Geode runs every request on its own bidi stream of one connection. With
// quic v0.1.49, 64 small request/response exchanges on one connection grew
// the median latency from ~40 ms to ~150 ms, and with nothing in flight the
// server kept sending ~370 datagrams/s. Nothing ever retired a finished
// stream, so every per-read flow-control pass walked every stream the
// connection had ever seen, and the stream-count credit (RFC 9000 §4.6
// MAX_STREAMS) was never returned, so a connection could not open more than
// initial_max_streams_bidi streams in its lifetime.
//
// This test drives a real client and server endpoint over loopback through
// the public API, the way an application does: the client opens a stream,
// writes a request with FIN and reads the response to FIN; the server reads
// the request to FIN and answers with FIN. It never calls teardownStream.
// It runs more exchanges than the server's initial_max_streams_bidi (1000),
// then leaves the connection idle and asserts:
//   (a) no STREAM data is retransmitted (loopback, no loss) and nothing is
//       left tracked for retransmission once everything is acknowledged;
//   (b) the idle connection is quiet (no PTO/retransmission traffic);
//   (c) per-exchange latency does not grow with the number of completed
//       streams;
//   (d) stream state of completed streams is retired on both endpoints, and
//       the client can open more streams than the initial stream limit.

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
// complete under -Dfips; the stream lifecycle under test is crypto-agnostic.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";

const HANDSHAKE_TIMEOUT_MS: i64 = 5_000;
// Per-exchange ceiling. A healthy loopback exchange takes well under 10 ms
// even in a Debug build.
const EXCHANGE_TIMEOUT_MS: i64 = 5_000;
// Whole-run budget. A healthy Debug run takes a few seconds; the defect
// makes every exchange slower than the one before.
const RUN_BUDGET_MS: i64 = 60_000;
// More than the server's initial_max_streams_bidi (1000), so the run fails
// unless stream-count credit is returned as streams complete.
const EXCHANGES: usize = 1100;
const IDLE_MS: i64 = 2_000;
const REQUEST_BYTES: usize = 96;
const RESPONSE_BYTES: usize = 600;

var next_port = std.atomic.Value(u16).init(20500);

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

const io = std.Io.Threaded.global_single_threaded.io();

const ConnSnapshot = struct {
    pn_app_tx: u64,
    stream_retx_packets: u64,
    acked_resent_packets: u64,
    retx_tracked: usize,
    streams_rx: usize,
    stream_txs: usize,
};

fn snapshot(conn: *api.Connection) ConnSnapshot {
    conn.mu.lockUncancelable(io);
    defer conn.mu.unlock(io);
    return .{
        .pn_app_tx = conn.pn_app_tx,
        .stream_retx_packets = conn.stream_retx_packets,
        .acked_resent_packets = conn.retx_diag.acked_resent_packets,
        .retx_tracked = if (conn.app_stream_retx_init) conn.app_stream_retx.count() else 0,
        .streams_rx = if (conn.streams_rx_init) conn.streams_rx.count() else 0,
        .stream_txs = if (conn.stream_txs_init) conn.stream_txs.count() else 0,
    };
}

const ServerStream = struct {
    sid: api.QuicStreamId,
    request_bytes: usize = 0,
    response_sent: usize = 0,
    request_done: bool = false,
};

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    conn_out: *std.atomic.Value(?*api.Connection),
    response: []const u8,
    allocator: std.mem.Allocator,
    completed: *std.atomic.Value(u64),
};

fn serverThread(ctx: ServerCtx) void {
    var conn: ?*api.Connection = null;
    var active: std.ArrayList(ServerStream) = .empty;
    defer active.deinit(ctx.allocator);
    var finished: std.AutoHashMapUnmanaged(api.QuicStreamId, void) = .empty;
    defer finished.deinit(ctx.allocator);
    var scratch: [4096]u8 = undefined;

    while (!ctx.done.load(.acquire)) {
        _ = ctx.ep.pollWithStats(1) catch {};
        if (conn == null) {
            if (api.tryAccept(ctx.ep)) |c| {
                c.mu.lockUncancelable(io);
                c.retx_diag.enabled = true;
                c.mu.unlock(io);
                conn = c;
                ctx.conn_out.store(c, .release);
            }
        }
        const c = conn orelse continue;

        while (api.hasIncomingStreams(c)) {
            const sid = api.acceptStream(c) catch break;
            if (finished.contains(sid)) continue;
            var known = false;
            for (active.items) |s| {
                if (s.sid == sid) known = true;
            }
            if (!known) active.append(ctx.allocator, .{ .sid = sid }) catch {};
        }

        var i: usize = 0;
        while (i < active.items.len) {
            const s = &active.items[i];
            while (!s.request_done) {
                const n = api.readStream(c, s.sid, &scratch) catch break;
                if (n == 0) {
                    if (api.isStreamFinished(c, s.sid)) s.request_done = true;
                    break;
                }
                s.request_bytes += n;
            }
            if (s.request_done) {
                while (s.response_sent < ctx.response.len) {
                    const rest = ctx.response[s.response_sent..];
                    const n = api.writeStream(c, s.sid, rest, true) catch break;
                    if (n == 0) break;
                    s.response_sent += n;
                }
                if (s.response_sent == ctx.response.len) {
                    finished.put(ctx.allocator, s.sid, {}) catch {};
                    _ = ctx.completed.fetchAdd(1, .release);
                    _ = active.swapRemove(i);
                    continue;
                }
            }
            i += 1;
        }
    }
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

/// Open a bidi stream, retrying while the peer's stream-count credit is
/// exhausted. Returns null if no credit arrives before the deadline.
fn openStreamWithCredit(ep: *endpoint_mod.Endpoint, conn: *api.Connection, deadline_ms: i64) ?api.QuicStreamId {
    while (nowMs() < deadline_ms) {
        const sid = api.openStream(conn, true) catch |err| switch (err) {
            error.OutOfStreams => {
                _ = ep.pollWithStats(1) catch {};
                continue;
            },
            else => return null,
        };
        return sid;
    }
    return null;
}

test "SONNY-6478 completed streams are retired, never resent, and stay fast on a long-lived connection" {
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

    const response = try allocator.alloc(u8, RESPONSE_BYTES);
    defer allocator.free(response);
    for (response, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);

    var server_done = std.atomic.Value(bool).init(false);
    var server_conn = std.atomic.Value(?*api.Connection).init(null);
    var completed = std.atomic.Value(u64).init(0);
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{ServerCtx{
        .ep = &server_ep,
        .done = &server_done,
        .conn_out = &server_conn,
        .response = response,
        .allocator = allocator,
        .completed = &completed,
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
    conn.mu.lockUncancelable(io);
    conn.retx_diag.enabled = true;
    conn.mu.unlock(io);

    const hs_deadline = nowMs() + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = client_ep.pollWithStats(1) catch {};
    }
    try testing.expect(api.isHandshakeConfirmed(conn));

    var request: [REQUEST_BYTES]u8 = undefined;
    for (&request, 0..) |*b, i| b.* = @truncate(i);

    const latencies = try allocator.alloc(u64, EXCHANGES);
    defer allocator.free(latencies);
    var recv_buf: [4096]u8 = undefined;
    var done_exchanges: usize = 0;
    var failure: ?[]const u8 = null;

    const run_deadline = nowMs() + RUN_BUDGET_MS;
    exchanges: for (0..EXCHANGES) |i| {
        if (nowMs() >= run_deadline) {
            failure = "run budget exceeded (exchanges keep getting slower)";
            break;
        }
        if (i % 100 == 0 and i > 0) {
            testlog.print("  exchange {d}: last latency {d}us\n", .{ i, latencies[i - 1] / 1000 });
        }
        const t0 = nowNs();
        const deadline = @min(nowMs() + EXCHANGE_TIMEOUT_MS, run_deadline);
        const sid = openStreamWithCredit(&client_ep, conn, deadline) orelse {
            failure = "openStream: no stream-count credit (MAX_STREAMS) from the server";
            break;
        };
        var written: usize = 0;
        while (written < request.len) {
            if (nowMs() >= deadline) {
                failure = "request write timed out";
                break :exchanges;
            }
            const n = api.writeStream(conn, sid, request[written..], true) catch |err| {
                std.debug.print("writeStream({d}) failed: {s}\n", .{ sid, @errorName(err) });
                failure = "request write failed";
                break :exchanges;
            };
            if (n == 0) {
                _ = client_ep.pollWithStats(1) catch {};
                continue;
            }
            written += n;
        }
        var got: usize = 0;
        while (true) {
            if (nowMs() >= deadline) {
                failure = "response timed out";
                break :exchanges;
            }
            const n = api.readStream(conn, sid, &recv_buf) catch |err| switch (err) {
                error.WouldBlock => {
                    _ = client_ep.pollWithStats(1) catch {};
                    continue;
                },
                else => {
                    failure = "response read failed";
                    break :exchanges;
                },
            };
            if (n == 0) {
                if (api.isStreamFinished(conn, sid)) break;
                _ = client_ep.pollWithStats(1) catch {};
                continue;
            }
            if (!std.mem.eql(u8, recv_buf[0..n], response[got .. got + n])) {
                failure = "response content mismatch";
                break :exchanges;
            }
            got += n;
        }
        if (got != response.len) {
            failure = "short response";
            break;
        }
        latencies[i] = @intCast(nowNs() - t0);
        done_exchanges += 1;
    }

    // Idle: keep both endpoints polling (ACKs, timers) with nothing to send.
    const srv = server_conn.load(.acquire).?;
    const settle_deadline = nowMs() + 200;
    while (nowMs() < settle_deadline) _ = client_ep.pollWithStats(1) catch {};
    const cli_before = snapshot(conn);
    const srv_before = snapshot(srv);
    const idle_deadline = nowMs() + IDLE_MS;
    while (nowMs() < idle_deadline) _ = client_ep.pollWithStats(1) catch {};
    const cli_after = snapshot(conn);
    const srv_after = snapshot(srv);

    const idle_packets = (cli_after.pn_app_tx - cli_before.pn_app_tx) + (srv_after.pn_app_tx - srv_before.pn_app_tx);

    // Medians of the first and last quarter of the exchanges (275 each):
    // a scheduler stall moves a handful of samples, not a median of 275
    // (20-sample windows flaked on a loaded 2-vCPU runner). The defect grew
    // latency with every completed stream, roughly linearly, which puts the
    // last quarter at about 7x the first.
    var first_med: u64 = 0;
    var last_med: u64 = 0;
    if (done_exchanges >= 4) {
        const q = done_exchanges / 4;
        first_med = median(latencies[0..q]);
        last_med = median(latencies[done_exchanges - q .. done_exchanges]);
    }

    const report_fmt = "\n  SONNY-6478: exchanges={d}/{d} failure={s}\n" ++
        "  latency median first quarter={d}us last quarter={d}us\n" ++
        "  idle {d}ms: packets sent client={d} server={d}\n" ++
        "  STREAM retransmissions: client={d} server={d} (of data already acknowledged: client={d} server={d}); still tracked: client={d} server={d}\n" ++
        "  stream state: client rx={d} tx={d}; server rx={d} tx={d}\n";
    const report_args = .{
        done_exchanges,                             EXCHANGES,
        failure orelse "none",                      first_med / 1000,
        last_med / 1000,                            IDLE_MS,
        cli_after.pn_app_tx - cli_before.pn_app_tx, srv_after.pn_app_tx - srv_before.pn_app_tx,
        cli_after.stream_retx_packets,              srv_after.stream_retx_packets,
        cli_after.acked_resent_packets,             srv_after.acked_resent_packets,
        cli_after.retx_tracked,                     srv_after.retx_tracked,
        cli_after.streams_rx,                       cli_after.stream_txs,
        srv_after.streams_rx,                       srv_after.stream_txs,
    };

    const all_ok = failure == null and done_exchanges == EXCHANGES and
        cli_after.retx_tracked == 0 and srv_after.retx_tracked == 0 and idle_packets <= 4 and
        last_med <= 3 * first_med + 2 * std.time.ns_per_ms and
        cli_after.stream_retx_packets == cli_before.stream_retx_packets and
        srv_after.stream_retx_packets == srv_before.stream_retx_packets and
        cli_after.acked_resent_packets == 0 and srv_after.acked_resent_packets == 0 and
        cli_after.streams_rx + cli_after.stream_txs <= 4 and srv_after.streams_rx + srv_after.stream_txs <= 4;
    if (all_ok) testlog.print(report_fmt, report_args) else std.debug.print(report_fmt, report_args);

    // (d) more streams than initial_max_streams_bidi complete.
    try testing.expect(failure == null);
    try testing.expectEqual(EXCHANGES, done_exchanges);

    // (a) loopback, no loss: no STREAM data was retransmitted, and nothing
    // acknowledged is still tracked for retransmission.
    try testing.expectEqual(@as(usize, 0), cli_after.retx_tracked);
    try testing.expectEqual(@as(usize, 0), srv_after.retx_tracked);
    try testing.expectEqual(srv_before.stream_retx_packets, srv_after.stream_retx_packets);
    try testing.expectEqual(cli_before.stream_retx_packets, cli_after.stream_retx_packets);
    // Data the peer had already acknowledged is never sent again. How many
    // retransmissions happen at all is not asserted: a PTO after a
    // scheduler stall legitimately resends data whose ACK has not arrived
    // yet, so the total depends on the runner (0-12 locally, 26 on a shared
    // CI runner) and is only reported.
    try testing.expectEqual(@as(u64, 0), cli_after.acked_resent_packets);
    try testing.expectEqual(@as(u64, 0), srv_after.acked_resent_packets);

    // (b) idle connection: at most a handful of ACK-only packets.
    try testing.expect(idle_packets <= 4);

    // (c) latency does not grow with the number of completed streams.
    // Generous for noisy CI runners: the defect grew it several-fold.
    try testing.expect(last_med <= 3 * first_med + 2 * std.time.ns_per_ms);

    // (d) completed streams are retired on both endpoints.
    try testing.expect(cli_after.streams_rx + cli_after.stream_txs <= 4);
    try testing.expect(srv_after.streams_rx + srv_after.stream_txs <= 4);

    _ = api.close(conn, 0, "done") catch {};
    _ = client_ep.pollWithStats(1) catch {};
}

const conn_mod = @import("quic_conn");

fn readyServerConn(conn: *conn_mod.Connection, alloc: *std.mem.Allocator) void {
    conn.init(alloc, .Server, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "PEER");
}

/// Acknowledge every packet the connection has sent so far.
fn ackAll(conn: *conn_mod.Connection) void {
    const largest = conn.pn_app_tx - 1;
    conn.onAckReceived(largest, largest, &.{});
}

test "SONNY-6478 a finished peer stream is retired, returns stream credit and ignores late frames" {
    var alloc = testing.allocator;
    var conn: conn_mod.Connection = undefined;
    readyServerConn(&conn, &alloc);
    defer conn.deinit();

    const sid: u64 = 4; // client-initiated bidi
    const limit_before = conn.local_max_streams_bidi;

    try conn.pushStreamFrame(sid, 0, "request", true);
    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 7), try conn.readStream(sid, &buf));
    // Receive side done (Data Read), send side not started: still open.
    try testing.expect(!conn.isStreamRetired(sid));

    try testing.expectEqual(@as(usize, 8), try conn.writeStream(sid, "response", true));
    // FIN sent but not acknowledged yet (Data Sent, not Data Recvd).
    try testing.expect(!conn.isStreamRetired(sid));
    try testing.expect(conn.stream_txs.contains(sid));

    ackAll(&conn);
    try testing.expect(conn.isStreamRetired(sid));
    try testing.expect(!conn.streams_rx.contains(sid));
    try testing.expect(!conn.stream_txs.contains(sid));
    try testing.expectEqual(limit_before + 1, conn.local_max_streams_bidi);
    try testing.expectEqual(@as(usize, 0), conn.app_stream_retx.count());

    // A late retransmission of the request must not resurrect the stream.
    try conn.pushStreamFrame(sid, 0, "request", true);
    try testing.expect(!conn.streams_rx.contains(sid));
    try testing.expect(!conn.hasIncomingStreams() or (conn.acceptStream() catch null) == null);

    // The application sees the end of the stream, and cannot write again.
    try testing.expectEqual(@as(usize, 0), try conn.readStream(sid, &buf));
    try testing.expect(conn.isStreamFinished(sid));
    try testing.expectError(error.StreamStopped, conn.writeStream(sid, "more", false));
    try testing.expectError(error.StreamStopped, conn.closeStream(sid, 0));
}

test "SONNY-6478 streams opened implicitly by a higher stream are not mistaken for retired ones" {
    var alloc = testing.allocator;
    var conn: conn_mod.Connection = undefined;
    readyServerConn(&conn, &alloc);
    defer conn.deinit();

    // Stream 12 arrives first and implicitly opens 0, 4 and 8 (RFC 9000 §3.2).
    try conn.pushStreamFrame(12, 0, "c", true);
    try testing.expect(!conn.isStreamRetired(8));
    try conn.pushStreamFrame(8, 0, "b", true);
    try testing.expect(conn.streams_rx.contains(8));
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try conn.readStream(8, &buf));
    try testing.expectEqual(@as(u8, 'b'), buf[0]);
    // Unused implicitly opened streams stay usable.
    try testing.expect(!conn.isStreamRetired(4));
}

test "SONNY-6478 a closed local stream is retired once its FIN is acknowledged and the response read" {
    var alloc = testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "PEER");

    _ = try conn.openStream(true); // stream 0 (legacy single-stream fields)
    const sid = try conn.openStream(true);
    try testing.expectEqual(@as(u64, 4), sid);
    try testing.expectEqual(@as(usize, 3), try conn.writeStream(sid, "req", false));
    // closeStream's FIN is tracked like data: retransmitted if lost.
    try conn.closeStream(sid, 0);
    try testing.expectEqual(@as(usize, 2), conn.app_stream_retx.count());

    try conn.pushStreamFrame(sid, 0, "resp", true);
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try conn.readStream(sid, &buf));
    try testing.expect(!conn.isStreamRetired(sid)); // FIN not acknowledged yet

    ackAll(&conn);
    try testing.expect(conn.isStreamRetired(sid));
    try testing.expectEqual(@as(usize, 0), try conn.readStream(sid, &buf));
    // Retiring a locally initiated stream returns no credit to the peer.
    try testing.expectEqual(@as(u64, 1000), conn.local_max_streams_bidi);
}

test "SONNY-6478 data acknowledged under its original packet number is not sent again" {
    var alloc = testing.allocator;
    var conn: conn_mod.Connection = undefined;
    conn.init(&alloc, .Client, -1, conn_mod.SockAddr.ipv4(127, 0, 0, 1, 4433));
    defer conn.deinit();
    conn.app_tx_keys = .{ .key = .{0} ** 16, .iv = .{0} ** 12, .hp = .{0} ** 16 };
    conn.peer_finished_verified = true;
    conn.address_validated = true;
    conn.peer_initial_scid.len = 4;
    @memcpy(conn.peer_initial_scid.bytes[0..4], "PEER");
    conn.retx_diag.enabled = true;

    _ = try conn.openStream(true); // stream 0
    const sid = try conn.openStream(true);
    try testing.expectEqual(@as(usize, 7), try conn.writeStream(sid, "request", false)); // pn 0
    // A PTO (e.g. after a scheduler stall) resends it as pn 1.
    conn.sendPtoProbeApp();
    try testing.expectEqual(@as(u64, 1), conn.stream_retx_packets);
    // The ACK for the ORIGINAL packet then arrives: the data is delivered.
    conn.onAckReceived(0, 0, &.{});
    // pn 1 is then lost (three later packets acknowledged).
    for (0..3) |_| conn.sendControlFrames(&[_]u8{0x01});
    conn.onAckReceived(4, 2, &.{});

    // The delivered data must not be sent a third time, and nothing of it
    // may stay tracked.
    try testing.expectEqual(@as(u64, 0), conn.retx_diag.acked_resent_packets);
    try testing.expectEqual(@as(u64, 1), conn.stream_retx_packets);
    try testing.expectEqual(@as(usize, 0), conn.app_stream_retx.count());
}
