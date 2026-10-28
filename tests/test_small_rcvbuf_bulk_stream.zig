// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test: bulk server->client stream transfer stalls when the
// receiver's kernel UDP receive buffer is small.
//
// Geode `backup create` streams a ~470 KB backup over one bidi stream.
// On Docker/AWS hosts net.core.rmem_max defaults to 212992, so quic's
// 16 MiB SO_RCVBUF request is clamped and the receiver drops datagrams
// whenever the sender bursts faster than the client drains. The client
// printed "Progress: 0%" and hung until timeout.
//
// This test pins the receiver's SO_RCVBUF to 106496 (kernel doubles it
// to ~212 KB, the Docker default) and pushes 1 MiB on one stream. The
// transfer must complete (all bytes + FIN, content verified) within the
// deadline.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const test_certs = @import("test_certs");
const build_options = @import("quic_build_options");

// The loopback handshake with the embedded Ed25519 test certificate does not
// complete under -Dfips (FIPS signature/key-share policy). The loss-recovery
// path under test is crypto-agnostic and is covered by the -Dfips=false gate,
// so skip in FIPS mode, as tests/test_pending_hs_send_retry.zig does.
const skip_under_fips = build_options.fips;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";

// Per-handshake timeout. Generous to absorb scheduler jitter on
// CI runners; the bug repro itself triggers within ~hundreds of ms
// of handshake completion, so this is just slack for setup.
const HANDSHAKE_TIMEOUT_MS: i64 = 5_000;

// Per-RT (write+read) timeout. The bug surfaces as the read loop
// stalling indefinitely once ~12 KiB of data has been received --
// 10s is far more than a healthy localhost transfer needs (which
// finishes in tens of ms) and matches the geode reproducer's
// 30s ceiling profile while staying inside the test budget.
const RT_TIMEOUT_MS: i64 = 20_000;

// Response size. 32 KiB is roughly 2x the documented stall threshold
// of ~12-18 KiB and exercises both initial cwnd exhaustion and
// subsequent slow-start growth. A passing run transfers all 32 KiB
// plus FIN; a failing run (pre-fix) gets stuck around 12 KiB delivered
// because cwnd never grows past the initial value once standalone
// ACKs cannot be routed back to the connection. We deliberately stay
// well below 64 KiB so the test stays robust against UDP receive-buffer
// pressure on busy CI runners while still being many multiples past
// the bug threshold.
const RESPONSE_BYTES: usize = 1024 * 1024;

// SO_RCVBUF requested on the receiver. Linux doubles it, giving the
// 212992-byte buffer that Docker/AWS hosts cap at (rmem_max default).
const SMALL_RCVBUF: i32 = 106496;

// Atomic port allocator. Sits in 19700+ range to avoid collisions
// with handshake_e2e.zig (18900+), test_concurrent_handshake_race
// (19500+), and stream_throughput (19400+).
var next_port = std.atomic.Value(u16).init(20100);

fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

const StreamState = struct {
    stream_id: api.QuicStreamId,
    request_seen: bool,
    request_bytes: usize,
    sent_bytes: usize,
    fin_sent: bool,
};

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    response_payload: []const u8,
    allocator: std.mem.Allocator,
    bytes_pushed: *std.atomic.Value(u64),
};

// Try to push response bytes / FIN for one stream. Returns true on
// any forward progress. Used both during the main loop and the
// final drain so the trailing tail of the response (and its FIN)
// gets onto the wire even if the server thread is wrapping up.
fn pumpResponse(
    conn: *api.Connection,
    s: *StreamState,
    response: []const u8,
    bytes_pushed: *std.atomic.Value(u64),
) bool {
    if (s.fin_sent or !s.request_seen) return false;
    var progress = false;
    while (s.sent_bytes < response.len) {
        const remaining = response[s.sent_bytes..];
        const written = api.writeStream(conn, s.stream_id, remaining, false) catch break;
        if (written == 0) break; // CC-blocked or peer-fc; retry next tick
        s.sent_bytes += written;
        _ = bytes_pushed.fetchAdd(written, .seq_cst);
        progress = true;
    }
    if (s.sent_bytes == response.len and !s.fin_sent) {
        _ = api.writeStream(conn, s.stream_id, &[_]u8{}, true) catch return progress;
        s.fin_sent = true;
        progress = true;
    }
    return progress;
}

fn serverThread(ctx: ServerCtx) void {
    var conns: std.ArrayList(*api.Connection) = .empty;
    defer conns.deinit(ctx.allocator);
    var states_by_conn: std.ArrayList(std.ArrayList(StreamState)) = .empty;
    defer {
        for (states_by_conn.items) |*per| per.deinit(ctx.allocator);
        states_by_conn.deinit(ctx.allocator);
    }
    var scratch: [4096]u8 = undefined;

    while (!ctx.done.load(.acquire)) {
        _ = ctx.ep.pollWithStats(1) catch {};

        while (api.tryAccept(ctx.ep)) |c| {
            conns.append(ctx.allocator, c) catch continue;
            states_by_conn.append(ctx.allocator, .empty) catch continue;
        }

        for (conns.items, states_by_conn.items) |conn, *states| {
            while (api.hasIncomingStreams(conn)) {
                const sid = api.acceptStream(conn) catch break;
                states.append(ctx.allocator, .{
                    .stream_id = sid,
                    .request_seen = false,
                    .request_bytes = 0,
                    .sent_bytes = 0,
                    .fin_sent = false,
                }) catch {};
            }

            for (states.items) |*s| {
                if (s.fin_sent) continue;

                // Drain the client's small request bytes (and the FIN
                // that closes the request half).
                while (true) {
                    const n = api.readStream(conn, s.stream_id, &scratch) catch |err| {
                        if (err == error.WouldBlock) break;
                        break;
                    };
                    if (n == 0) {
                        if (api.isStreamFinished(conn, s.stream_id)) s.request_seen = true;
                        break;
                    }
                    s.request_bytes += n;
                }

                _ = pumpResponse(conn, s, ctx.response_payload, ctx.bytes_pushed);
            }
        }
    }

    // Final drain: keep poll-and-flush running so any pending TX
    // (especially the trailing FIN frame and its retransmissions)
    // make it onto the wire before deinit.
    var drain: usize = 0;
    while (drain < 50) : (drain += 1) {
        _ = ctx.ep.pollWithStats(1) catch {};
        for (conns.items, states_by_conn.items) |conn, *states| {
            for (states.items) |*s| {
                _ = pumpResponse(conn, s, ctx.response_payload, ctx.bytes_pushed);
            }
        }
    }
}

test "small_rcvbuf: bulk stream transfer completes with small receiver SO_RCVBUF" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (skip_under_fips) return error.SkipZigTest;

    const allocator = testing.allocator;

    // ----- Server endpoint -----
    const port = allocatePort();
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = test_certs.server_cert_der,
        .inline_server_priv_p256 = test_certs.server_key_der,
        .allow_insecure = true,
    };
    const alloc_for_init = allocator;
    var server_ep = try endpoint_mod.Endpoint.init(alloc_for_init, bind_addr, &server_cfg);
    defer server_ep.deinit();

    var target_buf: [32]u8 = undefined;
    const server_target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});

    // Deterministic byte pattern so the client can verify content,
    // not just length. A stall that *does* eventually catch up
    // mustn't accidentally pass on length alone.
    const response = try allocator.alloc(u8, RESPONSE_BYTES);
    defer allocator.free(response);
    for (response, 0..) |*b, i| b.* = @truncate(i);

    var server_done = std.atomic.Value(bool).init(false);
    var bytes_pushed = std.atomic.Value(u64).init(0);

    const srv_ctx = ServerCtx{
        .ep = &server_ep,
        .done = &server_done,
        .response_payload = response,
        .allocator = allocator,
        .bytes_pushed = &bytes_pushed,
    };
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{srv_ctx});
    defer {
        server_done.store(true, .release);
        srv_thread.join();
    }

    // ----- Client endpoint -----
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    const alloc_for_cli = allocator;
    var client_ep = try endpoint_mod.Endpoint.init(alloc_for_cli, "127.0.0.1:0", &cli_cfg);
    defer client_ep.deinit();

    // Shrink the receiver's kernel buffer to the Docker/AWS default.
    {
        const fd = client_ep.owned_udp_transport.?.fd;
        var size: i32 = SMALL_RCVBUF;
        const linux = std.os.linux;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, @ptrCast(std.mem.asBytes(&size)), @sizeOf(i32));
    }

    const conn = try api.connect(&client_ep, server_target, SERVER_SNI);

    const hs_deadline = nowMs() + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = client_ep.pollWithStats(1) catch {};
    }
    try testing.expect(api.isHandshakeConfirmed(conn));

    const sid = try api.openStream(conn, true);
    const request = "PING-REQ"; // 8 bytes, single packet.
    var sent: usize = 0;
    while (sent < request.len) {
        const last_chunk = (request.len - sent) == (request.len - sent); // always true; mark every write as last so FIN flushes
        const n = try api.writeStream(conn, sid, request[sent..], last_chunk);
        if (n == 0) {
            _ = client_ep.pollWithStats(1) catch {};
            continue;
        }
        sent += n;
    }

    // Drain the response. Pre-fix this loop times out around
    // ~12-18 KiB delivered with no FIN; post-fix it completes the
    // full RESPONSE_BYTES + FIN within tens of ms on loopback.
    var recv_scratch: [8 * 1024]u8 = undefined;
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(allocator);

    const rt_deadline = nowMs() + RT_TIMEOUT_MS;
    var fin_seen = false;
    while (nowMs() < rt_deadline) {
        _ = client_ep.pollWithStats(1) catch {};
        const n = api.readStream(conn, sid, &recv_scratch) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => break,
        };
        if (n == 0) {
            if (api.isStreamFinished(conn, sid)) {
                fin_seen = true;
                break;
            }
            continue;
        }
        try received.appendSlice(allocator, recv_scratch[0..n]);
        if (received.items.len >= response.len and api.isStreamFinished(conn, sid)) {
            fin_seen = true;
            break;
        }
    }

    if (!fin_seen or received.items.len != response.len) {
        std.debug.print(
            "\n  FAIL: bulk stream stalled with small SO_RCVBUF.\n" ++
                "  expected: received={d}B + FIN\n" ++
                "  got:      received={d}B fin_seen={}\n" ++
                "  server-side bytes_pushed={d}\n",
            .{ response.len, received.items.len, fin_seen, bytes_pushed.load(.acquire) },
        );
    }

    try testing.expect(fin_seen);
    try testing.expectEqual(response.len, received.items.len);

    // Content verification: protect against a "cwnd grows but data
    // is corrupted" regression elsewhere in the path.
    for (received.items, 0..) |b, i| {
        const want: u8 = @truncate(i);
        if (b != want) {
            std.debug.print(
                "\n  FAIL: response byte mismatch at offset {d}: want={x:0>2} got={x:0>2}\n",
                .{ i, want, b },
            );
            return error.TestExpectedEqual;
        }
    }

    _ = api.close(conn, 0, "done") catch {};
    _ = client_ep.pollWithStats(1) catch {};
}
