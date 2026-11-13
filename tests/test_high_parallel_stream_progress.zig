// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// Regression test for high-parallel QUIC communication progress. The failure
// shape this pins is not just handshake admission: many connections complete
// TLS, then application stream writes stop making PTO/loss progress and one or
// more clients wait forever for echo bytes or peer FIN.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint_mod = @import("quic_endpoint");
const pem = api.pem;

const test_alpn = [_][]const u8{"h3"};
const SERVER_SNI = "localhost";
const PARALLEL_CLIENTS: usize = 32;
const PAYLOAD_BYTES: usize = 1024;
// On the two-core CI runner, 32 unoptimized TLS handshakes take just over
// five seconds; optimized builds complete the same setup within that bound.
// This regression checks stream progress after TLS setup. Keep the release
// handshake deadline and every stream/FIN assertion, with bounded headroom
// for Debug's unoptimized cryptography rather than timing out healthy peers.
const HANDSHAKE_TIMEOUT_MS: i64 = if (builtin.mode == .Debug) 30_000 else 5_000;
// The echo/FIN phase needs the same Debug allowance (SONNY-6434 follow-up).
// On a CPU-starved runner the single server poller falls behind 32 clients:
// its UDP receive queue held ~13 MB while clients waited, every echo was
// sent after its client had given up, and the release-tuned 7 s window
// failed at the same rate on v0.1.48 (274109b) as on the current code
// (interleaved constrained runs of the CI command). A wedged stream still
// fails: it never completes within any deadline.
const RT_TIMEOUT_MS: i64 = if (builtin.mode == .Debug) 30_000 else 7_000;

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

const ServerCreds = struct {
    cert_der: []u8,
    priv_p256: []u8,
};

fn loadServerCreds(allocator: std.mem.Allocator) ?ServerCreds {
    const io = std.Io.Threaded.global_single_threaded.io();

    const cert_file = std.Io.Dir.cwd().openFile(io, "tests/certs/cert.pem", .{}) catch return null;
    defer cert_file.close(io);
    const cert_size = (cert_file.stat(io) catch return null).size;
    const cert_pem = allocator.alloc(u8, cert_size) catch return null;
    defer allocator.free(cert_pem);
    _ = cert_file.readPositionalAll(io, cert_pem, 0) catch return null;
    const cert_der = pem.parseCertificate(allocator, cert_pem) catch return null;

    const key_file = std.Io.Dir.cwd().openFile(io, "tests/certs/key.pem", .{}) catch {
        allocator.free(cert_der);
        return null;
    };
    defer key_file.close(io);
    const key_size = (key_file.stat(io) catch {
        allocator.free(cert_der);
        return null;
    }).size;
    const key_pem = allocator.alloc(u8, key_size) catch {
        allocator.free(cert_der);
        return null;
    };
    defer allocator.free(key_pem);
    _ = key_file.readPositionalAll(io, key_pem, 0) catch {
        allocator.free(cert_der);
        return null;
    };
    const priv = pem.parsePrivateKey(allocator, key_pem) catch {
        allocator.free(cert_der);
        return null;
    };

    return .{ .cert_der = cert_der, .priv_p256 = priv };
}

const StreamState = struct {
    stream_id: api.QuicStreamId,
    pending: std.ArrayList(u8),
    client_fin: bool,
    server_fin_sent: bool,
};

const ServerCtx = struct {
    ep: *endpoint_mod.Endpoint,
    done: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,
};

fn pumpStreams(
    conns: []*api.Connection,
    states_by_conn: []std.ArrayList(StreamState),
    scratch: []u8,
    allocator: std.mem.Allocator,
) bool {
    var progress = false;
    for (conns, states_by_conn) |conn, *states| {
        while (api.hasIncomingStreams(conn)) {
            const sid = api.acceptStream(conn) catch break;
            states.append(allocator, .{
                .stream_id = sid,
                .pending = .empty,
                .client_fin = false,
                .server_fin_sent = false,
            }) catch {};
            progress = true;
        }

        for (states.items) |*s| {
            if (s.server_fin_sent) continue;

            while (true) {
                const n = api.readStream(conn, s.stream_id, scratch) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };
                if (n == 0) break;
                s.pending.appendSlice(allocator, scratch[0..n]) catch break;
                progress = true;
            }

            if (api.isStreamFinished(conn, s.stream_id) and !s.client_fin) {
                s.client_fin = true;
                progress = true;
            }

            while (s.pending.items.len > 0) {
                const written = api.writeStream(conn, s.stream_id, s.pending.items, false) catch break;
                if (written == 0) break;
                const remaining = s.pending.items.len - written;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, s.pending.items[0..remaining], s.pending.items[written..]);
                }
                s.pending.shrinkRetainingCapacity(remaining);
                progress = true;
            }

            if (s.client_fin and s.pending.items.len == 0 and !s.server_fin_sent) {
                _ = api.writeStream(conn, s.stream_id, &[_]u8{}, true) catch {};
                s.server_fin_sent = true;
                progress = true;
            }
        }
    }
    return progress;
}

fn serverThread(ctx: ServerCtx) void {
    var conns: std.ArrayList(*api.Connection) = .empty;
    defer conns.deinit(ctx.allocator);

    var states_by_conn: std.ArrayList(std.ArrayList(StreamState)) = .empty;
    defer {
        for (states_by_conn.items) |*per_conn| {
            for (per_conn.items) |*s| s.pending.deinit(ctx.allocator);
            per_conn.deinit(ctx.allocator);
        }
        states_by_conn.deinit(ctx.allocator);
    }

    var scratch: [4096]u8 = undefined;
    while (!ctx.done.load(.acquire)) {
        _ = ctx.ep.pollWithStats(0) catch {};

        while (api.tryAccept(ctx.ep)) |c| {
            conns.append(ctx.allocator, c) catch continue;
            states_by_conn.append(ctx.allocator, .empty) catch continue;
        }

        _ = pumpStreams(conns.items, states_by_conn.items, &scratch, ctx.allocator);
    }

    var drain: usize = 0;
    while (drain < 50) : (drain += 1) {
        _ = ctx.ep.pollWithStats(1) catch {};
        _ = pumpStreams(conns.items, states_by_conn.items, &scratch, ctx.allocator);
    }
}

const ClientCtx = struct {
    allocator: std.mem.Allocator,
    server_addr: []const u8,
    index: usize,
    success_counter: *std.atomic.Value(u32),
    fail_counter: *std.atomic.Value(u32),
};

fn recordFailure(ctx: ClientCtx, phase: []const u8) void {
    std.debug.print("high-parallel client {d} failed at {s}\n", .{ ctx.index, phase });
    _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
}

/// Per-client state at an echo/FIN deadline, to tell a starved peer (the
/// server never acknowledged anything) from a stalled stream.
fn reportStreamTimeout(ctx: ClientCtx, conn: *api.Connection, sid: api.QuicStreamId, handshake_ms: i64, waited_ms: i64, received: usize) void {
    std.debug.print(
        "high-parallel client {d}: handshake_ms={d} waited_ms={d} received={d}/{d} peer_fin={} pto_app_count={d} pn_app_tx={d} largest_acked={d} tracked_stream_packets={d}\n",
        .{ ctx.index, handshake_ms, waited_ms, received, PAYLOAD_BYTES, api.isStreamFinished(conn, sid), conn.pto_app_count, conn.pn_app_tx, conn.largest_acked, conn.app_stream_retx.count() },
    );
}

fn clientThread(ctx: ClientCtx) void {
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var ep = endpoint_mod.Endpoint.init(ctx.allocator, "127.0.0.1:0", &cli_cfg) catch {
        recordFailure(ctx, "endpoint init");
        return;
    };
    defer ep.deinit();

    const conn = api.connect(&ep, ctx.server_addr, SERVER_SNI) catch {
        recordFailure(ctx, "connect");
        return;
    };

    const hs_start = nowMs();
    const hs_deadline = hs_start + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = ep.pollWithStats(1) catch {};
    }
    if (!api.isHandshakeConfirmed(conn)) {
        recordFailure(ctx, "handshake deadline");
        return;
    }

    const handshake_ms = nowMs() - hs_start;
    var payload: [PAYLOAD_BYTES]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i + ctx.index);

    const sid = api.openStream(conn, true) catch {
        recordFailure(ctx, "open stream");
        return;
    };

    const rt_start = nowMs();
    const rt_deadline = rt_start + RT_TIMEOUT_MS;
    var sent: usize = 0;
    while (sent < payload.len) {
        if (nowMs() >= rt_deadline) {
            recordFailure(ctx, "send deadline");
            return;
        }
        const n = api.writeStream(conn, sid, payload[sent..], false) catch {
            recordFailure(ctx, "stream write");
            return;
        };
        if (n == 0) {
            _ = ep.pollWithStats(1) catch {};
            continue;
        }
        sent += n;
    }

    _ = api.writeStream(conn, sid, &[_]u8{}, true) catch {
        recordFailure(ctx, "send FIN");
        return;
    };

    var recv_scratch: [2048]u8 = undefined;
    var received: usize = 0;
    while (nowMs() < rt_deadline) {
        _ = ep.pollWithStats(1) catch {};
        const n = api.readStream(conn, sid, &recv_scratch) catch |err| {
            if (err == error.WouldBlock) continue;
            recordFailure(ctx, "stream read");
            return;
        };
        if (n == 0) {
            if (received == payload.len and api.isStreamFinished(conn, sid)) {
                _ = ctx.success_counter.fetchAdd(1, .seq_cst);
                _ = api.close(conn, 0, "done") catch {};
                _ = ep.pollWithStats(1) catch {};
                return;
            }
            continue;
        }
        if (received + n > payload.len) {
            recordFailure(ctx, "echo length");
            return;
        }
        for (recv_scratch[0..n], 0..) |b, i| {
            if (b != payload[received + i]) {
                recordFailure(ctx, "echo content");
                return;
            }
        }
        received += n;
        if (received == payload.len and api.isStreamFinished(conn, sid)) {
            _ = ctx.success_counter.fetchAdd(1, .seq_cst);
            _ = api.close(conn, 0, "done") catch {};
            _ = ep.pollWithStats(1) catch {};
            return;
        }
    }

    reportStreamTimeout(ctx, conn, sid, handshake_ms, nowMs() - rt_start, received);
    recordFailure(ctx, "echo or peer FIN deadline");
}

test "high-parallel connections complete stream echo and FIN without blocking" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.heap.page_allocator;
    const creds_opt = loadServerCreds(allocator);
    if (creds_opt == null) return error.SkipZigTest;
    const creds = creds_opt.?;
    defer allocator.free(creds.cert_der);
    defer allocator.free(creds.priv_p256);

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = creds.cert_der,
        .inline_server_priv_p256 = creds.priv_p256,
        .allow_insecure = true,
    };
    // Independent test processes must not share a fixed UDP listener and its
    // Retry routing. Keep the OS-assigned socket bound for the entire fixture.
    var server_ep = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &server_cfg);
    defer server_ep.deinit();
    const port = api.getPort(&server_ep);
    try testing.expect(port != 0);

    var target_buf: [32]u8 = undefined;
    const server_target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});

    var server_done = std.atomic.Value(bool).init(false);
    const srv_ctx = ServerCtx{
        .ep = &server_ep,
        .done = &server_done,
        .allocator = allocator,
    };
    const srv_thread = try std.Thread.spawn(.{}, serverThread, .{srv_ctx});
    var server_joined = false;
    defer {
        if (!server_joined) {
            server_done.store(true, .release);
            srv_thread.join();
        }
    }

    var success_counter = std.atomic.Value(u32).init(0);
    var fail_counter = std.atomic.Value(u32).init(0);
    var threads: [PARALLEL_CLIENTS]std.Thread = undefined;
    var thread_ok = [_]bool{false} ** PARALLEL_CLIENTS;

    for (&threads, &thread_ok, 0..) |*t, *ok, i| {
        const cctx = ClientCtx{
            .allocator = allocator,
            .server_addr = server_target,
            .index = i,
            .success_counter = &success_counter,
            .fail_counter = &fail_counter,
        };
        if (std.Thread.spawn(.{}, clientThread, .{cctx})) |spawned| {
            t.* = spawned;
            ok.* = true;
        } else |_| {
            _ = fail_counter.fetchAdd(1, .seq_cst);
        }
    }

    for (threads, thread_ok) |t, ok| {
        if (ok) t.join();
    }

    server_done.store(true, .release);
    srv_thread.join();
    server_joined = true;

    const successes = success_counter.load(.acquire);
    const failures = fail_counter.load(.acquire);
    if (failures != 0 or successes != PARALLEL_CLIENTS) {
        std.debug.print(
            "\n  FAIL: high-parallel stream progress blocked or corrupted.\n" ++
                "  expected successes={d} failures=0\n" ++
                "  got      successes={d} failures={d}\n",
            .{ PARALLEL_CLIENTS, successes, failures },
        );
    }
    try testing.expectEqual(@as(u32, 0), failures);
    try testing.expectEqual(@as(u32, PARALLEL_CLIENTS), successes);
}
