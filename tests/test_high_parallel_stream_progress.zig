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
const HANDSHAKE_TIMEOUT_MS: i64 = 5_000;
const RT_TIMEOUT_MS: i64 = 7_000;

var next_port = std.atomic.Value(u16).init(19850);

fn allocatePort() u16 {
    return next_port.fetchAdd(1, .seq_cst);
}

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

fn clientThread(ctx: ClientCtx) void {
    var cli_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .allow_insecure = true,
    };
    var ep = endpoint_mod.Endpoint.init(ctx.allocator, "127.0.0.1:0", &cli_cfg) catch {
        _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
        return;
    };
    defer ep.deinit();

    const conn = api.connect(&ep, ctx.server_addr, SERVER_SNI) catch {
        _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
        return;
    };

    const hs_deadline = nowMs() + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < hs_deadline and !api.isHandshakeConfirmed(conn)) {
        _ = ep.pollWithStats(1) catch {};
    }
    if (!api.isHandshakeConfirmed(conn)) {
        _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
        return;
    }

    var payload: [PAYLOAD_BYTES]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i + ctx.index);

    const sid = api.openStream(conn, true) catch {
        _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
        return;
    };

    const rt_deadline = nowMs() + RT_TIMEOUT_MS;
    var sent: usize = 0;
    while (sent < payload.len) {
        if (nowMs() >= rt_deadline) {
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            return;
        }
        const n = api.writeStream(conn, sid, payload[sent..], false) catch {
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            return;
        };
        if (n == 0) {
            _ = ep.pollWithStats(1) catch {};
            continue;
        }
        sent += n;
    }

    _ = api.writeStream(conn, sid, &[_]u8{}, true) catch {
        _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
        return;
    };

    var recv_scratch: [2048]u8 = undefined;
    var received: usize = 0;
    while (nowMs() < rt_deadline) {
        _ = ep.pollWithStats(1) catch {};
        const n = api.readStream(conn, sid, &recv_scratch) catch |err| {
            if (err == error.WouldBlock) continue;
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
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
            _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
            return;
        }
        for (recv_scratch[0..n], 0..) |b, i| {
            if (b != payload[received + i]) {
                _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
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

    _ = ctx.fail_counter.fetchAdd(1, .seq_cst);
}

test "high-parallel connections complete stream echo and FIN without blocking" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.heap.page_allocator;
    const creds_opt = loadServerCreds(allocator);
    if (creds_opt == null) return error.SkipZigTest;
    const creds = creds_opt.?;
    defer allocator.free(creds.cert_der);
    defer allocator.free(creds.priv_p256);

    const port = allocatePort();
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "127.0.0.1:{d}", .{port});

    var server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = creds.cert_der,
        .inline_server_priv_p256 = creds.priv_p256,
        .allow_insecure = true,
    };
    var server_ep = try endpoint_mod.Endpoint.init(allocator, bind_addr, &server_cfg);
    defer server_ep.deinit();

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

const DropClientFinished = struct {
    sender: *const fn (*anyopaque, *api.Connection, []const u8) anyerror!usize,
    context: *anyopaque,
    dropped: bool = false,
    handshake_packets: usize = 0,

    fn send(raw: *anyopaque, conn: *api.Connection, bytes: []const u8) !usize {
        const self: *DropClientFinished = @ptrCast(@alignCast(raw));
        // Connection.send carries the client's Finished before Handshake ACKs,
        // which the endpoint sends separately. Simulate loss after submission.
        if (bytes.len > 0 and bytes[0] & 0xf0 == 0xe0) {
            self.handshake_packets += 1;
            if (!self.dropped) {
                self.dropped = true;
                return bytes.len;
            }
        }
        return self.sender(self.context, conn, bytes);
    }
};

test "lost client Finished recovers automatically and delivers stream data" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.heap.page_allocator;
    // This regression requires the same generated P-256 fixture as the existing
    // high-parallel test, but missing credentials must not silently skip it.
    const creds = loadServerCreds(allocator) orelse return error.MissingTestCredentials;
    defer allocator.free(creds.cert_der);
    defer allocator.free(creds.priv_p256);
    var address_buf: [32]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_buf, "127.0.0.1:{d}", .{allocatePort()});
    const server_cfg = cfg.QuicConfig{
        .alpn = &test_alpn,
        .inline_server_cert_der = creds.cert_der,
        .inline_server_priv_p256 = creds.priv_p256,
        .allow_insecure = true,
    };
    var server = try endpoint_mod.Endpoint.init(allocator, address, &server_cfg);
    defer server.deinit();
    const client_cfg = cfg.QuicConfig{ .alpn = &test_alpn, .allow_insecure = true };
    var client = try endpoint_mod.Endpoint.init(allocator, "127.0.0.1:0", &client_cfg);
    defer client.deinit();
    const conn = try api.connect(&client, address, SERVER_SNI);
    var drop = DropClientFinished{ .sender = conn.sender_fn.?, .context = conn.sender_ctx.? };
    conn.setSender(&drop, DropClientFinished.send);
    defer conn.setSender(drop.context, drop.sender);

    var peer: ?*api.Connection = null;
    const handshake_deadline = nowMs() + HANDSHAKE_TIMEOUT_MS;
    while (nowMs() < handshake_deadline and !conn.handshake_done_seen) {
        _ = try server.pollWithStats(1);
        if (peer == null) peer = server.popAccepted();
        _ = try client.pollWithStats(1);
    }
    try testing.expect(drop.dropped);
    try testing.expect(drop.handshake_packets >= 2);
    try testing.expect(conn.handshake_done_seen);
    const accepted = peer orelse return error.ServerDidNotAccept;
    try testing.expect(accepted.peer_finished_verified);
    try testing.expect(conn.hs_tx_keys == null and conn.hs_rx_keys == null);
    try testing.expect(conn.crypto_retx_handshake == null);

    const payload = "stream data after a lost Finished";
    const stream = try api.openStream(conn, true);
    try testing.expectEqual(payload.len, try api.writeStream(conn, stream, payload, true));
    var received: usize = 0;
    var incoming: ?api.QuicStreamId = null;
    var data: [payload.len]u8 = undefined;
    const stream_deadline = nowMs() + RT_TIMEOUT_MS;
    while (nowMs() < stream_deadline) {
        _ = try client.pollWithStats(1);
        _ = try server.pollWithStats(1);
        if (incoming == null and api.hasIncomingStreams(accepted)) incoming = try api.acceptStream(accepted);
        if (incoming) |sid| {
            if (received < data.len) {
                const n = api.readStream(accepted, sid, data[received..]) catch |err| {
                    if (err == error.WouldBlock) continue;
                    return err;
                };
                received += n;
            }
            if (received == data.len and api.isStreamFinished(accepted, sid)) break;
        }
    }
    try testing.expectEqualStrings(payload, data[0..received]);
    try testing.expect(api.isStreamFinished(accepted, incoming orelse return error.StreamNotAccepted));
}
