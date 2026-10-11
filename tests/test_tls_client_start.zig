// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros
const std = @import("std");
const api = @import("quic_api");
const cfg = @import("quic_config");
const endpoint = @import("quic_endpoint");
const client_mod = @import("client");
const endpoint_utils = @import("endpoint_utils");

test "QUIC client starts TLS and retains an actual ClientHello in both crypto modes" {
    const config = cfg.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try endpoint.Endpoint.init(std.testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    const conn = try api.connect(&ep, "127.0.0.1:19849", "localhost");
    try std.testing.expect(conn.tls_context != null);
    try std.testing.expect(conn.crypto_tx_off_initial > 0);
    try std.testing.expect(conn.crypto_retx_initial != null);
}

fn readFixture(path: []const u8) ![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const size = (try file.stat(io)).size;
    if (size > 64 * 1024) return error.FixtureTooLarge;
    const bytes = try std.testing.allocator.alloc(u8, @intCast(size));
    errdefer std.testing.allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.TruncatedFixture;
    return bytes;
}

fn nowNs() i96 {
    return std.Io.Clock.awake.now(std.Io.Threaded.global_single_threaded.io()).nanoseconds;
}

test "authenticated QUIC peers complete the selected TLS exchange and exchange stream data with FIN" {
    const allocator = std.testing.allocator;
    const cert_pem = try readFixture("tests/certs/cert.pem");
    defer allocator.free(cert_pem);
    const key_pem = try readFixture("tests/certs/key.pem");
    defer allocator.free(key_pem);
    const ca_pem = try readFixture("tests/certs/ca.pem");
    defer allocator.free(ca_pem);
    const cert = try api.pem.parseCertificate(allocator, cert_pem);
    defer allocator.free(cert);
    const key = try api.pem.parsePrivateKey(allocator, key_pem);
    defer allocator.free(key);
    const ca = try api.pem.parseCertificate(allocator, ca_pem);
    defer allocator.free(ca);
    const server_config = cfg.QuicConfig{
        .alpn = &.{"h3"},
        .inline_server_cert_der = cert,
        .inline_server_priv_p256 = key,
    };
    var server = try endpoint.Endpoint.init(allocator, "127.0.0.1:0", &server_config);
    defer server.deinit();
    const port = api.getPort(&server);
    try std.testing.expect(port != 0);
    var address_buf: [32]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_buf, "127.0.0.1:{d}", .{port});
    const client_config = cfg.QuicConfig{ .alpn = &.{"h3"}, .inline_ca_chain_der = &.{ca} };
    var client = try endpoint.Endpoint.init(allocator, "127.0.0.1:0", &client_config);
    defer client.deinit();
    const conn = try api.connect(&client, address, "localhost");
    var accepted: ?*api.Connection = null;
    const handshake_deadline = nowNs() + 5 * std.time.ns_per_s;
    while (nowNs() < handshake_deadline and (!conn.handshake_done_seen or accepted == null)) {
        _ = try server.pollWithStats(1);
        if (accepted == null) accepted = server.popAccepted();
        _ = try client.pollWithStats(1);
    }
    if (!conn.handshake_done_seen or accepted == null) {
        std.debug.print("TLS phase={s}, Initial CRYPTO bytes={d}, handshake_done={}, accepted={}\n", .{
            @tagName(conn.tls_context.?.phase), conn.crypto_tx_off_initial, conn.handshake_done_seen, accepted != null,
        });
        return error.HandshakeTimeout;
    }
    const peer = accepted.?;
    try std.testing.expect(peer.peer_finished_verified);
    try std.testing.expect(api.isHandshakeConfirmed(conn));

    const request = "authenticated client stream payload";
    const response = "authenticated server stream response";
    const stream = try api.openStream(conn, true);
    try std.testing.expectEqual(request.len, try api.writeStream(conn, stream, request, true));
    var incoming: ?api.QuicStreamId = null;
    var request_buf: [request.len]u8 = undefined;
    var response_buf: [response.len]u8 = undefined;
    var request_read: usize = 0;
    var response_read: usize = 0;
    var response_sent = false;
    const stream_deadline = nowNs() + 5 * std.time.ns_per_s;
    while (nowNs() < stream_deadline) {
        _ = try server.pollWithStats(1);
        _ = try client.pollWithStats(1);
        if (incoming == null and api.hasIncomingStreams(peer)) incoming = try api.acceptStream(peer);
        if (incoming) |sid| {
            if (request_read < request.len) {
                request_read += api.readStream(peer, sid, request_buf[request_read..]) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
            }
            if (!response_sent and request_read == request.len and api.isStreamFinished(peer, sid)) {
                try std.testing.expectEqualStrings(request, &request_buf);
                try std.testing.expectEqual(response.len, try api.writeStream(peer, sid, response, true));
                response_sent = true;
            }
        }
        if (response_read < response.len) {
            response_read += api.readStream(conn, stream, response_buf[response_read..]) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
        }
        if (response_read == response.len and api.isStreamFinished(conn, stream)) break;
    }
    try std.testing.expect(response_sent);
    try std.testing.expectEqualStrings(response, response_buf[0..response_read]);
    try std.testing.expect(api.isStreamFinished(conn, stream));
}

test "TLS startup rejection propagates before sending or arming Initial recovery" {
    const config = cfg.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try endpoint.Endpoint.init(std.testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    const conn = try ep.connectClient("127.0.0.1:19849");
    // Exercise the real TLS policy error through the endpoint, in both modes.
    conn.tls_context.?.config.supported_groups = &.{};
    try std.testing.expectError(error.UnsupportedKeyShareGroup, ep.clientSendInitialProbe(conn));
    try std.testing.expectEqual(@as(u64, 0), conn.pn_initial_tx);
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_tx_off_initial);
    try std.testing.expect(conn.crypto_retx_initial == null);
    try std.testing.expectEqual(@as(usize, 0), ep.timers.items.len);
}

fn failSend(_: *anyopaque, _: @TypeOf(@as(api.Connection, undefined).peer), _: []const u8) anyerror!usize {
    return error.InjectedInitialSendFailure;
}

test "a failed public connect removes registered aliases before freeing the connection" {
    const config = cfg.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try endpoint.Endpoint.init(std.testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    const original_send = ep.transport.sendFn;
    ep.transport.sendFn = failSend;
    try std.testing.expectError(error.InjectedInitialSendFailure, api.connect(&ep, "127.0.0.1:19849", "localhost"));
    const aliases = ep.conns.count();
    // The failing parent has already freed the connection. Clear its dangling
    // aliases so the regression reports the ownership error without a second free.
    if (aliases != 0) ep.conns.clearRetainingCapacity();
    try std.testing.expectEqual(@as(usize, 0), aliases);
    try std.testing.expectEqual(@as(usize, 0), ep.timers.items.len);
    try std.testing.expectEqual(@as(usize, 0), ep.pto_dirty_set.count());
    try std.testing.expectEqual(@as(u32, 0), ep.pto_dirty_count.load(.acquire));
    _ = try ep.pollWithStats(0);
    for (0..3) |_| {
        try std.testing.expectError(error.InjectedInitialSendFailure, api.connect(&ep, "127.0.0.1:19849", "localhost"));
        try std.testing.expectEqual(@as(usize, 0), ep.conns.count());
        _ = try ep.pollWithStats(0);
    }
    ep.transport.sendFn = original_send;
    const retry = try api.connect(&ep, "127.0.0.1:19849", "localhost");
    try std.testing.expect(retry.crypto_tx_off_initial > 0);
}

fn clientCreationAllocationCase(allocator: std.mem.Allocator) !void {
    const config = cfg.QuicConfig{ .alpn = &.{"h3"} };
    // Exercise the actual constructor without mixing endpoint/socket allocations
    // into the injected allocator's ownership accounting.
    var alloc = allocator;
    var conns = @TypeOf(@as(endpoint.Endpoint, undefined).conns).init(allocator);
    defer conns.deinit();
    const peer = @TypeOf(@as(api.Connection, undefined).peer).ipv4(127, 0, 0, 1, 19849);
    const conn = client_mod.createClientConnection(&alloc, peer, endpoint_utils.invalidSocket(), config, 1, &conns, 0) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), conns.count());
        return err;
    };
    defer allocator.destroy(conn);
    defer conn.deinit();
    try std.testing.expect(conn.tls_context != null);
}

test "client construction allocation failures unwind resources and registrations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, clientCreationAllocationCase, .{});
}

test "connection teardown removes every pending work reference and preserves other connections" {
    const config = cfg.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try endpoint.Endpoint.init(std.testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    const doomed = try ep.connectClient("127.0.0.1:19849");
    const survivor = try ep.connectClient("127.0.0.1:19850");
    for ([_]*api.Connection{ doomed, survivor }) |conn| {
        conn.markPtoDirty();
        ep.markPendingHandshakeSend(conn);
        conn.markClosed();
    }
    const io = std.Io.Threaded.global_single_threaded.io();
    ep.mu.lockUncancelable(io);
    ep.destroyConnections(&.{doomed});
    ep.mu.unlock(io);
    try std.testing.expectEqual(@as(usize, 2), ep.conns.count());
    try std.testing.expectEqual(@as(usize, 1), ep.pto_dirty_set.count());
    try std.testing.expectEqual(@as(u32, 1), ep.pto_dirty_count.load(.acquire));
    try std.testing.expect(ep.pto_dirty_set.contains(survivor));
    try std.testing.expectEqual(@as(usize, 1), ep.pending_hs_send_set.count());
    try std.testing.expectEqual(@as(u32, 1), ep.pending_hs_send_count.load(.acquire));
    try std.testing.expect(ep.pending_hs_send_set.contains(survivor));
    try std.testing.expectEqual(@as(usize, 1), ep.closed_conn_set.count());
    try std.testing.expectEqual(@as(u32, 1), ep.closed_conn_count.load(.acquire));
    try std.testing.expect(ep.closed_conn_set.contains(survivor));
    _ = try ep.pollWithStats(0);
}

const SnapshotWorkers = struct {
    ep: *endpoint.Endpoint,
    conn: *api.Connection,
    poll_failed: std.atomic.Value(bool) = .init(false),
    destroyed: std.atomic.Value(bool) = .init(false),

    fn poll(self: *@This()) void {
        _ = self.ep.pollWithStats(0) catch {
            self.poll_failed.store(true, .release);
            return;
        };
    }

    fn destroy(self: *@This()) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        self.ep.mu.lockUncancelable(io);
        self.ep.destroyConnections(&.{self.conn});
        self.ep.mu.unlock(io);
        self.destroyed.store(true, .release);
    }
};

fn expectSnapshotOwnership(pending_handshake: bool) !void {
    const config = cfg.QuicConfig{ .alpn = &.{"h3"} };
    var ep = try endpoint.Endpoint.init(std.testing.allocator, "127.0.0.1:0", &config);
    defer ep.deinit();
    const conn = try ep.connectClient("127.0.0.1:19849");
    if (pending_handshake) ep.markPendingHandshakeSend(conn) else conn.markPtoDirty();
    var workers = SnapshotWorkers{ .ep = &ep, .conn = conn };
    const io = std.Io.Threaded.global_single_threaded.io();
    const work_mu = if (pending_handshake) &conn.endpoint_rx_serial_mu else &conn.mu;
    work_mu.lockUncancelable(io);
    var held = true;
    var poll_thread: ?std.Thread = null;
    var destroy_thread: ?std.Thread = null;
    defer {
        if (held) work_mu.unlock(io);
        if (poll_thread) |thread| thread.join();
        if (destroy_thread) |thread| thread.join();
    }
    poll_thread = try std.Thread.spawn(.{}, SnapshotWorkers.poll, .{&workers});
    const snapshot_deadline = nowNs() + 5 * std.time.ns_per_s;
    while (conn.endpoint_rx_refs.load(.acquire) == 0 and nowNs() < snapshot_deadline) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(conn.endpoint_rx_refs.load(.acquire) > 0);
    destroy_thread = try std.Thread.spawn(.{}, SnapshotWorkers.destroy, .{&workers});
    const destroy_deadline = nowNs() + 5 * std.time.ns_per_s;
    while (!conn.endpoint_destroying.load(.acquire) and nowNs() < destroy_deadline) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(conn.endpoint_destroying.load(.acquire));
    try std.testing.expect(!workers.destroyed.load(.acquire));
    work_mu.unlock(io);
    held = false;
    poll_thread.?.join();
    poll_thread = null;
    destroy_thread.?.join();
    destroy_thread = null;
    try std.testing.expect(workers.destroyed.load(.acquire));
    try std.testing.expect(!workers.poll_failed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), ep.conns.count());
    try std.testing.expectEqual(@as(usize, 0), ep.pto_dirty_set.count());
    try std.testing.expectEqual(@as(usize, 0), ep.pending_hs_send_set.count());
    _ = try ep.pollWithStats(0);
}

test "PTO poll snapshot retains its connection until pending work completes" {
    try expectSnapshotOwnership(false);
}

test "handshake poll snapshot retains its connection until pending work completes" {
    try expectSnapshotOwnership(true);
}
