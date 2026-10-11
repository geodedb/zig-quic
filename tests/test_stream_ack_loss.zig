const std = @import("std");
const api = @import("quic_api");

fn nowNs() i96 {
    return std.Io.Clock.awake.now(std.Io.Threaded.global_single_threaded.io()).nanoseconds;
}

const BurstLoss = struct {
    forward_ctx: *anyopaque,
    forward_fn: *const fn (*anyopaque, *api.Connection, []const u8) anyerror!usize,
    remaining: usize = 31,
    dropped: usize = 0,

    fn send(ctx: *anyopaque, conn: *api.Connection, bytes: []const u8) anyerror!usize {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.remaining != 0) {
            self.remaining -= 1;
            self.dropped += 1;
            // Model network loss after a successful UDP submission.
            return bytes.len;
        }
        return self.forward_fn(self.forward_ctx, conn, bytes);
    }
};

test "SONNY-4797 authenticated UDP stream recovers a 31-packet burst loss and FIN" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, "tests/certs/cert.pem", allocator, .limited(64 * 1024));
    defer allocator.free(cert_pem);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, "tests/certs/key.pem", allocator, .limited(64 * 1024));
    defer allocator.free(key_pem);
    const ca_pem = try std.Io.Dir.cwd().readFileAlloc(io, "tests/certs/ca.pem", allocator, .limited(64 * 1024));
    defer allocator.free(ca_pem);
    const cert = try api.pem.parseCertificate(allocator, cert_pem);
    defer allocator.free(cert);
    const key = try api.pem.parsePrivateKey(allocator, key_pem);
    defer allocator.free(key);
    const ca = try api.pem.parseCertificate(allocator, ca_pem);
    defer allocator.free(ca);
    const server_config = api.QuicConfig{
        .alpn = &.{"h3"},
        .inline_server_cert_der = cert,
        .inline_server_priv_p256 = key,
        .enable_pacing = false,
    };
    var server = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &server_config);
    defer server.deinit();
    var address_buf: [32]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_buf, "127.0.0.1:{d}", .{api.getPort(&server)});
    const client_config = api.QuicConfig{
        .alpn = &.{"h3"},
        .inline_ca_chain_der = &.{ca},
        .enable_pacing = false,
        .initial_congestion_window_packets = 64,
    };
    var client = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &client_config);
    defer client.deinit();
    const conn = try api.connect(&client, address, "localhost");
    var accepted: ?*api.Connection = null;
    const handshake_deadline = nowNs() + 5 * std.time.ns_per_s;
    while (nowNs() < handshake_deadline and (!conn.handshake_done_seen or accepted == null)) {
        _ = try server.pollWithStats(1);
        if (accepted == null) accepted = server.popAccepted();
        _ = try client.pollWithStats(1);
    }
    try std.testing.expect(accepted != null);
    try std.testing.expect(api.isHandshakeConfirmed(conn));
    const peer = accepted.?;
    try std.testing.expect(peer.peer_finished_verified);

    var loss = BurstLoss{ .forward_ctx = conn.sender_ctx.?, .forward_fn = conn.sender_fn.? };
    conn.setSender(&loss, BurstLoss.send);
    defer conn.setSender(loss.forward_ctx, loss.forward_fn);
    const stream = try api.openStream(conn, true);
    var expected: [32]u8 = undefined;
    for (&expected, 0..) |*byte, i| {
        byte.* = @intCast(i);
        try std.testing.expectEqual(@as(usize, 1), try api.writeStream(conn, stream, expected[i .. i + 1], i + 1 == expected.len));
    }
    try std.testing.expectEqual(@as(usize, 31), loss.dropped);

    var incoming: ?api.QuicStreamId = null;
    var received: [expected.len]u8 = undefined;
    var count: usize = 0;
    const deadline = nowNs() + 5 * std.time.ns_per_s;
    while (nowNs() < deadline) {
        _ = try server.pollWithStats(1);
        _ = try client.pollWithStats(1);
        if (incoming == null and api.hasIncomingStreams(peer)) incoming = try api.acceptStream(peer);
        if (incoming) |sid| {
            if (count < received.len) {
                count += api.readStream(peer, sid, received[count..]) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
            }
            if (count == received.len and api.isStreamFinished(peer, sid)) break;
        }
    }
    if (count != expected.len) std.debug.print("burst loss: dropped={d} received={d}/{d} retained={d}\n", .{ loss.dropped, count, expected.len, conn.app_stream_retx.count() });
    try std.testing.expectEqual(expected.len, count);
    try std.testing.expectEqualSlices(u8, &expected, &received);
    try std.testing.expect(api.isStreamFinished(peer, incoming.?));
}
