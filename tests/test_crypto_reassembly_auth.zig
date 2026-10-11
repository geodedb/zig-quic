// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 CodePros
const std = @import("std");
const api = @import("quic_api");
const handshake = @import("handshake_integration");

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

test "authenticated TLS consumes overlapping reordered CRYPTO once then exchanges UDP stream data and FIN" {
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
    const server_config = api.QuicConfig{
        .alpn = &.{"h3"},
        .inline_server_cert_der = cert,
        .inline_server_priv_p256 = key,
    };
    var server = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &server_config);
    defer server.deinit();
    const port = api.getPort(&server);
    try std.testing.expect(port != 0);
    var address_buf: [32]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_buf, "127.0.0.1:{d}", .{port});
    const client_config = api.QuicConfig{ .alpn = &.{"h3"}, .inline_ca_chain_der = &.{ca} };
    var client = try api.QuicEndpoint.init(allocator, "127.0.0.1:0", &client_config);
    defer client.deinit();
    const conn = try api.connect(&client, address, "localhost");
    var accepted: ?*api.Connection = null;
    const flight_deadline = nowNs() + 5 * std.time.ns_per_s;
    while (nowNs() < flight_deadline) {
        _ = try server.pollWithStats(1);
        if (accepted == null) accepted = server.popAccepted();
        if (accepted) |peer| {
            if (peer.crypto_retx_initial != null and peer.crypto_retx_handshake != null) break;
        } else {
            // The default stateless Retry does not allocate a server
            // connection. Let the client validate Retry and resend Initial;
            // once accepted, leave the real server TLS flight queued so this
            // test can deliver its CRYPTO fragments in a controlled order.
            _ = try client.pollWithStats(1);
        }
    }
    const server_conn = accepted orelse return error.ServerDidNotAccept;
    const initial = server_conn.crypto_retx_initial orelse return error.MissingServerHello;
    const flight = server_conn.crypto_retx_handshake orelse return error.MissingServerFlight;
    try std.testing.expect(flight.len > 6);
    try std.testing.expectEqual(@as(u64, 0), server_conn.crypto_retx_initial_off);
    try std.testing.expectEqual(@as(u64, 0), server_conn.crypto_retx_handshake_off);
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_rx_off_initial);
    // Model the received Initial header using the actual peer's SCID, then
    // feed its genuine authenticated TLS flight through production reassembly.
    // Only CRYPTO delivery order is controlled here; certificate verification,
    // Finished verification and key derivation stay enabled in both modes.
    conn.peer_initial_scid = server_conn.our_scid;
    conn.peer_initial_scid_set = true;
    conn.expected_rx_dcid_len = null;
    {
        handshake.setCurrentConnection(conn);
        defer handshake.clearCurrentConnection();
        _ = try conn.handleInitialCrypto(&client.allocator, server_conn.crypto_retx_initial_off, initial);
        _ = try conn.handleHandshakeCrypto(&client.allocator, 4, flight[4..]);
        _ = try conn.handleHandshakeCrypto(&client.allocator, 4, flight[4..]);
        _ = try conn.handleHandshakeCrypto(&client.allocator, 0, flight[0..6]);
    }
    if (conn.crypto_rx_off_handshake != flight.len) {
        std.debug.print("CRYPTO overlap regression: expected {d} authenticated flight bytes, consumed {d}\n", .{
            flight.len, conn.crypto_rx_off_handshake,
        });
    }
    try std.testing.expectEqual(@as(u64, @intCast(flight.len)), conn.crypto_rx_off_handshake);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_buffer_handshake.count);
    try std.testing.expect(conn.peer_finished_verified);
    try std.testing.expect(conn.last_handshake_error == null);
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
    try std.testing.expect(peer == server_conn);
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
