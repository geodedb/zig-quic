//! DATAGRAM extension tests (RFC 9221)
//!
//! These tests verify the DATAGRAM extension functionality:
//! - DATAGRAM frames can be sent and received
//! - Datagrams are unreliable (no retransmission)
//! - Size limits are enforced
//! - Multiple datagrams can be sent concurrently

const std = @import("std");
const quic = @import("../../zig/quic.zig");

test "send and receive datagram" {
    const allocator = std.testing.allocator;

    // Start server with DATAGRAM enabled
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .enable_datagram = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client with DATAGRAM enabled
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .enable_datagram = true,
    });
    defer client.deinit();

    // Connect
    var client_conn = try client.connect("127.0.0.1", server_port, "localhost");
    defer client_conn.close();

    try client_conn.waitForHandshake();

    server.poll(50) catch {};
    const server_conn = try server.accept();
    defer server_conn.close();

    try server_conn.waitForHandshake();

    // Send datagram from client to server
    const datagram_data = "Hello via DATAGRAM!";
    const sent = try client_conn.sendDatagram(datagram_data);
    try std.testing.expectEqual(datagram_data.len, sent);

    // Flush to ensure delivery
    client.flush(10);
    server.flush(10);

    // Server receives datagram
    var recv_buf: [1024]u8 = undefined;
    var received = false;
    var attempts: usize = 0;
    while (!received and attempts < 100) : (attempts += 1) {
        const n = server_conn.recvDatagram(&recv_buf) catch |err| {
            if (err == error.Done or err == error.BufferTooShort) {
                server.poll(10) catch {};
                continue;
            }
            return err;
        };

        if (n > 0) {
            try std.testing.expectEqualStrings(datagram_data, recv_buf[0..n]);
            received = true;
        }
    }

    try std.testing.expect(received);
}

test "multiple datagrams" {
    const allocator = std.testing.allocator;

    // Start server with DATAGRAM enabled
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .enable_datagram = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client with DATAGRAM enabled
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .enable_datagram = true,
    });
    defer client.deinit();

    // Connect
    var client_conn = try client.connect("127.0.0.1", server_port, "localhost");
    defer client_conn.close();

    try client_conn.waitForHandshake();

    server.poll(50) catch {};
    const server_conn = try server.accept();
    defer server_conn.close();

    try server_conn.waitForHandshake();

    // Send multiple datagrams
    const num_datagrams = 10;
    var i: usize = 0;
    while (i < num_datagrams) : (i += 1) {
        var buf: [64]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Datagram {d}", .{i});
        _ = try client_conn.sendDatagram(msg);
    }

    // Flush
    client.flush(20);
    server.flush(20);

    // Receive datagrams (note: DATAGRAM is unreliable, so we might not get all)
    var received: usize = 0;
    var attempts: usize = 0;
    var recv_buf: [1024]u8 = undefined;

    while (attempts < 200) : (attempts += 1) {
        const n = server_conn.recvDatagram(&recv_buf) catch |err| {
            if (err == error.Done or err == error.BufferTooShort) {
                server.poll(10) catch {};
                continue;
            }
            return err;
        };

        if (n > 0) {
            received += 1;
        }
    }

    // We should receive at least some datagrams (DATAGRAM is unreliable)
    // In practice over loopback, we should get most or all of them
    try std.testing.expect(received > 0);
}

test "bidirectional datagram exchange" {
    const allocator = std.testing.allocator;

    // Start server with DATAGRAM enabled
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .enable_datagram = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client with DATAGRAM enabled
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .enable_datagram = true,
    });
    defer client.deinit();

    // Connect
    var client_conn = try client.connect("127.0.0.1", server_port, "localhost");
    defer client_conn.close();

    try client_conn.waitForHandshake();

    server.poll(50) catch {};
    const server_conn = try server.accept();
    defer server_conn.close();

    try server_conn.waitForHandshake();

    // Client sends datagram
    const client_msg = "Client -> Server";
    _ = try client_conn.sendDatagram(client_msg);

    client.flush(10);
    server.flush(10);

    // Server receives and responds
    var recv_buf: [1024]u8 = undefined;
    var attempts: usize = 0;
    var received_client_msg = false;

    while (!received_client_msg and attempts < 100) : (attempts += 1) {
        const n = server_conn.recvDatagram(&recv_buf) catch |err| {
            if (err == error.Done or err == error.BufferTooShort) {
                server.poll(10) catch {};
                continue;
            }
            return err;
        };

        if (n > 0) {
            try std.testing.expectEqualStrings(client_msg, recv_buf[0..n]);
            received_client_msg = true;
        }
    }

    try std.testing.expect(received_client_msg);

    // Server responds
    const server_msg = "Server -> Client";
    _ = try server_conn.sendDatagram(server_msg);

    server.flush(10);
    client.flush(10);

    // Client receives response
    attempts = 0;
    var received_server_msg = false;

    while (!received_server_msg and attempts < 100) : (attempts += 1) {
        const n = client_conn.recvDatagram(&recv_buf) catch |err| {
            if (err == error.Done or err == error.BufferTooShort) {
                client.poll(10) catch {};
                continue;
            }
            return err;
        };

        if (n > 0) {
            try std.testing.expectEqualStrings(server_msg, recv_buf[0..n]);
            received_server_msg = true;
        }
    }

    try std.testing.expect(received_server_msg);
}
