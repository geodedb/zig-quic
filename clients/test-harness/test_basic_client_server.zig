//! Basic client-server connectivity tests
//!
//! These tests verify fundamental QUIC client library functionality:
//! - Client can connect to server
//! - TLS handshake completes successfully
//! - Bidirectional streams work
//! - Data can be sent and received
//! - Connections close cleanly

const std = @import("std");
const quic = @import("../../zig/quic.zig");
const api = @import("quic_api");

test "client can connect to server" {
    const allocator = std.testing.allocator;

    // Start server
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0, // Use any available port
    });
    defer server.deinit();

    const server_port = server.getPort();
    try std.testing.expect(server_port > 0);

    // Start client
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
    });
    defer client.deinit();

    // Connect
    var client_conn = try client.connect("127.0.0.1", server_port, "localhost");
    defer client_conn.close();

    // Poll both sides to exchange handshake
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        server.poll(10) catch {};
        client.poll(10) catch {};

        if (client_conn.isHandshakeComplete()) break;
    }

    try std.testing.expect(client_conn.isHandshakeComplete());

    // Accept on server side
    const server_conn = try server.accept();
    defer server_conn.close();

    try std.testing.expect(server_conn.isHandshakeComplete());
}

test "bidirectional stream data exchange" {
    const allocator = std.testing.allocator;

    // Start server
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
    });
    defer client.deinit();

    // Connect
    var client_conn = try client.connect("127.0.0.1", server_port, "localhost");
    defer client_conn.close();

    // Wait for handshake
    try client_conn.waitForHandshake();

    // Accept on server side
    server.poll(50) catch {};
    const server_conn = try server.accept();
    defer server_conn.close();

    try server_conn.waitForHandshake();

    // Client opens stream and sends data
    var client_stream = try client_conn.openStream(true);
    defer client_stream.close();

    const send_data = "Hello from client!";
    try client_stream.writeAll(send_data);

    // Flush data
    client.flush(10);
    server.flush(10);

    // Server accepts stream and reads data
    var attempts: usize = 0;
    while (!server_conn.hasIncomingStreams() and attempts < 100) : (attempts += 1) {
        server.poll(10) catch {};
        client.poll(10) catch {};
    }

    try std.testing.expect(server_conn.hasIncomingStreams());

    var server_stream = try server_conn.acceptStream();
    defer server_stream.close();

    var recv_buf: [1024]u8 = undefined;
    var total_read: usize = 0;
    attempts = 0;
    while (total_read < send_data.len and attempts < 100) : (attempts += 1) {
        const n = server_stream.read(recv_buf[total_read..]) catch |err| {
            if (err == error.Done) {
                server.poll(10) catch {};
                continue;
            }
            return err;
        };
        if (n > 0) {
            total_read += n;
        } else {
            server.poll(10) catch {};
        }
    }

    try std.testing.expectEqualStrings(send_data, recv_buf[0..total_read]);

    // Server responds
    const response_data = "Hello from server!";
    try server_stream.writeAndFinish(response_data);

    // Flush data
    server.flush(10);
    client.flush(10);

    // Client reads response
    total_read = 0;
    attempts = 0;
    while (total_read < response_data.len and attempts < 100) : (attempts += 1) {
        const n = client_stream.read(recv_buf[total_read..]) catch |err| {
            if (err == error.Done) {
                client.poll(10) catch {};
                continue;
            }
            return err;
        };
        if (n > 0) {
            total_read += n;
        } else {
            client.poll(10) catch {};
        }
    }

    try std.testing.expectEqualStrings(response_data, recv_buf[0..total_read]);
}

test "multiple streams on single connection" {
    const allocator = std.testing.allocator;

    // Start server
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
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

    // Open multiple streams
    const num_streams = 5;
    var i: usize = 0;
    while (i < num_streams) : (i += 1) {
        var stream = try client_conn.openStream(true);
        defer stream.close();

        var buf: [64]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Message {d}", .{i});
        try stream.writeAndFinish(msg);
    }

    // Flush
    client.flush(20);
    server.flush(20);

    // Server accepts and reads all streams
    var received: usize = 0;
    var attempts: usize = 0;
    while (received < num_streams and attempts < 200) : (attempts += 1) {
        server.poll(10) catch {};

        if (server_conn.hasIncomingStreams()) {
            var stream = try server_conn.acceptStream();
            defer stream.close();

            var recv_buf: [1024]u8 = undefined;
            const n = stream.read(&recv_buf) catch |err| {
                if (err == error.Done) continue;
                return err;
            };

            if (n > 0) {
                received += 1;
            }
        }
    }

    try std.testing.expectEqual(num_streams, received);
}

test "ALPN negotiation" {
    const allocator = std.testing.allocator;

    const test_alpn = "my-test-protocol";

    // Start server
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{test_alpn},
        .allow_insecure = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{test_alpn},
        .allow_insecure = true,
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

    // Check ALPN
    const client_alpn = client_conn.getNegotiatedAlpn();
    try std.testing.expect(client_alpn != null);
    try std.testing.expectEqualStrings(test_alpn, client_alpn.?);

    const server_alpn = server_conn.getNegotiatedAlpn();
    try std.testing.expect(server_alpn != null);
    try std.testing.expectEqualStrings(test_alpn, server_alpn.?);
}

test "connection close with error code" {
    const allocator = std.testing.allocator;

    // Start server
    var server = try quic.QuicServer.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
        .bind_address = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const server_port = server.getPort();

    // Start client
    var client = try quic.QuicClient.init(allocator, .{
        .alpn = &[_][]const u8{"test"},
        .allow_insecure = true,
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

    // Client closes with error
    try client_conn.closeWithError(42, "test error");

    // Flush to propagate close
    client.flush(10);
    server.flush(10);

    // Server should see the connection as drained after some polling
    var i: usize = 0;
    while (i < 50 and !server_conn.isDrained()) : (i += 1) {
        server.poll(10) catch {};
    }
}
