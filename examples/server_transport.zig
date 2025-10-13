const std = @import("std");
const transport = @import("quic");

// Example QUIC server using the high-level transport API
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Configure the QUIC transport
    const config = transport.QuicTransport.Config{
        .address = "0.0.0.0",
        .port = 4433,
        .max_connections = 100,
        .idle_timeout_ms = 30000,
        .cert_path = "certs/server.crt",
        .key_path = "certs/server.key",
    };

    // Initialize the transport
    var quic_transport = try transport.QuicTransport.init(allocator, config);
    defer quic_transport.deinit();

    // Start listening for connections
    try quic_transport.listen();
    std.debug.print("QUIC server listening on port {d}\n", .{config.port});

    // Accept and handle connections
    while (true) {
        // Poll for incoming packets
        try quic_transport.poll(10);

        // Accept a new connection
        const conn = quic_transport.accept() catch |err| {
            if (err == transport.QuicError.ConnectionFailed) {
                continue; // No connection available yet
            }
            return err;
        };

        std.debug.print("Accepted new connection\n", .{});

        // Spawn a thread to handle this connection
        const thread = try std.Thread.spawn(.{}, handleConnection, .{conn});
        thread.detach();
    }
}

fn handleConnection(conn: *transport.QuicConnection) void {
    defer conn.close();

    // Accept a stream
    const stream = conn.acceptStream() catch |err| {
        std.debug.print("Failed to accept stream: {}\n", .{err});
        return;
    };
    defer stream.close();

    // Read request
    var buf: [4096]u8 = undefined;
    const n = stream.read(&buf) catch |err| {
        std.debug.print("Failed to read from stream: {}\n", .{err});
        return;
    };

    std.debug.print("Received {d} bytes: {s}\n", .{ n, buf[0..n] });

    // Send response
    const response = "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "Hello, QUIC!\n";

    stream.writeAll(response) catch |err| {
        std.debug.print("Failed to write response: {}\n", .{err});
        return;
    };

    std.debug.print("Sent response\n", .{});
}
