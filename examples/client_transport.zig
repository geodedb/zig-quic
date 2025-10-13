const std = @import("std");
const transport = @import("quic");

// Example QUIC client using the high-level transport API
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get server address from command line args or use default
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const server_addr = if (args.len > 1) args[1] else "127.0.0.1";
    const server_port = if (args.len > 2) try std.fmt.parseInt(u16, args[2], 10) else 4433;

    std.debug.print("Connecting to {s}:{d}\n", .{ server_addr, server_port });

    // Initialize the QUIC client
    var client = transport.QuicClient.init(allocator);
    defer client.deinit();

    // Connect to the server
    try client.connect(server_addr, server_port);
    std.debug.print("Connected successfully\n", .{});

    // Wait for handshake to complete
    try client.waitForHandshake();
    std.debug.print("Handshake completed\n", .{});

    // Get a stream
    const stream = try client.getStream();
    defer stream.deinit();

    // Send a request
    const request = "GET / HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "\r\n";

    try stream.writeAll(request);
    std.debug.print("Sent request: {s}\n", .{request});

    // Read the response
    var buf: [4096]u8 = undefined;
    const n = try stream.read(&buf);

    std.debug.print("Received response ({d} bytes):\n{s}\n", .{ n, buf[0..n] });
}
