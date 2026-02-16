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
    var ca_path: ?[]const u8 = null;
    var allow_insecure = false;
    if (args.len > 3) {
        if (std.mem.eql(u8, args[3], "--insecure")) {
            allow_insecure = true;
        } else {
            ca_path = args[3];
        }
    }

    std.debug.print("Connecting to {s}:{d}\n", .{ server_addr, server_port });

    // Initialize the QUIC client
    var client = transport.QuicClient.init(allocator);
    defer client.deinit();

    // Connect to the server (secure by default)
    if (allow_insecure) {
        try client.connectInsecure(server_addr, server_port, true);
    } else if (ca_path) |ca| {
        try client.connectEx(server_addr, server_port, ca, null, null);
    } else {
        std.debug.print("Missing CA certificate path. Provide a CA path as the third arg or use --insecure for local testing.\n", .{});
        return error.MissingCaCert;
    }
    std.debug.print("Connected successfully\n", .{});

    // Wait for handshake to complete
    try client.waitForHandshake(5);
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
