const std = @import("std");
const posix = std.posix;

pub fn main() !void {
    const port: u16 = 19999;

    // Create UDP socket
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);

    // Set socket to reuse address
    const reuse: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse));

    // Bind to address
    const addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0, // 0.0.0.0
        .zero = undefined,
    };
    try posix.bind(sock, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));

    std.debug.print("UDP echo server listening on port {d}\n", .{port});

    var buf: [1024]u8 = undefined;
    var client_addr: posix.sockaddr = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

    while (true) {
        // Receive packet
        const n = posix.recvfrom(sock, &buf, 0, &client_addr, &client_addr_len) catch |err| {
            std.debug.print("recvfrom error: {}\n", .{err});
            continue;
        };

        if (n > 0) {
            std.debug.print("Received {d} bytes: {s}\n", .{ n, buf[0..n] });

            // Echo back
            _ = posix.sendto(sock, buf[0..n], 0, &client_addr, client_addr_len) catch |err| {
                std.debug.print("sendto error: {}\n", .{err});
                continue;
            };
            std.debug.print("Echoed back {d} bytes\n", .{n});
        }
    }
}