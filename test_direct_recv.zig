const std = @import("std");
const posix = std.posix;

pub fn main() !void {
    // Create UDP socket
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);

    // Bind to 4433
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 4433);
    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    std.debug.print("Server listening on 127.0.0.1:4433\n", .{});
    std.debug.print("Socket fd: {}\n", .{sock});

    // Try to receive WITHOUT epoll, directly
    var buf: [4096]u8 = undefined;
    var peer_storage: posix.sockaddr.storage = undefined;
    var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer_storage));

    std.debug.print("Calling recvfrom (blocking)...\n", .{});

    // Use blocking mode to test
    const n = try posix.recvfrom(sock, &buf, 0, @ptrCast(&peer_storage), &peer_len);

    std.debug.print("Received {} bytes!\n", .{n});

    if (peer_storage.family == posix.AF.INET) {
        const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(&peer_storage));
        const addr_bytes = @as([4]u8, @bitCast(sin.addr));
        std.debug.print("From {}.{}.{}.{}:{}\n", .{
            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
            std.mem.bigToNative(u16, sin.port)
        });
    }
}